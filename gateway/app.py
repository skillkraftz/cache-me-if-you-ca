from flask import Flask, jsonify, request
import ipaddress
import os
import requests
import redis
import socket
from urllib.parse import urljoin, urlparse

from shared.auth import (
    canonical_json_bytes,
    new_jti,
    now_ts,
    sha256_hex,
    sign_payload,
    verify_payload,
)

app = Flask(__name__)
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "3"))
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
TOKEN_SERVICE_URL = os.getenv("TOKEN_SERVICE_URL", "http://token-service:5003")
INTERNAL_ADMIN_A_URL = os.getenv("INTERNAL_ADMIN_A_URL", "http://internal-admin-a:5001")
INTERNAL_ADMIN_B_URL = os.getenv("INTERNAL_ADMIN_B_URL", "http://internal-admin-b:5001")
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin")
ACCESS_TOKEN_PUBLIC_KEY_PEM = os.getenv("ACCESS_TOKEN_PUBLIC_KEY_PEM", "")
INTERNAL_ADMIN_A_RESPONSE_PUBLIC_KEY_PEM = os.getenv(
    "INTERNAL_ADMIN_A_RESPONSE_PUBLIC_KEY_PEM", ""
)
INTERNAL_ADMIN_B_RESPONSE_PUBLIC_KEY_PEM = os.getenv(
    "INTERNAL_ADMIN_B_RESPONSE_PUBLIC_KEY_PEM", ""
)
ALLOWED_PROXY_URLS = {
    u.strip() for u in os.getenv("ALLOWED_PROXY_URLS", "").split(",") if u.strip()
}
GATEWAY_CLIENT_ID = os.getenv("GATEWAY_CLIENT_ID", "gateway")
GATEWAY_CLIENT_PRIVATE_KEY_PEM = os.getenv("GATEWAY_CLIENT_PRIVATE_KEY_PEM", "")
SERVICE_ASSERTION_AUDIENCE = os.getenv("SERVICE_ASSERTION_AUDIENCE", "token-service")
OPERATOR_ASSERTION_AUDIENCE = os.getenv(
    "OPERATOR_ASSERTION_AUDIENCE", "mesh-operator-approval"
)
OPERATOR_PUBLIC_KEY_PEM = os.getenv("OPERATOR_PUBLIC_KEY_PEM", "")
ALLOWED_OPERATOR_IDS = {
    value.strip()
    for value in os.getenv("ALLOWED_OPERATOR_IDS", "ops-admin").split(",")
    if value.strip()
}
ENABLE_RAW_TOKEN_HELPER = (
    os.getenv("ENABLE_RAW_TOKEN_HELPER", "false").lower() == "true"
)
FETCH_MAX_REDIRECTS = int(os.getenv("FETCH_MAX_REDIRECTS", "3"))
ASSERTION_TTL_SECONDS = int(os.getenv("ASSERTION_TTL_SECONDS", "30"))
ASSERTION_CLOCK_SKEW_SECONDS = int(os.getenv("ASSERTION_CLOCK_SKEW_SECONDS", "5"))
RESPONSE_PROOF_AUDIENCE = os.getenv("RESPONSE_PROOF_AUDIENCE", "gateway")


def _redis():
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def _request(method: str, url: str, **kwargs):
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    with requests.Session() as session:
        session.trust_env = False
        return session.request(method, url, **kwargs)


def _admin_target(name: str) -> str | None:
    return {
        "a": INTERNAL_ADMIN_A_URL,
        "b": INTERNAL_ADMIN_B_URL,
    }.get(name)


def _admin_response_public_key(name: str) -> str:
    if name == "a":
        return INTERNAL_ADMIN_A_RESPONSE_PUBLIC_KEY_PEM
    return INTERNAL_ADMIN_B_RESPONSE_PUBLIC_KEY_PEM


def _passthrough_response(response):
    return (
        response.text,
        response.status_code,
        {"Content-Type": response.headers.get("Content-Type", "application/json")},
    )


def _reserve_once(key: str, ttl: int, error: str, status: int):
    try:
        if not _redis().set(key, "1", ex=max(1, ttl), nx=True):
            return False, jsonify({"error": error}), status
    except Exception:
        return False, jsonify({"error": "redis unavailable"}), 503
    return True, None, None


def _resolve_ip_addresses(hostname: str) -> set[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("unresolvable host") from exc
    addresses = {item[4][0] for item in infos}
    if not addresses:
        raise ValueError("unresolvable host")
    return addresses


def _validate_fetch_target(target: str):
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("unsupported scheme")
    if not parsed.hostname:
        raise ValueError("missing hostname")
    if parsed.username or parsed.password:
        raise ValueError("credentials in URL are not allowed")
    for address in _resolve_ip_addresses(parsed.hostname):
        if not ipaddress.ip_address(address).is_global:
            raise PermissionError("blocked private or internal address")
    return parsed


def _safe_fetch(target: str):
    current = target
    for hop in range(FETCH_MAX_REDIRECTS + 1):
        _validate_fetch_target(current)
        response = _request("GET", current, allow_redirects=False)
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location", "").strip()
            if not location:
                raise ValueError("redirect missing location")
            if hop >= FETCH_MAX_REDIRECTS:
                raise ValueError("too many redirects")
            current = urljoin(current, location)
            continue
        return response, current
    raise ValueError("too many redirects")


def _request_query_sha256() -> str:
    return sha256_hex(
        canonical_json_bytes(
            {key: request.args.getlist(key) for key in sorted(request.args.keys())}
        )
    )


def _request_body_sha256() -> str:
    return sha256_hex(request.get_data(cache=True) or b"")


def _validate_operator_claims(
    operator_assertion: str,
    expected_scope: str,
    expected_resource: str,
    expected_target: str,
):
    payload = verify_payload(operator_assertion, OPERATOR_PUBLIC_KEY_PEM)
    if payload is None:
        return None, "bad operator assertion"
    now = now_ts()
    operator_id = payload.get("iss")
    if operator_id not in ALLOWED_OPERATOR_IDS:
        return None, "unknown operator"
    if payload.get("sub") != operator_id:
        return None, "bad operator subject"
    if payload.get("aud") != OPERATOR_ASSERTION_AUDIENCE:
        return None, "bad operator audience"
    if payload.get("scope") != expected_scope:
        return None, "operator scope not permitted"
    if payload.get("client_id") != GATEWAY_CLIENT_ID:
        return None, "operator client mismatch"
    if payload.get("resource") != expected_resource:
        return None, "operator resource mismatch"
    if payload.get("target") != expected_target:
        return None, "operator target mismatch"
    if payload.get("iat", 0) > now + ASSERTION_CLOCK_SKEW_SECONDS:
        return None, "operator assertion not yet valid"
    if payload.get("exp", 0) < now - ASSERTION_CLOCK_SKEW_SECONDS:
        return None, "operator assertion expired"
    if not payload.get("jti"):
        return None, "missing operator assertion jti"
    return payload, None


def _validate_operator_assertion(
    operator_assertion: str,
    expected_scope: str,
    expected_resource: str,
    expected_target: str,
):
    payload, err = _validate_operator_claims(
        operator_assertion, expected_scope, expected_resource, expected_target
    )
    if err:
        return None, err
    if payload.get("method") != request.method:
        return None, "operator request mismatch"
    if payload.get("path") != request.path:
        return None, "operator request mismatch"
    if payload.get("query_sha256") != _request_query_sha256():
        return None, "operator request mismatch"
    if payload.get("body_sha256") != _request_body_sha256():
        return None, "operator request mismatch"
    return payload, None


def _validate_nested_operator_assertion(
    operator_assertion: str,
    expected_scope: str,
    expected_resource: str,
    expected_target: str,
):
    return _validate_operator_claims(
        operator_assertion, expected_scope, expected_resource, expected_target
    )


def _require_operator(scope: str, resource: str, target: str):
    operator_assertion = request.headers.get("X-Operator-Assertion", "").strip()
    if not operator_assertion:
        return None, (jsonify({"error": "forbidden"}), 403)
    payload, err = _validate_operator_assertion(
        operator_assertion, scope, resource, target
    )
    if err:
        return None, (jsonify({"error": err}), 403)
    ok, body, status = _reserve_once(
        f"gateway-operator-proof:{payload['jti']}",
        payload.get("exp", now_ts()) - now_ts() + ASSERTION_CLOCK_SKEW_SECONDS,
        "operator proof replay",
        403,
    )
    if not ok:
        return None, (body, status)
    return operator_assertion, None


def _validate_export_token(token: str, expected_target: str):
    payload = verify_payload(token, ACCESS_TOKEN_PUBLIC_KEY_PEM)
    if payload is None:
        return None, "bad token signature"
    now = now_ts()
    if payload.get("iat", 0) > now + ASSERTION_CLOCK_SKEW_SECONDS:
        return None, "token not yet valid"
    if payload.get("exp", 0) < now - ASSERTION_CLOCK_SKEW_SECONDS:
        return None, "token expired"
    if payload.get("iss") != "token-service":
        return None, "bad token issuer"
    if payload.get("aud") != TOKEN_AUDIENCE:
        return None, "bad token audience"
    if (
        payload.get("client_id") != GATEWAY_CLIENT_ID
        or payload.get("sub") != GATEWAY_CLIENT_ID
    ):
        return None, "bad token client"
    scopes = set((payload.get("scope") or "").split())
    if "admin.export.read" not in scopes:
        return None, "missing export scope"
    if payload.get("target_replica") != expected_target:
        return None, "wrong target replica"
    operator_assertion = payload.get("operator_assertion", "")
    if not operator_assertion:
        return None, "missing operator approval"
    operator_payload, err = _validate_nested_operator_assertion(
        operator_assertion, "admin.export.read", "/admin/export", expected_target
    )
    if err:
        return None, err
    if payload.get("actor") != operator_payload.get("sub"):
        return None, "actor mismatch"
    return payload, None


def _validate_export_response(response, target: str, token_payload: dict):
    if response.status_code != 200:
        return None, None
    try:
        body = response.json()
    except ValueError:
        return None, "bad upstream json"
    proof = body.get("response_proof", "")
    if not proof:
        return None, "missing response proof"
    proof_payload = verify_payload(proof, _admin_response_public_key(target))
    if proof_payload is None:
        return None, "bad response proof"
    now = now_ts()
    if proof_payload.get("aud") != RESPONSE_PROOF_AUDIENCE:
        return None, "bad response proof audience"
    if proof_payload.get("path") != "/admin/export":
        return None, "bad response proof path"
    if proof_payload.get("target_replica") != target:
        return None, "bad response proof target"
    if proof_payload.get("client_id") != token_payload.get("client_id"):
        return None, "bad response proof client"
    if proof_payload.get("actor") != token_payload.get("actor"):
        return None, "bad response proof actor"
    if proof_payload.get("token_jti") != token_payload.get("jti"):
        return None, "bad response proof token"
    if proof_payload.get("iat", 0) > now + ASSERTION_CLOCK_SKEW_SECONDS:
        return None, "response proof not yet valid"
    if proof_payload.get("exp", 0) < now - ASSERTION_CLOCK_SKEW_SECONDS:
        return None, "response proof expired"
    unsigned_body = dict(body)
    unsigned_body.pop("response_proof", None)
    if proof_payload.get("body_sha256") != sha256_hex(
        canonical_json_bytes(unsigned_body)
    ):
        return None, "response proof body mismatch"
    return body, None


def _build_service_assertion(method: str, path: str, body_bytes: bytes) -> str:
    now = now_ts()
    payload = {
        "iss": GATEWAY_CLIENT_ID,
        "sub": GATEWAY_CLIENT_ID,
        "aud": SERVICE_ASSERTION_AUDIENCE,
        "iat": now,
        "exp": now + ASSERTION_TTL_SECONDS,
        "jti": new_jti(),
        "method": method,
        "path": path,
        "body_sha256": sha256_hex(body_bytes),
    }
    return sign_payload(payload, GATEWAY_CLIENT_PRIVATE_KEY_PEM)


def _token_service_post(path: str, payload: dict):
    body_bytes = canonical_json_bytes(payload)
    headers = {
        "Content-Type": "application/json",
        "X-Client-Id": GATEWAY_CLIENT_ID,
        "X-Client-Assertion": _build_service_assertion("POST", path, body_bytes),
    }
    return _request(
        "POST", f"{TOKEN_SERVICE_URL}{path}", data=body_bytes, headers=headers
    )


@app.get("/health")
def health():
    return {"ok": True, "service": "gateway"}


@app.get("/fetch")
def fetch():
    target = request.args.get("url", "").strip()
    if not target:
        return jsonify({"error": "missing url"}), 400
    try:
        r, final_url = _safe_fetch(target)
        return jsonify(
            {
                "status_code": r.status_code,
                "content_type": r.headers.get("Content-Type"),
                "body": r.text[:1200],
                "final_url": final_url,
            }
        )
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502


@app.get("/proxy-health")
def proxy_health():
    try:
        r = _request("GET", f"{INTERNAL_ADMIN_A_URL}/health")
        return jsonify({"upstream_status": r.status_code, "body": r.json()})
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502


@app.get("/proxy-allowlisted")
def proxy_allowlisted():
    target = request.args.get("target", "").strip()
    if target not in ALLOWED_PROXY_URLS:
        return jsonify({"error": "target not allowlisted"}), 403
    try:
        r = _request("GET", target, allow_redirects=False)
        return jsonify({"upstream_status": r.status_code, "body": r.json()})
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502


@app.get("/ops/raw-token")
def raw_token():
    if not ENABLE_RAW_TOKEN_HELPER:
        return jsonify({"error": "gone"}), 410
    target = request.args.get("target", "a")
    if _admin_target(target) is None:
        return jsonify({"error": "unknown target"}), 400
    operator_assertion, err = _require_operator(
        "admin.export.read", "/admin/export", target
    )
    if err:
        return err
    scope = request.args.get("scope", "admin.export.read")
    try:
        r = _token_service_post(
            "/v1/mint",
            {
                "audience": "internal-admin",
                "scope": scope,
                "operator_assertion": operator_assertion,
                "target_replica": target,
            },
        )
        return _passthrough_response(r)
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502


@app.get("/ops/use-token")
def use_token():
    target = request.args.get("target", "a")
    base = _admin_target(target)
    if base is None:
        return jsonify({"error": "unknown target"}), 400
    _, err = _require_operator("admin.export.read", "/admin/export", target)
    if err:
        return err
    token = request.args.get("token", "")
    _, token_err = _validate_export_token(token, target)
    if token_err:
        return jsonify({"error": token_err}), 403
    try:
        r = _request(
            "GET", f"{base}/admin/export", headers={"Authorization": f"Bearer {token}"}
        )
        token_payload, _ = _validate_export_token(token, target)
        body, proof_err = _validate_export_response(r, target, token_payload)
        if proof_err:
            return jsonify({"error": proof_err}), 502
        if body is not None:
            return jsonify(body)
        return _passthrough_response(r)
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502


@app.get("/ops/export")
def export():
    target = request.args.get("target", "a")
    base = _admin_target(target)
    if base is None:
        return jsonify({"error": "unknown target"}), 400
    operator_assertion, err = _require_operator(
        "admin.export.read", "/admin/export", target
    )
    if err:
        return err
    try:
        mint = _token_service_post(
            "/v1/mint",
            {
                "audience": "internal-admin",
                "scope": "admin.export.read",
                "operator_assertion": operator_assertion,
                "target_replica": target,
            },
        )
        if mint.status_code != 200:
            return _passthrough_response(mint)
        token = mint.json()["access_token"]
        token_payload, token_err = _validate_export_token(token, target)
        if token_err:
            return jsonify({"error": token_err}), 502
        r = _request(
            "GET", f"{base}/admin/export", headers={"Authorization": f"Bearer {token}"}
        )
        body, proof_err = _validate_export_response(r, target, token_payload)
        if proof_err:
            return jsonify({"error": proof_err}), 502
        if body is not None:
            return jsonify(body)
        return _passthrough_response(r)
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
