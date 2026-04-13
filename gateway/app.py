from flask import Flask, jsonify, request
import ipaddress
import os, uuid
import requests
import socket
from urllib.parse import urljoin, urlparse

app = Flask(__name__)
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "3"))
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "lab-admin-key")
TOKEN_SERVICE_URL = os.getenv("TOKEN_SERVICE_URL", "http://token-service:5003")
INTERNAL_ADMIN_A_URL = os.getenv("INTERNAL_ADMIN_A_URL", "http://internal-admin-a:5001")
INTERNAL_ADMIN_B_URL = os.getenv("INTERNAL_ADMIN_B_URL", "http://internal-admin-b:5001")
ALLOWED_PROXY_URLS = {
    u.strip() for u in os.getenv("ALLOWED_PROXY_URLS", "").split(",") if u.strip()
}
GATEWAY_CLIENT_ID = os.getenv("GATEWAY_CLIENT_ID", "gateway")
GATEWAY_CLIENT_SECRET = os.getenv("GATEWAY_CLIENT_SECRET", "gateway-client-secret")
ENABLE_RAW_TOKEN_HELPER = (
    os.getenv("ENABLE_RAW_TOKEN_HELPER", "false").lower() == "true"
)
FETCH_MAX_REDIRECTS = int(os.getenv("FETCH_MAX_REDIRECTS", "3"))


def _request(method: str, url: str, **kwargs):
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    with requests.Session() as session:
        session.trust_env = False
        return session.request(method, url, **kwargs)


def _admin_target(name: str) -> str | None:
    targets = {
        "a": INTERNAL_ADMIN_A_URL,
        "b": INTERNAL_ADMIN_B_URL,
    }
    return targets.get(name)


def _new_nonce(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def _passthrough_response(response):
    return (
        response.text,
        response.status_code,
        {"Content-Type": response.headers.get("Content-Type", "application/json")},
    )


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


def _admin_ok() -> bool:
    return hmac_compare(request.headers.get("X-Admin-Api-Key", ""), ADMIN_API_KEY)


def hmac_compare(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(a, b)


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
    if not _admin_ok():
        return jsonify({"error": "forbidden"}), 403
    scope = request.args.get("scope", "admin.export.read")
    subject = request.args.get("subject", GATEWAY_CLIENT_ID)
    nonce = request.headers.get("X-Nonce", "").strip() or _new_nonce("gateway-raw")
    headers = {
        "X-Client-Id": GATEWAY_CLIENT_ID,
        "X-Client-Secret": GATEWAY_CLIENT_SECRET,
        "X-Nonce": nonce,
    }
    try:
        r = _request(
            "POST",
            f"{TOKEN_SERVICE_URL}/v1/mint",
            json={
                "audience": "internal-admin",
                "scope": scope,
                "subject": subject,
            },
            headers=headers,
        )
        return _passthrough_response(r)
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502


@app.get("/ops/use-token")
def use_token():
    if not _admin_ok():
        return jsonify({"error": "forbidden"}), 403
    token = request.args.get("token", "")
    target = request.args.get("target", "a")
    base = _admin_target(target)
    if base is None:
        return jsonify({"error": "unknown target"}), 400
    try:
        r = _request(
            "GET", f"{base}/admin/export", headers={"Authorization": f"Bearer {token}"}
        )
        return _passthrough_response(r)
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502


@app.get("/ops/export")
def export():
    if not _admin_ok():
        return jsonify({"error": "forbidden"}), 403
    target = request.args.get("target", "a")
    base = _admin_target(target)
    if base is None:
        return jsonify({"error": "unknown target"}), 400
    headers = {
        "X-Client-Id": GATEWAY_CLIENT_ID,
        "X-Client-Secret": GATEWAY_CLIENT_SECRET,
        "X-Nonce": _new_nonce("gateway-export"),
    }
    try:
        mint = _request(
            "POST",
            f"{TOKEN_SERVICE_URL}/v1/mint",
            json={
                "audience": "internal-admin",
                "scope": "admin.export.read",
                "subject": GATEWAY_CLIENT_ID,
            },
            headers=headers,
        )
        if mint.status_code != 200:
            return _passthrough_response(mint)
        token = mint.json()["access_token"]
        r = _request(
            "GET", f"{base}/admin/export", headers={"Authorization": f"Bearer {token}"}
        )
        return _passthrough_response(r)
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
