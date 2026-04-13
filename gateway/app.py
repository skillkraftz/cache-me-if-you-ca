from flask import Flask, jsonify, request
import os
import time
import json
import uuid
import base64
import socket
import ipaddress

import requests
from urllib.parse import urlparse, urlunparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


app = Flask(__name__)

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "3"))
TOKEN_SERVICE_URL = os.getenv("TOKEN_SERVICE_URL", "http://token-service:5003")
INTERNAL_ADMIN_A_URL = os.getenv("INTERNAL_ADMIN_A_URL", "http://internal-admin-a:5001")
INTERNAL_ADMIN_B_URL = os.getenv("INTERNAL_ADMIN_B_URL", "http://internal-admin-b:5001")
ALLOWED_PROXY_URLS = {
    u.strip() for u in os.getenv("ALLOWED_PROXY_URLS", "").split(",") if u.strip()
}
GATEWAY_CLIENT_ID = os.getenv("GATEWAY_CLIENT_ID", "gateway")
GATEWAY_CLIENT_KEY_ID = os.getenv("GATEWAY_CLIENT_KEY_ID", "gateway-client-v1")
GATEWAY_CLIENT_KEY_SEED_B64 = os.environ["GATEWAY_CLIENT_KEY_SEED_B64"]
CLIENT_ASSERTION_LIFETIME_SECONDS = int(
    os.getenv("CLIENT_ASSERTION_LIFETIME_SECONDS", "30")
)


# -----------------------------------------------------------------------------
# Crypto helpers (inlined)
# -----------------------------------------------------------------------------


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _load_private(seed_b64: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_b64d(seed_b64))


def _sign_compact(priv: Ed25519PrivateKey, header: dict, payload: dict) -> str:
    h_b64 = _b64e(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p_b64 = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = priv.sign(signing_input)
    return f"{h_b64}.{p_b64}.{_b64e(sig)}"


GATEWAY_CLIENT_KEY = _load_private(GATEWAY_CLIENT_KEY_SEED_B64)


def _gateway_client_assertion() -> str:
    """Mint a fresh client assertion attesting 'this request is from the
    gateway'. Short-lived and single-use: the token-service claims the jti
    in Redis so the assertion cannot be replayed. The typ header pins it
    as a client-authentication artifact so it can never be mistaken for
    an operator actor assertion or an access token.
    """
    now = int(time.time())
    header = {
        "alg": "EdDSA",
        "typ": "client-auth+jwt",
        "kid": GATEWAY_CLIENT_KEY_ID,
    }
    payload = {
        "iss": GATEWAY_CLIENT_ID,
        "sub": GATEWAY_CLIENT_ID,
        "aud": "token-service",
        "iat": now,
        "nbf": now,
        "exp": now + CLIENT_ASSERTION_LIFETIME_SECONDS,
        "jti": str(uuid.uuid4()),
    }
    return _sign_compact(GATEWAY_CLIENT_KEY, header, payload)


# -----------------------------------------------------------------------------
# SSRF-safe fetch helpers (kept from the previous turn)
# -----------------------------------------------------------------------------


def _resolve_and_validate(host: str):
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:
        return None, "dns resolution failed"
    results = []
    for info in infos:
        family = info[0]
        sockaddr = info[4]
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return None, "invalid resolved address"
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):
            return None, "host resolves to a non-public address"
        results.append((family, ip_str))
    if not results:
        return None, "host has no addresses"
    return results, None


def _safe_fetch(target_url: str):
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        return None, ("unsupported scheme", 400)
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        return None, ("userinfo not allowed", 400)
    host = parsed.hostname
    if not host:
        return None, ("missing host", 400)
    try:
        raw_port = parsed.port
    except ValueError:
        return None, ("invalid port", 400)
    ips, err = _resolve_and_validate(host)
    if err:
        return None, (err, 403)

    if parsed.scheme == "http":
        family, ip = ips[0]
        port = raw_port or 80
        if family == socket.AF_INET6:
            pinned_netloc = f"[{ip}]:{port}"
        else:
            pinned_netloc = f"{ip}:{port}"
        if raw_port and raw_port != 80:
            host_header = f"{host}:{raw_port}"
        else:
            host_header = host
        pinned_url = urlunparse(
            (
                "http",
                pinned_netloc,
                parsed.path or "/",
                parsed.params,
                parsed.query,
                "",
            )
        )
        try:
            r = requests.get(
                pinned_url,
                headers={"Host": host_header},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
        except Exception as e:
            return None, (str(e), 502)
    else:
        try:
            r = requests.get(
                target_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
        except Exception as e:
            return None, (str(e), 502)

    if 300 <= r.status_code < 400:
        return None, ("redirects are not permitted", 403)
    return r, None


# -----------------------------------------------------------------------------
# Admin target mapping
# -----------------------------------------------------------------------------


def _admin_target(name: str) -> str:
    if name == "a":
        return INTERNAL_ADMIN_A_URL
    if name == "b":
        return INTERNAL_ADMIN_B_URL
    return ""


# -----------------------------------------------------------------------------
# Operator actor-assertion plumbing
# -----------------------------------------------------------------------------


def _require_actor_assertion():
    """Every /ops/* endpoint requires an X-Actor-Assertion header. The
    gateway does NOT trust or verify the assertion itself - it merely
    checks that one is present, bounds its size, and forwards it to the
    token-service which is the single authority. This keeps the gateway
    stateless with respect to operator identity: a compromised gateway
    still cannot forge operator actions because it never holds operator
    private key material.
    """
    assertion = request.headers.get("X-Actor-Assertion", "") or ""
    if not assertion:
        return None, (jsonify({"error": "missing X-Actor-Assertion"}), 401)
    if len(assertion) > 4096:
        return None, (jsonify({"error": "oversize X-Actor-Assertion"}), 400)
    if assertion.count(".") != 2:
        return None, (jsonify({"error": "malformed X-Actor-Assertion"}), 400)
    return assertion, None


def _mint_delegated_token(actor_assertion: str, scope: str):
    """Call token-service /v1/mint presenting the gateway's fresh client
    assertion plus the operator's actor assertion. Returns
    (token, None) or (None, (response, status)).
    """
    client_assertion = _gateway_client_assertion()
    body = {
        "audience": "internal-admin",
        "scope": scope,
        "client_assertion": client_assertion,
        "actor_assertion": actor_assertion,
    }
    try:
        r = requests.post(
            f"{TOKEN_SERVICE_URL}/v1/mint",
            json=body,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
    except Exception as e:
        return None, (jsonify({"error": f"token service unreachable: {e}"}), 502)
    if r.status_code != 200:
        return None, (r.text, r.status_code)
    try:
        return r.json()["access_token"], None
    except Exception:
        return None, (jsonify({"error": "malformed mint response"}), 502)


# -----------------------------------------------------------------------------
# HTTP routes
# -----------------------------------------------------------------------------


@app.get("/health")
def health():
    return {"ok": True, "service": "gateway"}


@app.get("/fetch")
def fetch():
    target = request.args.get("url", "").strip()
    if not target:
        return jsonify({"error": "missing url"}), 400
    r, err = _safe_fetch(target)
    if err:
        msg, status = err
        return jsonify({"error": msg}), status
    return jsonify(
        {
            "status_code": r.status_code,
            "content_type": r.headers.get("Content-Type"),
            "body": r.text[:1200],
            "final_url": target,
        }
    )


@app.get("/proxy-health")
def proxy_health():
    r = requests.get(
        f"{INTERNAL_ADMIN_A_URL}/health",
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    try:
        body = r.json()
    except Exception:
        body = None
    return jsonify({"upstream_status": r.status_code, "body": body})


@app.get("/proxy-allowlisted")
def proxy_allowlisted():
    target = request.args.get("target", "").strip()
    if target not in ALLOWED_PROXY_URLS:
        return jsonify({"error": "target not allowlisted"}), 403
    r = requests.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=False)
    try:
        body = r.json()
    except Exception:
        body = None
    return jsonify({"upstream_status": r.status_code, "body": body})


@app.get("/ops/raw-token")
def raw_token():
    # Retired endpoint (previous turn). The confused-deputy pattern is
    # gone and actor-assertion flow replaces the whole "mint and hand a
    # bearer to the caller" idea.
    return jsonify({"error": "endpoint retired"}), 410


@app.get("/ops/use-token")
def use_token():
    # Retired (this turn). This endpoint was a thin passthrough that sent
    # a caller-supplied bearer to internal-admin. Its local auth check
    # (X-Actor-Assertion size+format only) never called the token-service
    # and never verified the assertion's signature, so an external
    # attacker holding any stolen bearer could proxy it into internal-
    # admin with a literal "a.b.c" string as the header. The whole point
    # of the new trust model is that the gateway should never forward an
    # attacker-supplied bearer, so the endpoint is gone. Use /ops/export
    # for the mint-and-use-atomically flow.
    return jsonify({"error": "endpoint retired"}), 410


def _relay_to_admin(
    assertion: str, scope: str, upstream_path: str, *, forward_params=()
):
    """Shared plumbing for /ops/* endpoints that relay to internal-admin.

    Performs the delegated mint, forwards the operator's request nonce
    upstream, calls internal-admin, and returns the response verbatim
    with the X-Response-Envelope header intact. The gateway is a
    transparent transport: it cannot meaningfully tamper with the body
    without invalidating the envelope body hash, nor with the envelope
    without invalidating the signature.
    """
    target = request.args.get("target", "a")
    base = _admin_target(target)
    if not base:
        return jsonify({"error": "unknown target"}), 400
    token, mint_err = _mint_delegated_token(assertion, scope)
    if mint_err:
        body, status = mint_err
        if isinstance(body, str):
            return (body, status, {"Content-Type": "application/json"})
        return body, status
    upstream_headers = {"Authorization": f"Bearer {token}"}
    nonce = request.headers.get("X-Request-Nonce")
    if nonce is not None:
        upstream_headers["X-Request-Nonce"] = nonce
    upstream_params = {}
    for key in forward_params:
        if key in request.args:
            upstream_params[key] = request.args[key]
    r = requests.get(
        f"{base}{upstream_path}",
        headers=upstream_headers,
        params=upstream_params,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    response_headers = {
        "Content-Type": r.headers.get("Content-Type", "application/json"),
    }
    envelope = r.headers.get("X-Response-Envelope")
    if envelope is not None:
        response_headers["X-Response-Envelope"] = envelope
    return (r.text, r.status_code, response_headers)


@app.get("/ops/export")
def export():
    assertion, err = _require_actor_assertion()
    if err:
        return err
    return _relay_to_admin(assertion, "admin.export.read", "/admin/export")


@app.get("/ops/audit")
def audit():
    """Relay an operator's request for their own audit log. The operator
    uses this to reconcile the requests they *think* they submitted
    against the list of requests internal-admin actually processed. A
    compromised gateway cannot meaningfully lie here: the response is
    envelope-signed end-to-end and the operator verifies on receipt.
    """
    assertion, err = _require_actor_assertion()
    if err:
        return err
    return _relay_to_admin(
        assertion,
        "audit.self.read",
        "/internal/audit",
        forward_params=("since",),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
