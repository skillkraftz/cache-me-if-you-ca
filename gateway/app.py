from flask import Flask, jsonify, request
import os
import socket
import ipaddress
import requests
from urllib.parse import urlparse, urlunparse

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


def _admin_target(name: str) -> str:
    # Strictly allow only the two known replica names. Unknown names refuse.
    if name == "a":
        return INTERNAL_ADMIN_A_URL
    if name == "b":
        return INTERNAL_ADMIN_B_URL
    return ""


def _admin_ok() -> bool:
    import hmac

    supplied = request.headers.get("X-Admin-Api-Key", "") or ""
    return hmac.compare_digest(supplied, ADMIN_API_KEY)


def _resolve_and_validate(host: str):
    """Resolve hostname to IPs and require every answer to be a globally
    routable public address. Returns (list_of_(family, ip), None) on success
    or (None, reason) on failure. Any non-public address (private, loopback,
    link-local, reserved, multicast, unspecified) causes rejection.
    """
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
    """Validate the URL and perform a safe HTTP GET that:
    - rejects non-http(s) schemes
    - rejects URLs containing userinfo
    - rejects hosts that resolve to any non-public address
    - disables redirect following (redirects are refused explicitly)
    - DNS-pins HTTP requests to the validated IP to defeat rebinding

    Returns (requests.Response, None) on success or
    (None, (error_message, http_status)) on rejection / transport error.
    """
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        return None, ("unsupported scheme", 400)
    # Any embedded credentials indicate an attempt to smuggle a netloc past
    # naive blocklists; refuse unconditionally.
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        return None, ("userinfo not allowed", 400)
    host = parsed.hostname
    if not host:
        return None, ("missing host", 400)
    # Validate port bounds early.
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
        # Preserve the original Host header so virtual-hosted servers
        # continue to route correctly.
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
        # HTTPS path preserves SNI / certificate validation by keeping the
        # hostname. The IP allowlist still applied above, so the primary
        # SSRF vectors (internal hostnames, loopback, metadata IPs) are
        # already rejected. DNS rebinding inside the request window is a
        # residual risk that is mitigated by short timeouts and by the
        # fact that we refuse all redirects.
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
        f"{INTERNAL_ADMIN_A_URL}/health", timeout=REQUEST_TIMEOUT, allow_redirects=False
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
    # Retired. This helper previously allowed any caller with the admin
    # API key to request a mint with an attacker-controlled subject, nonce,
    # and scope, and then receive the raw bearer back. That is a classic
    # confused-deputy pattern and is disabled. Use /ops/export for the
    # legitimate mint-and-use flow.
    return jsonify({"error": "endpoint retired"}), 410


@app.get("/ops/use-token")
def use_token():
    if not _admin_ok():
        return jsonify({"error": "forbidden"}), 403
    token = request.args.get("token", "") or ""
    target = request.args.get("target", "a")
    base = _admin_target(target)
    if not base:
        return jsonify({"error": "unknown target"}), 400
    if not token:
        return jsonify({"error": "missing token"}), 400
    r = requests.get(
        f"{base}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    return (
        r.text,
        r.status_code,
        {"Content-Type": r.headers.get("Content-Type", "application/json")},
    )


@app.get("/ops/export")
def export():
    if not _admin_ok():
        return jsonify({"error": "forbidden"}), 403
    target = request.args.get("target", "a")
    base = _admin_target(target)
    if not base:
        return jsonify({"error": "unknown target"}), 400
    # Generate a fresh per-request nonce server-side so attackers can never
    # inject a deterministic one via the request.
    import uuid

    nonce = f"gw-{uuid.uuid4()}"
    headers = {
        "X-Client-Id": GATEWAY_CLIENT_ID,
        "X-Client-Secret": GATEWAY_CLIENT_SECRET,
        "X-Nonce": nonce,
    }
    mint = requests.post(
        f"{TOKEN_SERVICE_URL}/v1/mint",
        json={
            "audience": "internal-admin",
            "scope": "admin.export.read",
            "subject": GATEWAY_CLIENT_ID,
        },
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    if mint.status_code != 200:
        return (
            mint.text,
            mint.status_code,
            {"Content-Type": mint.headers.get("Content-Type", "application/json")},
        )
    try:
        token = mint.json()["access_token"]
    except Exception:
        return jsonify({"error": "malformed mint response"}), 502
    r = requests.get(
        f"{base}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    return (
        r.text,
        r.status_code,
        {"Content-Type": r.headers.get("Content-Type", "application/json")},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
