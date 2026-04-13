from flask import Flask, jsonify, request
import os, time
import requests
import socket
from urllib.parse import urlparse

app = Flask(__name__)
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "3"))
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "lab-admin-key")
TOKEN_SERVICE_URL = os.getenv("TOKEN_SERVICE_URL", "http://token-service:5003")
INTERNAL_ADMIN_A_URL = os.getenv("INTERNAL_ADMIN_A_URL", "http://internal-admin-a:5001")
INTERNAL_ADMIN_B_URL = os.getenv("INTERNAL_ADMIN_B_URL", "http://internal-admin-b:5001")
ALLOWED_PROXY_URLS = {u.strip() for u in os.getenv("ALLOWED_PROXY_URLS", "").split(",") if u.strip()}
GATEWAY_CLIENT_ID = os.getenv("GATEWAY_CLIENT_ID", "gateway")
GATEWAY_CLIENT_SECRET = os.getenv("GATEWAY_CLIENT_SECRET", "gateway-client-secret")


def weak_block(parsed) -> bool:
    netloc = (parsed.netloc or "").lower()
    blocked = {"internal-admin-a:5001", "localhost", "localhost:5000"}
    return netloc in blocked


def _admin_target(name: str) -> str:
    return INTERNAL_ADMIN_A_URL if name == "a" else INTERNAL_ADMIN_B_URL


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
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "unsupported scheme"}), 400
    if weak_block(parsed):
        return jsonify({"error": "blocked hostname"}), 403
    try:
        ip = socket.gethostbyname(parsed.hostname)
        if ip.startswith("127.") or ip == "::1":
            return jsonify({"error": "blocked localhost"}), 403
    except Exception:
        pass
    try:
        r = requests.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        return jsonify({
            "status_code": r.status_code,
            "content_type": r.headers.get("Content-Type"),
            "body": r.text[:1200],
            "final_url": r.url,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.get("/proxy-health")
def proxy_health():
    r = requests.get(f"{INTERNAL_ADMIN_A_URL}/health", timeout=REQUEST_TIMEOUT)
    return jsonify({"upstream_status": r.status_code, "body": r.json()})


@app.get("/proxy-allowlisted")
def proxy_allowlisted():
    target = request.args.get("target", "").strip()
    if target not in ALLOWED_PROXY_URLS:
        return jsonify({"error": "target not allowlisted"}), 403
    r = requests.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=False)
    return jsonify({"upstream_status": r.status_code, "body": r.json()})


@app.get("/ops/raw-token")
def raw_token():
    if not _admin_ok():
        return jsonify({"error": "forbidden"}), 403
    scope = request.args.get("scope", "admin.export.read")
    subject = request.args.get("subject", GATEWAY_CLIENT_ID)
    nonce = request.headers.get("X-Nonce", f"gateway-raw-{int(time.time() * 1000)}")
    headers = {
        "X-Client-Id": GATEWAY_CLIENT_ID,
        "X-Client-Secret": GATEWAY_CLIENT_SECRET,
        "X-Nonce": nonce,
    }
    r = requests.post(f"{TOKEN_SERVICE_URL}/v1/mint", json={
        "audience": "internal-admin",
        "scope": scope,
        "subject": subject,
    }, headers=headers, timeout=REQUEST_TIMEOUT)
    return (r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})


@app.get("/ops/use-token")
def use_token():
    if not _admin_ok():
        return jsonify({"error": "forbidden"}), 403
    token = request.args.get("token", "")
    target = request.args.get("target", "a")
    base = _admin_target(target)
    r = requests.get(f"{base}/admin/export", headers={"Authorization": f"Bearer {token}"}, timeout=REQUEST_TIMEOUT)
    return (r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})


@app.get("/ops/export")
def export():
    if not _admin_ok():
        return jsonify({"error": "forbidden"}), 403
    target = request.args.get("target", "a")
    base = _admin_target(target)
    headers = {
        "X-Client-Id": GATEWAY_CLIENT_ID,
        "X-Client-Secret": GATEWAY_CLIENT_SECRET,
    }
    mint = requests.post(f"{TOKEN_SERVICE_URL}/v1/mint", json={
        "audience": "internal-admin",
        "scope": "admin.export.read",
        "subject": GATEWAY_CLIENT_ID,
    }, headers=headers, timeout=REQUEST_TIMEOUT)
    if mint.status_code != 200:
        return (mint.text, mint.status_code, {"Content-Type": mint.headers.get("Content-Type", "application/json")})
    token = mint.json()["access_token"]
    r = requests.get(f"{base}/admin/export", headers={"Authorization": f"Bearer {token}"}, timeout=REQUEST_TIMEOUT)
    return (r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
