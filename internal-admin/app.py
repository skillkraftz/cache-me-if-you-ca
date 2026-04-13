from flask import Flask, jsonify, request
import os, time, base64, json, hmac, hashlib

app = Flask(__name__)
REPLICA_NAME = os.getenv("REPLICA_NAME", "internal-admin")
ACCESS_TOKEN_SECRET = os.getenv("ACCESS_TOKEN_SECRET", "lab-access-token-secret")
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin")
JTI_CACHE_TTL_SECONDS = int(os.getenv("JTI_CACHE_TTL_SECONDS", "120"))
_USED = {}


def _clean():
    now = int(time.time())
    stale = [k for k, v in _USED.items() if v < now]
    for k in stale:
        _USED.pop(k, None)


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def verify_token(token: str):
    try:
        p, s = token.split('.', 1)
        body = _b64d(p)
        sig = _b64d(s)
    except Exception:
        return None, "bad token format"
    expected = hmac.new(ACCESS_TOKEN_SECRET.encode(), body, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None, "bad token signature"
    try:
        payload = json.loads(body.decode())
    except Exception:
        return None, "bad token payload"
    now = int(time.time())
    if payload.get("iss") != "token-service":
        return None, "bad issuer"
    if payload.get("aud") != TOKEN_AUDIENCE:
        return None, "bad audience"
    if payload.get("exp", 0) < now:
        return None, "expired"
    jti = payload.get("jti")
    _clean()
    if jti in _USED:
        return None, "replay detected"
    _USED[jti] = now + JTI_CACHE_TTL_SECONDS
    return payload, None


def require_scope(scope: str):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, (jsonify({"error": "forbidden"}), 403)
    payload, err = verify_token(auth.split(None, 1)[1])
    if err:
        return None, (jsonify({"error": err}), 403)
    scopes = set((payload.get("scope") or "").split())
    if scope not in scopes:
        return None, (jsonify({"error": "missing required scope"}), 403)
    return payload, None


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": REPLICA_NAME})


@app.get("/debug/config")
def debug_config():
    return jsonify({
        "service": REPLICA_NAME,
        "app_env": os.getenv("APP_ENV", "dev"),
        "token_audience": TOKEN_AUDIENCE,
        "redis_url": os.getenv("REDIS_URL", "redis://redis:6379/0"),
        "replica": REPLICA_NAME,
        "allowed_subjects": ["gateway", "observer"],
    })


@app.get("/internal/metrics")
def metrics():
    payload, err = require_scope("internal.metrics.read")
    if err:
        return err
    return jsonify({"service": REPLICA_NAME, "caller": payload.get("sub"), "status": "ok", "queue_depth": 2})


@app.get("/admin/export")
def export():
    payload, err = require_scope("admin.export.read")
    if err:
        return err
    return jsonify({
        "service": REPLICA_NAME,
        "caller": payload.get("sub"),
        "records": 2,
        "users": [
            {"id": 1, "email": "alice@example.internal"},
            {"id": 2, "email": "bob@example.internal"},
        ],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
