from flask import Flask, jsonify, request
import os, time, base64, json, hmac, hashlib
import redis

app = Flask(__name__)
REPLICA_NAME = os.getenv("REPLICA_NAME", "internal-admin")
ACCESS_TOKEN_SECRET = os.getenv("ACCESS_TOKEN_SECRET", "lab-access-token-secret")
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin")
JTI_CACHE_TTL_SECONDS = int(os.getenv("JTI_CACHE_TTL_SECONDS", "120"))
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
SCOPE_CLIENTS = {
    "admin.export.read": {"gateway"},
    "debug.config.read": {"gateway", "observer"},
    "internal.metrics.read": {"gateway", "observer"},
}


def _redis():
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _caller_client_id(payload: dict) -> str:
    return payload.get("client_id") or payload.get("sub", "")


def _reserve_jti(jti: str, exp: int, now: int):
    ttl = max(1, max(exp - now, JTI_CACHE_TTL_SECONDS))
    try:
        if not _redis().set(f"jti:{jti}", REPLICA_NAME, ex=ttl, nx=True):
            return False, "replay detected", 403
    except Exception:
        return False, "token state unavailable", 503
    return True, None, None


def verify_token(token: str):
    try:
        p, s = token.split(".", 1)
        body = _b64d(p)
        sig = _b64d(s)
    except Exception:
        return None, "bad token format", 403
    expected = hmac.new(ACCESS_TOKEN_SECRET.encode(), body, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None, "bad token signature", 403
    try:
        payload = json.loads(body.decode())
    except Exception:
        return None, "bad token payload", 403
    now = int(time.time())
    if payload.get("iss") != "token-service":
        return None, "bad issuer", 403
    if payload.get("aud") != TOKEN_AUDIENCE:
        return None, "bad audience", 403
    if payload.get("exp", 0) < now:
        return None, "expired", 403
    jti = payload.get("jti")
    if not jti:
        return None, "missing jti", 403
    ok, err, status = _reserve_jti(jti, payload.get("exp", now), now)
    if not ok:
        return None, err, status
    return payload, None, None


def require_scope(scope: str):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, (jsonify({"error": "forbidden"}), 403)
    payload, err, status = verify_token(auth.split(None, 1)[1])
    if err:
        return None, (jsonify({"error": err}), status)
    scopes = set((payload.get("scope") or "").split())
    if scope not in scopes:
        return None, (jsonify({"error": "missing required scope"}), 403)
    caller = _caller_client_id(payload)
    allowed_clients = SCOPE_CLIENTS.get(scope)
    if allowed_clients and caller not in allowed_clients:
        return None, (jsonify({"error": "caller not permitted"}), 403)
    return payload, None


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": REPLICA_NAME})


@app.get("/debug/config")
def debug_config():
    _, err = require_scope("debug.config.read")
    if err:
        return err
    return jsonify(
        {
            "service": REPLICA_NAME,
            "app_env": os.getenv("APP_ENV", "dev"),
            "token_audience": TOKEN_AUDIENCE,
            "redis_url": REDIS_URL,
            "replica": REPLICA_NAME,
            "allowed_subjects": ["gateway", "observer"],
        }
    )


@app.get("/internal/metrics")
def metrics():
    payload, err = require_scope("internal.metrics.read")
    if err:
        return err
    return jsonify(
        {
            "service": REPLICA_NAME,
            "caller": _caller_client_id(payload),
            "status": "ok",
            "queue_depth": 2,
        }
    )


@app.get("/admin/export")
def export():
    payload, err = require_scope("admin.export.read")
    if err:
        return err
    return jsonify(
        {
            "service": REPLICA_NAME,
            "caller": _caller_client_id(payload),
            "records": 2,
            "users": [
                {"id": 1, "email": "alice@example.internal"},
                {"id": 2, "email": "bob@example.internal"},
            ],
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
