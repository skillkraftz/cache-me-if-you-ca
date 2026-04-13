from flask import Flask, jsonify, request
import os
import time
import base64
import json
import hmac
import hashlib
import redis

app = Flask(__name__)
REPLICA_NAME = os.getenv("REPLICA_NAME", "internal-admin")
ACCESS_TOKEN_SECRET = os.getenv("ACCESS_TOKEN_SECRET", "lab-access-token-secret")
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin")
JTI_CACHE_TTL_SECONDS = int(os.getenv("JTI_CACHE_TTL_SECONDS", "120"))
MAX_TOKEN_LIFETIME_SECONDS = int(os.getenv("MAX_TOKEN_LIFETIME_SECONDS", "60"))
CLOCK_SKEW_SECONDS = int(os.getenv("CLOCK_SKEW_SECONDS", "5"))
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
# Hard-coded set of subjects we will honour. Any token whose "sub" claim is
# not in this set is rejected even if it is signed and otherwise valid. This
# closes the subject-spoofing footgun at the consumer side.
ALLOWED_SUBJECTS = {"gateway", "observer"}

_redis_client = None


def _redis():
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_timeout=2,
            socket_connect_timeout=2,
        )
    return _redis_client


class ReplayBackendUnavailable(Exception):
    pass


def _claim_jti(jti: str) -> bool:
    """Atomically claim a JTI in the shared Redis store. Returns True the
    first time the JTI is seen and False on replay. Raises
    ReplayBackendUnavailable if the backend cannot confirm the claim, in
    which case the caller must fail closed: we refuse to accept the token
    because we cannot prove it has not already been spent on another
    replica.
    """
    key = f"jti:{jti}"
    try:
        ok = _redis().set(key, "1", nx=True, ex=JTI_CACHE_TTL_SECONDS)
    except Exception:
        raise ReplayBackendUnavailable()
    return bool(ok)


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def verify_token(token: str):
    if not token or "." not in token:
        return None, "bad token format"
    try:
        p, s = token.split(".", 1)
        body = _b64d(p)
        sig = _b64d(s)
    except Exception:
        return None, "bad token format"
    expected = hmac.new(ACCESS_TOKEN_SECRET.encode(), body, hashlib.sha256).digest()
    # Constant-time signature compare.
    if not hmac.compare_digest(sig, expected):
        return None, "bad token signature"
    try:
        payload = json.loads(body.decode())
    except Exception:
        return None, "bad token payload"
    if not isinstance(payload, dict):
        return None, "bad token payload"

    now = int(time.time())
    if payload.get("iss") != "token-service":
        return None, "bad issuer"
    if payload.get("aud") != TOKEN_AUDIENCE:
        return None, "bad audience"

    iat = payload.get("iat")
    exp = payload.get("exp")
    nbf = payload.get("nbf", iat)
    if not isinstance(iat, int) or not isinstance(exp, int):
        return None, "bad time claims"
    if not isinstance(nbf, int):
        nbf = iat
    # Reject tokens that are from too far in the future (minor clock skew ok).
    if iat > now + CLOCK_SKEW_SECONDS:
        return None, "token from the future"
    if nbf > now + CLOCK_SKEW_SECONDS:
        return None, "token not yet valid"
    if exp <= now - CLOCK_SKEW_SECONDS:
        return None, "expired"
    # Cap acceptable token lifetime regardless of what the issuer claimed,
    # so a compromised issuer cannot mint 100-year tokens.
    if exp - iat > MAX_TOKEN_LIFETIME_SECONDS + CLOCK_SKEW_SECONDS:
        return None, "token lifetime too long"

    subject = payload.get("sub", "")
    if subject not in ALLOWED_SUBJECTS:
        return None, "subject not permitted"

    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        return None, "missing jti"

    # Atomically claim the JTI in Redis. If another replica (or the same
    # replica, in another request) already spent it, we reject. If Redis is
    # unavailable we fail CLOSED because we cannot prove freshness.
    try:
        fresh = _claim_jti(jti)
    except ReplayBackendUnavailable:
        return None, "replay store unavailable"
    if not fresh:
        return None, "replay detected"

    return payload, None


def require_scope(scope: str):
    auth = request.headers.get("Authorization", "") or ""
    if not auth.startswith("Bearer "):
        return None, (jsonify({"error": "forbidden"}), 403)
    token = auth.split(None, 1)[1].strip()
    payload, err = verify_token(token)
    if err:
        # "replay store unavailable" is an operational 503, not a client 403.
        if err == "replay store unavailable":
            return None, (jsonify({"error": err}), 503)
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
    # The debug surface now requires a scoped bearer token. Previously this
    # leaked replica identity, Redis URL, and the allowed-subjects list to
    # anybody who could reach the service (including via SSRF).
    payload, err = require_scope("debug.config.read")
    if err:
        return err
    return jsonify(
        {
            "service": REPLICA_NAME,
            "app_env": os.getenv("APP_ENV", "dev"),
            "token_audience": TOKEN_AUDIENCE,
            "replica": REPLICA_NAME,
            "caller": payload.get("sub"),
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
            "caller": payload.get("sub"),
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
            "caller": payload.get("sub"),
            "records": 2,
            "users": [
                {"id": 1, "email": "alice@example.internal"},
                {"id": 2, "email": "bob@example.internal"},
            ],
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
