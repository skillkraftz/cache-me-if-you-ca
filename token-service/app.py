from flask import Flask, jsonify, request
import os
import time
import base64
import json
import hmac
import hashlib
import uuid
import redis

app = Flask(__name__)
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
# There is no fail-open path. The original service supported a STRICT_REDIS
# toggle; removing the toggle is deliberate. Allowing Redis to be silently
# bypassed lets an attacker DoS Redis (or wait for a partial failure) and
# then replay nonces.
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin")
ACCESS_TOKEN_SECRET = os.getenv("ACCESS_TOKEN_SECRET", "lab-access-token-secret")
NONCE_TTL_SECONDS = int(os.getenv("NONCE_TTL_SECONDS", "60"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
RATE_LIMIT_BURST = int(os.getenv("RATE_LIMIT_BURST", "60"))
TOKEN_LIFETIME_SECONDS = int(os.getenv("TOKEN_LIFETIME_SECONDS", "30"))
MAX_NONCE_LENGTH = int(os.getenv("MAX_NONCE_LENGTH", "128"))

CLIENTS = {
    "gateway": {
        "secret": os.getenv("GATEWAY_CLIENT_SECRET", "gateway-client-secret"),
        "scopes": {
            "admin.export.read",
            "internal.metrics.read",
            "debug.config.read",
            "token.discovery",
        },
        "audiences": {TOKEN_AUDIENCE},
    },
    "observer": {
        "secret": os.getenv("OBSERVER_CLIENT_SECRET", "observer-client-secret"),
        "scopes": {"internal.metrics.read", "debug.config.read", "token.discovery"},
        "audiences": {TOKEN_AUDIENCE},
    },
}

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


class RedisUnavailable(Exception):
    pass


def _fail_closed_response():
    return jsonify({"error": "security state backend unavailable"}), 503


def _claim_nonce(client_id: str, nonce: str):
    """Atomically claim a per-client nonce. Returns (True, None, None) when
    the nonce is fresh, (False, response, status) when it is a replay, and
    raises RedisUnavailable when the backend cannot confirm the claim.
    """
    key = f"nonce:{client_id}:{nonce}"
    try:
        # SET key value NX EX TTL is an atomic claim-or-fail. Two concurrent
        # mint requests carrying the same nonce cannot both succeed.
        ok = _redis().set(key, "1", nx=True, ex=NONCE_TTL_SECONDS)
    except Exception:
        raise RedisUnavailable()
    if not ok:
        return False, jsonify({"error": "nonce replay"}), 403
    return True, None, None


def _check_rate(client_id: str):
    """Atomic per-minute rate limit. Raises RedisUnavailable on backend
    failure so the caller can fail the whole mint request.
    """
    try:
        r = _redis()
        window = int(time.time() // 60)
        key = f"rate:{client_id}:{window}"
        # Pipeline the INCR + EXPIRE so an intermediary crash cannot leave a
        # counter without a TTL. INCR is already atomic by itself.
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.expire(key, 120)
        count, _ = pipe.execute()
    except Exception:
        raise RedisUnavailable()
    if count > RATE_LIMIT_BURST:
        return False, jsonify({"error": "rate limit exceeded"}), 429
    return True, None, None


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign(payload):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(ACCESS_TOKEN_SECRET.encode(), body, hashlib.sha256).digest()
    return f"{_b64e(body)}.{_b64e(sig)}"


def _authenticate_client():
    """Return (client_id, None) on success or (None, (response, status))."""
    client_id = request.headers.get("X-Client-Id", "") or ""
    client_secret = request.headers.get("X-Client-Secret", "") or ""
    if client_id not in CLIENTS:
        return None, (jsonify({"error": "unknown client"}), 403)
    if not hmac.compare_digest(client_secret, CLIENTS[client_id]["secret"]):
        return None, (jsonify({"error": "bad client secret"}), 403)
    return client_id, None


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "token-service"})


@app.get("/.well-known/mesh")
def mesh():
    # Now requires authenticated client credentials and returns a minimal
    # response that does not enumerate other clients. Used only for basic
    # service discovery by already-credentialed peers.
    client_id, err = _authenticate_client()
    if err:
        resp, status = err
        return resp, status
    return jsonify(
        {
            "service": "token-service",
            "audience": TOKEN_AUDIENCE,
            "caller": client_id,
        }
    )


@app.post("/v1/mint")
def mint():
    client_id, err = _authenticate_client()
    if err:
        resp, status = err
        return resp, status

    nonce = request.headers.get("X-Nonce", "") or ""
    # A missing or blank nonce used to fall back to a literal string that was
    # shared across all callers; that silently broke replay protection. Now
    # it is an explicit client error.
    if not nonce or len(nonce) > MAX_NONCE_LENGTH:
        return jsonify({"error": "missing or oversize X-Nonce header"}), 400

    try:
        ok, body, status = _check_rate(client_id)
        if not ok:
            return body, status
        ok, body, status = _claim_nonce(client_id, nonce)
        if not ok:
            return body, status
    except RedisUnavailable:
        return _fail_closed_response()

    data = request.get_json(force=True, silent=True) or {}
    aud = data.get("audience", "")
    scope = data.get("scope", "")
    if aud not in CLIENTS[client_id]["audiences"]:
        return jsonify({"error": "bad audience"}), 400
    if scope not in CLIENTS[client_id]["scopes"]:
        return jsonify({"error": "scope not permitted"}), 403

    # Subject is bound to the authenticated client. The request body no
    # longer controls it: any supplied "subject" field is ignored. This
    # stops subject spoofing by any caller that can reach /v1/mint with
    # valid client credentials.
    subject = client_id

    now = int(time.time())
    # JTI is generated here from a cryptographically random UUID so that
    # attacker-supplied nonces cannot influence its value. This keeps JTI
    # uniqueness independent of caller behaviour and makes it safe to use
    # as the replay-cache key on downstream services.
    jti = str(uuid.uuid4())

    payload = {
        "iss": "token-service",
        "sub": subject,
        "aud": aud,
        "scope": scope,
        "iat": now,
        "nbf": now,
        "exp": now + TOKEN_LIFETIME_SECONDS,
        "jti": jti,
    }
    return jsonify(
        {
            "access_token": _sign(payload),
            "scope": scope,
            "issued_to": client_id,
            "subject": subject,
            "expires_in": TOKEN_LIFETIME_SECONDS,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003)
