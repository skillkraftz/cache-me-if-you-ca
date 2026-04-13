from flask import Flask, jsonify, request
import os, time, base64, json, hmac, hashlib
import redis

app = Flask(__name__)
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin")
ACCESS_TOKEN_SECRET = os.getenv("ACCESS_TOKEN_SECRET", "lab-access-token-secret")
NONCE_TTL_SECONDS = int(os.getenv("NONCE_TTL_SECONDS", "60"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
RATE_LIMIT_BURST = int(os.getenv("RATE_LIMIT_BURST", "60"))
MAX_NONCE_LENGTH = int(os.getenv("MAX_NONCE_LENGTH", "128"))
MAX_SUBJECT_LENGTH = int(os.getenv("MAX_SUBJECT_LENGTH", "128"))
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


def _redis():
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def _authenticate_client(required_scope: str | None = None):
    client_id = request.headers.get("X-Client-Id", "")
    client_secret = request.headers.get("X-Client-Secret", "")
    client = CLIENTS.get(client_id)
    if client is None:
        return None, None, (jsonify({"error": "unknown client"}), 403)
    if not hmac.compare_digest(client_secret, client["secret"]):
        return None, None, (jsonify({"error": "bad client secret"}), 403)
    if required_scope and required_scope not in client["scopes"]:
        return None, None, (jsonify({"error": "scope not permitted"}), 403)
    return client_id, client, None


def _validate_nonce(nonce: str):
    if not nonce:
        return False, (jsonify({"error": "missing nonce"}), 400)
    if len(nonce) > MAX_NONCE_LENGTH:
        return False, (jsonify({"error": "nonce too long"}), 400)
    return True, None


def _check_nonce(client_id, nonce):
    try:
        key = f"nonce:{client_id}:{nonce}"
        if not _redis().set(key, "1", ex=NONCE_TTL_SECONDS, nx=True):
            return False, jsonify({"error": "nonce replay"}), 403
        return True, None, None
    except Exception:
        return False, jsonify({"error": "redis unavailable"}), 503


def _check_rate(client_id):
    try:
        r = _redis()
        key = f"rate:{client_id}:{int(time.time() // 60)}"
        count = r.incr(key)
        if count == 1:
            r.expire(key, 120)
        if count > RATE_LIMIT_BURST:
            return False, jsonify({"error": "rate limit exceeded"}), 429
        return True, None, None
    except Exception:
        return False, jsonify({"error": "redis unavailable"}), 503


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign(payload):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(ACCESS_TOKEN_SECRET.encode(), body, hashlib.sha256).digest()
    return f"{_b64e(body)}.{_b64e(sig)}"


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "token-service"})


@app.get("/.well-known/mesh")
def mesh():
    client_id, _, err = _authenticate_client("token.discovery")
    if err:
        return err
    return jsonify(
        {"service": "token-service", "audience": TOKEN_AUDIENCE, "client_id": client_id}
    )


@app.post("/v1/mint")
def mint():
    client_id, client, err = _authenticate_client()
    if err:
        return err
    nonce = request.headers.get("X-Nonce", "").strip()
    ok, err = _validate_nonce(nonce)
    if not ok:
        return err
    ok, body, status = _check_rate(client_id)
    if not ok:
        return body, status
    ok, body, status = _check_nonce(client_id, nonce)
    if not ok:
        return body, status
    data = request.get_json(force=True, silent=True) or {}
    aud = data.get("audience", "")
    scope = data.get("scope", "")
    subject = str(data.get("subject") or client_id)
    if len(subject) > MAX_SUBJECT_LENGTH:
        return jsonify({"error": "subject too long"}), 400
    if aud not in client["audiences"]:
        return jsonify({"error": "bad audience"}), 400
    if scope not in client["scopes"]:
        return jsonify({"error": "scope not permitted"}), 403
    now = int(time.time())
    payload = {
        "iss": "token-service",
        "sub": subject,
        "client_id": client_id,
        "aud": aud,
        "scope": scope,
        "iat": now,
        "exp": now + 30,
        "jti": nonce + "-" + str(int(time.time() * 1000)),
    }
    return jsonify(
        {
            "access_token": _sign(payload),
            "scope": scope,
            "issued_to": client_id,
            "subject": subject,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003)
