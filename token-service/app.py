from flask import Flask, jsonify, request
import os, time, base64, json, hmac, hashlib
import redis

app = Flask(__name__)
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
STRICT_REDIS = os.getenv("STRICT_REDIS", "false").lower() == "true"
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin")
ACCESS_TOKEN_SECRET = os.getenv("ACCESS_TOKEN_SECRET", "lab-access-token-secret")
NONCE_TTL_SECONDS = int(os.getenv("NONCE_TTL_SECONDS", "60"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
RATE_LIMIT_BURST = int(os.getenv("RATE_LIMIT_BURST", "60"))
CLIENTS = {
    "gateway": {
        "secret": os.getenv("GATEWAY_CLIENT_SECRET", "gateway-client-secret"),
        "scopes": {"admin.export.read", "internal.metrics.read", "debug.config.read", "token.discovery"},
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


def _fail_or_skip(msg):
    if STRICT_REDIS:
        return jsonify({"error": msg}), 503
    return None


def _check_nonce(client_id, nonce):
    try:
        r = _redis()
        key = f"nonce:{client_id}:{nonce}"
        if r.get(key):
            return False, jsonify({"error": "nonce replay"}), 403
        r.setex(key, NONCE_TTL_SECONDS, "1")
        return True, None, None
    except Exception:
        maybe = _fail_or_skip("redis unavailable")
        if maybe is not None:
            return False, maybe, 503
        return True, None, None


def _check_rate(client_id):
    try:
        r = _redis()
        key = f"rate:{client_id}:{int(time.time() // 60)}"
        count = r.incr(key)
        r.expire(key, 120)
        if count > RATE_LIMIT_BURST:
            return False, jsonify({"error": "rate limit exceeded"}), 429
        return True, None, None
    except Exception:
        maybe = _fail_or_skip("redis unavailable")
        if maybe is not None:
            return False, maybe, 503
        return True, None, None


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign(payload):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(ACCESS_TOKEN_SECRET.encode(), body, hashlib.sha256).digest()
    return f"{_b64e(body)}.{_b64e(sig)}"


@app.get('/health')
def health():
    return jsonify({"ok": True, "service": "token-service"})


@app.get('/.well-known/mesh')
def mesh():
    # Intentionally over-exposed in the vulnerable baseline.
    return jsonify({"service": "token-service", "audience": TOKEN_AUDIENCE, "mode": "redis-backed-legacy-v2", "clients": sorted(CLIENTS.keys())})


@app.post('/v1/mint')
def mint():
    client_id = request.headers.get('X-Client-Id', '')
    client_secret = request.headers.get('X-Client-Secret', '')
    nonce = request.headers.get('X-Nonce', request.headers.get('X-Request-Id', 'missing-nonce'))
    if client_id not in CLIENTS:
        return jsonify({"error": "unknown client"}), 403
    if not hmac.compare_digest(client_secret, CLIENTS[client_id]['secret']):
        return jsonify({"error": "bad client secret"}), 403
    ok, body, status = _check_rate(client_id)
    if not ok:
        return body, status
    ok, body, status = _check_nonce(client_id, nonce)
    if not ok:
        return body, status
    data = request.get_json(force=True, silent=True) or {}
    aud = data.get('audience', '')
    scope = data.get('scope', '')
    subject = data.get('subject', client_id)
    if aud not in CLIENTS[client_id]['audiences']:
        return jsonify({"error": "bad audience"}), 400
    if scope not in CLIENTS[client_id]['scopes']:
        return jsonify({"error": "scope not permitted"}), 403
    payload = {
        "iss": "token-service",
        "sub": subject,
        "aud": aud,
        "scope": scope,
        "iat": int(time.time()),
        "exp": int(time.time()) + 30,
        "jti": nonce + '-' + str(int(time.time()*1000)),
    }
    return jsonify({"access_token": _sign(payload), "scope": scope, "issued_to": client_id, "subject": subject})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003)
