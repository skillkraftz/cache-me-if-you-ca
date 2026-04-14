from flask import Flask, jsonify, request
import os
import time

import redis

from shared.auth import new_jti, now_ts, sha256_hex, sign_payload, verify_payload

app = Flask(__name__)
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin")
ACCESS_TOKEN_PRIVATE_KEY_PEM = os.getenv("ACCESS_TOKEN_PRIVATE_KEY_PEM", "")
SERVICE_ASSERTION_AUDIENCE = os.getenv("SERVICE_ASSERTION_AUDIENCE", "token-service")
OPERATOR_ASSERTION_AUDIENCE = os.getenv(
    "OPERATOR_ASSERTION_AUDIENCE", "mesh-operator-approval"
)
OPERATOR_PUBLIC_KEY_PEM = os.getenv("OPERATOR_PUBLIC_KEY_PEM", "")
ALLOWED_OPERATOR_IDS = {
    value.strip()
    for value in os.getenv("ALLOWED_OPERATOR_IDS", "ops-admin").split(",")
    if value.strip()
}
ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "30"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
RATE_LIMIT_BURST = int(os.getenv("RATE_LIMIT_BURST", "60"))
ASSERTION_TTL_SECONDS = int(os.getenv("ASSERTION_TTL_SECONDS", "30"))
ASSERTION_CLOCK_SKEW_SECONDS = int(os.getenv("ASSERTION_CLOCK_SKEW_SECONDS", "5"))
CLIENTS = {
    "gateway": {
        "public_key": os.getenv("GATEWAY_CLIENT_PUBLIC_KEY_PEM", ""),
        "token_grants": {"admin.export.read"},
        "allow_discovery": False,
        "operator_scopes": {"admin.export.read"},
    },
    "observer": {
        "public_key": os.getenv("OBSERVER_CLIENT_PUBLIC_KEY_PEM", ""),
        "token_grants": {"internal.metrics.read", "debug.config.read"},
        "allow_discovery": True,
        "operator_scopes": set(),
    },
}


def _redis():
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def _reserve_once(key: str, ttl: int, error: str, status: int):
    try:
        if not _redis().set(key, "1", ex=max(1, ttl), nx=True):
            return False, jsonify({"error": error}), status
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


def _validate_window(payload: dict, kind: str):
    now = now_ts()
    if payload.get("iat", 0) > now + ASSERTION_CLOCK_SKEW_SECONDS:
        return None, f"{kind} not yet valid"
    if payload.get("exp", 0) < now - ASSERTION_CLOCK_SKEW_SECONDS:
        return None, f"{kind} expired"
    return now, None


def _authenticate_client():
    client_id = request.headers.get("X-Client-Id", "")
    assertion = request.headers.get("X-Client-Assertion", "")
    client = CLIENTS.get(client_id)
    if client is None:
        return None, None, None, (jsonify({"error": "unknown client"}), 403)
    payload = verify_payload(assertion, client["public_key"])
    if payload is None:
        return None, None, None, (jsonify({"error": "bad client assertion"}), 403)
    now, err = _validate_window(payload, "client assertion")
    if err:
        return None, None, None, (jsonify({"error": err}), 403)
    if payload.get("iss") != client_id or payload.get("sub") != client_id:
        return None, None, None, (jsonify({"error": "bad client identity"}), 403)
    if payload.get("aud") != SERVICE_ASSERTION_AUDIENCE:
        return None, None, None, (jsonify({"error": "bad client audience"}), 403)
    if payload.get("method") != request.method or payload.get("path") != request.path:
        return (
            None,
            None,
            None,
            (jsonify({"error": "client assertion request mismatch"}), 403),
        )
    if payload.get("body_sha256") != sha256_hex(request.get_data(cache=True) or b""):
        return (
            None,
            None,
            None,
            (jsonify({"error": "client assertion body mismatch"}), 403),
        )
    jti = payload.get("jti")
    if not jti:
        return (
            None,
            None,
            None,
            (jsonify({"error": "missing client assertion jti"}), 403),
        )
    ok, body, status = _reserve_once(
        f"client-assertion:{client_id}:{jti}",
        payload.get("exp", now) - now + ASSERTION_CLOCK_SKEW_SECONDS,
        "client assertion replay",
        403,
    )
    if not ok:
        return None, None, None, (body, status)
    return client_id, client, payload, None


def _verify_operator_assertion(
    operator_assertion: str, client_id: str, scope: str, resource: str
):
    payload = verify_payload(operator_assertion, OPERATOR_PUBLIC_KEY_PEM)
    if payload is None:
        return None, (jsonify({"error": "bad operator assertion"}), 403)
    now, err = _validate_window(payload, "operator assertion")
    if err:
        return None, (jsonify({"error": err}), 403)
    operator_id = payload.get("iss")
    if operator_id not in ALLOWED_OPERATOR_IDS:
        return None, (jsonify({"error": "unknown operator"}), 403)
    if payload.get("sub") != operator_id:
        return None, (jsonify({"error": "bad operator subject"}), 403)
    if payload.get("aud") != OPERATOR_ASSERTION_AUDIENCE:
        return None, (jsonify({"error": "bad operator audience"}), 403)
    if payload.get("scope") != scope:
        return None, (jsonify({"error": "operator scope not permitted"}), 403)
    if payload.get("client_id") != client_id:
        return None, (jsonify({"error": "operator client mismatch"}), 403)
    if payload.get("resource") != resource:
        return None, (jsonify({"error": "operator resource mismatch"}), 403)
    jti = payload.get("jti")
    if not jti:
        return None, (jsonify({"error": "missing operator assertion jti"}), 403)
    ok, body, status = _reserve_once(
        f"operator-approval:{jti}",
        payload.get("exp", now) - now + ASSERTION_CLOCK_SKEW_SECONDS,
        "operator approval replay",
        403,
    )
    if not ok:
        return None, (body, status)
    return payload, None


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "token-service"})


@app.get("/.well-known/mesh")
def mesh():
    client_id, client, _, err = _authenticate_client()
    if err:
        return err
    if not client["allow_discovery"]:
        return jsonify({"error": "discovery not permitted"}), 403
    return jsonify(
        {"service": "token-service", "audience": TOKEN_AUDIENCE, "client_id": client_id}
    )


@app.post("/v1/mint")
def mint():
    client_id, client, _, err = _authenticate_client()
    if err:
        return err
    ok, body, status = _check_rate(client_id)
    if not ok:
        return body, status
    data = request.get_json(force=True, silent=True) or {}
    aud = data.get("audience", "")
    scope = data.get("scope", "")
    if aud != TOKEN_AUDIENCE:
        return jsonify({"error": "bad audience"}), 400
    if scope not in client["token_grants"]:
        return jsonify({"error": "scope not permitted"}), 403
    operator_assertion = str(data.get("operator_assertion") or "")
    actor = None
    if scope in client["operator_scopes"]:
        if not operator_assertion:
            return jsonify({"error": "operator approval required"}), 403
        operator_payload, err = _verify_operator_assertion(
            operator_assertion, client_id, scope, "/admin/export"
        )
        if err:
            return err
        actor = operator_payload["sub"]
    elif operator_assertion:
        return jsonify({"error": "operator approval not accepted for scope"}), 400
    now = now_ts()
    payload = {
        "iss": "token-service",
        "sub": client_id,
        "client_id": client_id,
        "aud": aud,
        "scope": scope,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
        "jti": new_jti(),
    }
    if operator_assertion:
        payload["actor"] = actor
        payload["operator_assertion"] = operator_assertion
    return jsonify(
        {
            "access_token": sign_payload(payload, ACCESS_TOKEN_PRIVATE_KEY_PEM),
            "scope": scope,
            "issued_to": client_id,
            "subject": client_id,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003)
