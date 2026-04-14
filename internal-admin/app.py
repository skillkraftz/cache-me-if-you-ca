from flask import Flask, jsonify, request
import os

import redis

from shared.auth import now_ts, verify_payload

app = Flask(__name__)
REPLICA_NAME = os.getenv("REPLICA_NAME", "internal-admin")
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin")
ACCESS_TOKEN_PUBLIC_KEY_PEM = os.getenv("ACCESS_TOKEN_PUBLIC_KEY_PEM", "")
OPERATOR_PUBLIC_KEY_PEM = os.getenv("OPERATOR_PUBLIC_KEY_PEM", "")
OPERATOR_ASSERTION_AUDIENCE = os.getenv(
    "OPERATOR_ASSERTION_AUDIENCE", "mesh-operator-approval"
)
ALLOWED_OPERATOR_IDS = {
    value.strip()
    for value in os.getenv("ALLOWED_OPERATOR_IDS", "ops-admin").split(",")
    if value.strip()
}
JTI_CACHE_TTL_SECONDS = int(os.getenv("JTI_CACHE_TTL_SECONDS", "120"))
ASSERTION_CLOCK_SKEW_SECONDS = int(os.getenv("ASSERTION_CLOCK_SKEW_SECONDS", "5"))
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
SCOPE_POLICY = {
    "admin.export.read": {
        "clients": {"gateway"},
        "operators": ALLOWED_OPERATOR_IDS,
        "resource": "/admin/export",
    },
    "debug.config.read": {"clients": {"observer"}},
    "internal.metrics.read": {"clients": {"observer"}},
}


def _redis():
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def _reserve_once(key: str, ttl: int, error: str, status: int):
    try:
        if not _redis().set(key, REPLICA_NAME, ex=max(1, ttl), nx=True):
            return False, error, status
    except Exception:
        return False, "token state unavailable", 503
    return True, None, None


def _validate_window(payload: dict, kind: str):
    now = now_ts()
    if payload.get("iat", 0) > now + ASSERTION_CLOCK_SKEW_SECONDS:
        return None, f"{kind} not yet valid", 403
    if payload.get("exp", 0) < now - ASSERTION_CLOCK_SKEW_SECONDS:
        return None, f"{kind} expired", 403
    return now, None, None


def _verify_operator_assertion(
    operator_assertion: str, client_id: str, scope: str, resource: str
):
    payload = verify_payload(operator_assertion, OPERATOR_PUBLIC_KEY_PEM)
    if payload is None:
        return None, "bad operator assertion", 403
    now, err, status = _validate_window(payload, "operator assertion")
    if err:
        return None, err, status
    operator_id = payload.get("iss")
    if operator_id not in ALLOWED_OPERATOR_IDS:
        return None, "unknown operator", 403
    if payload.get("sub") != operator_id:
        return None, "bad operator subject", 403
    if payload.get("aud") != OPERATOR_ASSERTION_AUDIENCE:
        return None, "bad operator audience", 403
    if payload.get("scope") != scope:
        return None, "operator scope not permitted", 403
    if payload.get("client_id") != client_id:
        return None, "operator client mismatch", 403
    if payload.get("resource") != resource:
        return None, "operator resource mismatch", 403
    jti = payload.get("jti")
    if not jti:
        return None, "missing operator assertion jti", 403
    ok, err, status = _reserve_once(
        f"operator-approval-use:{jti}",
        payload.get("exp", now) - now + ASSERTION_CLOCK_SKEW_SECONDS,
        "operator approval replay",
        403,
    )
    if not ok:
        return None, err, status
    return payload, None, None


def verify_token(token: str):
    payload = verify_payload(token, ACCESS_TOKEN_PUBLIC_KEY_PEM)
    if payload is None:
        return None, "bad token signature", 403
    now, err, status = _validate_window(payload, "token")
    if err:
        return None, err, status
    if payload.get("iss") != "token-service":
        return None, "bad issuer", 403
    if payload.get("aud") != TOKEN_AUDIENCE:
        return None, "bad audience", 403
    client_id = payload.get("client_id")
    if not client_id or payload.get("sub") != client_id:
        return None, "bad token subject", 403
    jti = payload.get("jti")
    if not jti:
        return None, "missing jti", 403
    ok, err, status = _reserve_once(
        f"access-jti:{jti}",
        max(payload.get("exp", now) - now, JTI_CACHE_TTL_SECONDS),
        "replay detected",
        403,
    )
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
    policy = SCOPE_POLICY[scope]
    client_id = payload.get("client_id", "")
    if client_id not in policy["clients"]:
        return None, (jsonify({"error": "caller not permitted"}), 403)
    allowed_operators = policy.get("operators")
    if allowed_operators is not None:
        operator_assertion = payload.get("operator_assertion", "")
        if not operator_assertion:
            return None, (jsonify({"error": "missing operator approval"}), 403)
        operator_payload, err, status = _verify_operator_assertion(
            operator_assertion, client_id, scope, policy["resource"]
        )
        if err:
            return None, (jsonify({"error": err}), status)
        if payload.get("actor") != operator_payload.get("sub"):
            return None, (jsonify({"error": "actor mismatch"}), 403)
        if operator_payload.get("sub") not in allowed_operators:
            return None, (jsonify({"error": "operator not permitted"}), 403)
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
            "allowed_subjects": ["observer"],
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
            "caller": payload.get("client_id"),
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
            "caller": payload.get("client_id"),
            "records": 2,
            "users": [
                {"id": 1, "email": "alice@example.internal"},
                {"id": 2, "email": "bob@example.internal"},
            ],
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
