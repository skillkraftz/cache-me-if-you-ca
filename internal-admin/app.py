from flask import Flask, jsonify, request
import os
import time
import base64
import json

import redis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

REPLICA_NAME = os.getenv("REPLICA_NAME", "internal-admin")
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin")
JTI_CACHE_TTL_SECONDS = int(os.getenv("JTI_CACHE_TTL_SECONDS", "120"))
MAX_TOKEN_LIFETIME_SECONDS = int(os.getenv("MAX_TOKEN_LIFETIME_SECONDS", "60"))
CLOCK_SKEW_SECONDS = int(os.getenv("CLOCK_SKEW_SECONDS", "5"))
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

# Signing public keys indexed by kid. This service holds NO private key
# material and can never mint a token. Keys are provided via env for the
# lab; in production they would be fetched from the issuer's JWKS endpoint
# and pinned by fingerprint.
TOKEN_VERIFY_KEYS = {}
for entry in os.getenv("TOKEN_VERIFY_KEYS", "").split(","):
    entry = entry.strip()
    if not entry:
        continue
    kid, pub_b64 = entry.split(":", 1)
    TOKEN_VERIFY_KEYS[kid] = Ed25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(pub_b64 + "=" * (-len(pub_b64) % 4))
    )

if not TOKEN_VERIFY_KEYS:
    raise RuntimeError("no TOKEN_VERIFY_KEYS configured; refusing to start")

# Subjects we are willing to honour. This set is deliberately narrow and
# lives at the consumer side so that even a compromised issuer cannot mint
# an admin token for an arbitrary actor. Operators are included because
# delegated tokens mint with sub=<operator> and act={sub: <relaying client>}.
ALLOWED_SUBJECTS = {"gateway", "observer", "ops-alice", "ops-bob"}

# Tokens that carry an "act" (actor) claim must have the actor sub inside
# this set; this is the list of clients that are allowed to relay.
ALLOWED_ACTORS = {"gateway"}


# -----------------------------------------------------------------------------
# Crypto helpers (inlined, same shape as token-service)
# -----------------------------------------------------------------------------


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _verify_compact(pub_by_kid, token: str):
    if not token or token.count(".") != 2:
        return None, None, "bad token format"
    h_b64, p_b64, s_b64 = token.split(".", 2)
    signing_input = f"{h_b64}.{p_b64}".encode()
    try:
        header = json.loads(_b64d(h_b64).decode())
        payload = json.loads(_b64d(p_b64).decode())
        sig = _b64d(s_b64)
    except Exception:
        return None, None, "bad token encoding"
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None, None, "bad token structure"
    if header.get("alg") != "EdDSA":
        return None, None, "bad alg"
    if header.get("typ") != "JWT":
        return None, None, "bad typ"
    kid = header.get("kid")
    pub = pub_by_kid.get(kid)
    if pub is None:
        return None, None, "unknown kid"
    try:
        pub.verify(sig, signing_input)
    except InvalidSignature:
        return None, None, "bad signature"
    return header, payload, None


# -----------------------------------------------------------------------------
# Redis-backed JTI replay cache
# -----------------------------------------------------------------------------


_redis_client = None


class ReplayBackendUnavailable(Exception):
    pass


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


def _claim_jti(jti: str) -> bool:
    key = f"tok_jti:{jti}"
    try:
        ok = _redis().set(key, "1", nx=True, ex=JTI_CACHE_TTL_SECONDS)
    except Exception:
        raise ReplayBackendUnavailable()
    return bool(ok)


# -----------------------------------------------------------------------------
# Token verification
# -----------------------------------------------------------------------------


def verify_token(token: str):
    _h, payload, err = _verify_compact(TOKEN_VERIFY_KEYS, token)
    if err:
        return None, err

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
    if iat > now + CLOCK_SKEW_SECONDS:
        return None, "token from the future"
    if nbf > now + CLOCK_SKEW_SECONDS:
        return None, "token not yet valid"
    if exp <= now - CLOCK_SKEW_SECONDS:
        return None, "expired"
    if exp - iat > MAX_TOKEN_LIFETIME_SECONDS + CLOCK_SKEW_SECONDS:
        return None, "token lifetime too long"

    subject = payload.get("sub", "")
    if subject not in ALLOWED_SUBJECTS:
        return None, "subject not permitted"

    # If this is a delegated token (act claim), the actor must be in the
    # allowed relay set. This is a second independent check: the issuer
    # already vetted the actor, but the consumer also enforces its own
    # policy on who may act on behalf of others.
    act = payload.get("act")
    if act is not None:
        if not isinstance(act, dict):
            return None, "bad act claim"
        actor_sub = act.get("sub")
        if actor_sub not in ALLOWED_ACTORS:
            return None, "actor not permitted"

    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        return None, "missing jti"

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
        if err == "replay store unavailable":
            return None, (jsonify({"error": err}), 503)
        return None, (jsonify({"error": err}), 403)
    scopes = set((payload.get("scope") or "").split())
    if scope not in scopes:
        return None, (jsonify({"error": "missing required scope"}), 403)
    return payload, None


# -----------------------------------------------------------------------------
# HTTP routes
# -----------------------------------------------------------------------------


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": REPLICA_NAME})


@app.get("/debug/config")
def debug_config():
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
            "actor": (payload.get("act") or {}).get("sub"),
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
            "actor": (payload.get("act") or {}).get("sub"),
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
            "actor": (payload.get("act") or {}).get("sub"),
            "records": 2,
            "users": [
                {"id": 1, "email": "alice@example.internal"},
                {"id": 2, "email": "bob@example.internal"},
            ],
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
