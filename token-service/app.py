from flask import Flask, jsonify, request
import os
import time
import base64
import json
import uuid

import redis
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin")
TOKEN_LIFETIME_SECONDS = int(os.getenv("TOKEN_LIFETIME_SECONDS", "30"))
ASSERTION_MAX_LIFETIME_SECONDS = int(os.getenv("ASSERTION_MAX_LIFETIME_SECONDS", "60"))
ASSERTION_REPLAY_TTL_SECONDS = int(os.getenv("ASSERTION_REPLAY_TTL_SECONDS", "120"))
CLOCK_SKEW_SECONDS = int(os.getenv("CLOCK_SKEW_SECONDS", "5"))
RATE_LIMIT_BURST = int(os.getenv("RATE_LIMIT_BURST", "60"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
MAX_ASSERTION_SIZE = int(os.getenv("MAX_ASSERTION_SIZE", "4096"))
SIGNING_KEY_ID = os.getenv("TOKEN_SIGNING_KEY_ID", "ts-v1")


# -----------------------------------------------------------------------------
# base64url + JWT-ish helpers (inlined to avoid a separate shared package)
# -----------------------------------------------------------------------------


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _load_private(seed_b64: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_b64d(seed_b64))


def _load_public(pub_b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_b64d(pub_b64))


def _pub_bytes(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


TYP_ACCESS_TOKEN = "at+jwt"
TYP_CLIENT_AUTH = "client-auth+jwt"
TYP_ACTOR_AUTH = "actor-auth+jwt"


def _sign_compact(priv: Ed25519PrivateKey, header: dict, payload: dict) -> str:
    h_b64 = _b64e(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p_b64 = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = priv.sign(signing_input)
    return f"{h_b64}.{p_b64}.{_b64e(sig)}"


def _verify_compact(pub_by_kid, token: str, expected_typ: str):
    """Verify a compact Ed25519-signed JWT-like token.
    pub_by_kid is a mapping of kid -> Ed25519PublicKey. expected_typ is
    the JOSE header typ value this call site expects; it is part of the
    trust decision so client assertions, actor assertions, and access
    tokens cannot be substituted for one another even if a kid is
    accidentally reused. Returns (header, payload, None) on success or
    (None, None, reason) on failure.
    """
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
    if header.get("typ") != expected_typ:
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
# Identity configuration
# -----------------------------------------------------------------------------


SIGNING_KEY = _load_private(os.environ["TOKEN_SIGNING_KEY_SEED_B64"])
SIGNING_PUB = _pub_bytes(SIGNING_KEY)


def _kid_for(label: str, version: str = "v1") -> str:
    return f"{label}-{version}"


# Registered clients. Each holds only a public key; the token-service holds
# zero client secrets. Scopes here are the *self-mint* scopes available via
# client_assertion alone. Any scope not in the set must be authorized by an
# operator via actor_assertion.
CLIENTS = {
    "gateway": {
        "pub_by_kid": {
            _kid_for("gateway-client"): _load_public(
                os.environ["GATEWAY_CLIENT_PUB_KEY_B64"]
            ),
        },
        "scopes": set(),
        "audiences": {TOKEN_AUDIENCE},
        "can_relay": True,
    },
    "observer": {
        "pub_by_kid": {
            _kid_for("observer-client"): _load_public(
                os.environ["OBSERVER_CLIENT_PUB_KEY_B64"]
            ),
        },
        "scopes": {"internal.metrics.read", "debug.config.read", "token.discovery"},
        "audiences": {TOKEN_AUDIENCE},
        "can_relay": False,
    },
}

# Registered operators. Operators are the real authority for privileged
# scopes; their entitlements do not live with any single client.
OPERATORS = {
    "ops-alice": {
        "pub_by_kid": {
            _kid_for("ops-alice"): _load_public(os.environ["OPS_ALICE_PUB_KEY_B64"]),
        },
        "scopes": {"admin.export.read", "internal.metrics.read", "debug.config.read"},
    },
    "ops-bob": {
        "pub_by_kid": {
            _kid_for("ops-bob"): _load_public(os.environ["OPS_BOB_PUB_KEY_B64"]),
        },
        "scopes": {"admin.export.read"},
    },
}


# -----------------------------------------------------------------------------
# Redis state: rate limit, assertion replay cache
# -----------------------------------------------------------------------------


class RedisUnavailable(Exception):
    pass


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


def _fail_closed():
    return jsonify({"error": "security state backend unavailable"}), 503


def _check_rate(client_id: str):
    try:
        r = _redis()
        window = int(time.time() // 60)
        key = f"rate:{client_id}:{window}"
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.expire(key, 120)
        count, _ = pipe.execute()
    except Exception:
        raise RedisUnavailable()
    if count > RATE_LIMIT_BURST:
        return False, jsonify({"error": "rate limit exceeded"}), 429
    return True, None, None


def _claim_assertion_jti(kind: str, issuer: str, jti: str) -> bool:
    """Claim a per-issuer assertion JTI atomically. Returns True if the JTI
    was fresh and is now reserved, False if the same JTI has already been
    seen. Raises RedisUnavailable on backend failure so the caller can fail
    closed.
    """
    key = f"assert:{kind}:{issuer}:{jti}"
    try:
        ok = _redis().set(key, "1", nx=True, ex=ASSERTION_REPLAY_TTL_SECONDS)
    except Exception:
        raise RedisUnavailable()
    return bool(ok)


# -----------------------------------------------------------------------------
# Assertion verification
# -----------------------------------------------------------------------------


def _check_assertion_claims(payload: dict, issuer_whitelist: set, now: int):
    iss = payload.get("iss")
    sub = payload.get("sub")
    if not isinstance(iss, str) or iss not in issuer_whitelist:
        return "unknown issuer"
    if sub != iss:
        return "iss must equal sub"
    if payload.get("aud") != "token-service":
        return "bad audience"
    iat = payload.get("iat")
    exp = payload.get("exp")
    nbf = payload.get("nbf", iat)
    if not isinstance(iat, int) or not isinstance(exp, int):
        return "bad time claims"
    if not isinstance(nbf, int):
        nbf = iat
    if iat > now + CLOCK_SKEW_SECONDS:
        return "assertion from the future"
    if nbf > now + CLOCK_SKEW_SECONDS:
        return "assertion not yet valid"
    if exp <= now - CLOCK_SKEW_SECONDS:
        return "assertion expired"
    if exp - iat > ASSERTION_MAX_LIFETIME_SECONDS + CLOCK_SKEW_SECONDS:
        return "assertion lifetime too long"
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti or len(jti) > 128:
        return "missing or bad jti"
    return None


def _verify_client_assertion(assertion: str):
    if not assertion or len(assertion) > MAX_ASSERTION_SIZE:
        return None, None, "bad client assertion size"
    if assertion.count(".") != 2:
        return None, None, "bad client assertion format"
    h_b64, _p, _s = assertion.split(".", 2)
    try:
        header = json.loads(_b64d(h_b64).decode())
    except Exception:
        return None, None, "bad client assertion header"
    if not isinstance(header, dict):
        return None, None, "bad client assertion header"
    kid = header.get("kid")
    matching_client = None
    pub_by_kid = None
    for cid, conf in CLIENTS.items():
        if kid in conf["pub_by_kid"]:
            matching_client = cid
            pub_by_kid = conf["pub_by_kid"]
            break
    if matching_client is None or pub_by_kid is None:
        return None, None, "unknown client kid"
    _h, payload, err = _verify_compact(pub_by_kid, assertion, TYP_CLIENT_AUTH)
    if err:
        return None, None, err
    err = _check_assertion_claims(payload, {matching_client}, int(time.time()))
    if err:
        return None, None, err
    return matching_client, payload, None


def _verify_actor_assertion(assertion: str):
    if not assertion or len(assertion) > MAX_ASSERTION_SIZE:
        return None, None, "bad actor assertion size"
    if assertion.count(".") != 2:
        return None, None, "bad actor assertion format"
    h_b64, _p, _s = assertion.split(".", 2)
    try:
        header = json.loads(_b64d(h_b64).decode())
    except Exception:
        return None, None, "bad actor assertion header"
    if not isinstance(header, dict):
        return None, None, "bad actor assertion header"
    kid = header.get("kid")
    matching_op = None
    pub_by_kid = None
    for oid, conf in OPERATORS.items():
        if kid in conf["pub_by_kid"]:
            matching_op = oid
            pub_by_kid = conf["pub_by_kid"]
            break
    if matching_op is None:
        return None, None, "unknown operator kid"
    _h, payload, err = _verify_compact(pub_by_kid, assertion, TYP_ACTOR_AUTH)
    if err:
        return None, None, err
    err = _check_assertion_claims(payload, {matching_op}, int(time.time()))
    if err:
        return None, None, err
    # Scope pinning is MANDATORY on actor assertions. An unpinned
    # assertion would otherwise be a proof-of-intent for the operator's
    # entire entitlement set, and a compromised relay could choose any
    # scope the operator holds. Requiring a pinned scope makes each
    # assertion a single-scope, single-shot capability.
    scope_claim = payload.get("scope")
    if not isinstance(scope_claim, str) or not scope_claim or " " in scope_claim:
        return None, None, "actor assertion must pin a single scope"
    return matching_op, payload, None


# -----------------------------------------------------------------------------
# HTTP routes
# -----------------------------------------------------------------------------


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "token-service"})


@app.get("/.well-known/jwks")
def jwks():
    """Public discovery of signing keys. This is anonymous because it
    contains only the public key material needed to verify tokens. No
    client identifiers, no scopes, no secrets.
    """
    return jsonify(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": SIGNING_KEY_ID,
                    "x": _b64e(SIGNING_PUB),
                }
            ]
        }
    )


@app.post("/v1/mint")
def mint():
    data = request.get_json(force=True, silent=True) or {}
    client_assertion = data.get("client_assertion", "") or ""
    actor_assertion = data.get("actor_assertion", "") or ""
    requested_aud = data.get("audience", "")
    requested_scope = data.get("scope", "")

    # Step 1: verify client assertion (always required).
    client_id, client_payload, err = _verify_client_assertion(client_assertion)
    if err:
        return jsonify({"error": f"client_assertion: {err}"}), 403

    try:
        ok, body, status = _check_rate(client_id)
        if not ok:
            return body, status
        # Replay-protect the client assertion itself. Two mint calls with
        # the same client assertion (i.e. same jti) cannot both succeed.
        if not _claim_assertion_jti("client", client_id, client_payload["jti"]):
            return jsonify({"error": "client_assertion replay"}), 403
    except RedisUnavailable:
        return _fail_closed()

    if requested_aud not in CLIENTS[client_id]["audiences"]:
        return jsonify({"error": "bad audience"}), 400

    # Step 2: determine the effective subject and authorized scopes. If an
    # actor assertion is supplied we require it to verify AND the client
    # must be allowed to relay for operators.
    effective_subject = client_id
    actor_id = None
    permitted_scopes = CLIENTS[client_id]["scopes"]

    if actor_assertion:
        if not CLIENTS[client_id]["can_relay"]:
            return jsonify({"error": "client cannot relay actor assertions"}), 403
        actor_id, actor_payload, err = _verify_actor_assertion(actor_assertion)
        if err:
            return jsonify({"error": f"actor_assertion: {err}"}), 403
        try:
            if not _claim_assertion_jti("actor", actor_id, actor_payload["jti"]):
                return jsonify({"error": "actor_assertion replay"}), 403
        except RedisUnavailable:
            return _fail_closed()
        # Scope is mandatory on actor assertions (enforced by
        # _verify_actor_assertion). Enforce strict pinning here: the
        # pinned scope must equal the requested scope. No exceptions, no
        # "if present" path. The operator's assertion is proof of intent
        # for one specific scope.
        if actor_payload["scope"] != requested_scope:
            return jsonify({"error": "actor_assertion scope mismatch"}), 403
        permitted_scopes = OPERATORS[actor_id]["scopes"]
        effective_subject = actor_id

    if requested_scope not in permitted_scopes:
        return jsonify({"error": "scope not permitted"}), 403

    now = int(time.time())
    header = {"alg": "EdDSA", "typ": TYP_ACCESS_TOKEN, "kid": SIGNING_KEY_ID}
    payload = {
        "iss": "token-service",
        "sub": effective_subject,
        "aud": requested_aud,
        "scope": requested_scope,
        "iat": now,
        "nbf": now,
        "exp": now + TOKEN_LIFETIME_SECONDS,
        "jti": str(uuid.uuid4()),
    }
    if actor_id is not None:
        payload["act"] = {"sub": client_id}
        # Bind this token to the originating actor assertion's jti so the
        # downstream service can include it in the response envelope.
        # This lets the operator verify "the response I am holding came
        # from a token minted from MY actor assertion" end-to-end.
        payload["act_jti"] = actor_payload["jti"]

    token = _sign_compact(SIGNING_KEY, header, payload)
    return jsonify(
        {
            "access_token": token,
            "token_type": "Bearer",
            "scope": requested_scope,
            "expires_in": TOKEN_LIFETIME_SECONDS,
            "subject": effective_subject,
            "issued_to": client_id,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003)
