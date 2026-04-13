from flask import Flask, jsonify, request, Response
import os
import time
import base64
import json
import hashlib

import redis
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

REPLICA_NAME = os.getenv("REPLICA_NAME", "internal-admin")
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin")
JTI_CACHE_TTL_SECONDS = int(os.getenv("JTI_CACHE_TTL_SECONDS", "120"))
MAX_TOKEN_LIFETIME_SECONDS = int(os.getenv("MAX_TOKEN_LIFETIME_SECONDS", "60"))
CLOCK_SKEW_SECONDS = int(os.getenv("CLOCK_SKEW_SECONDS", "5"))
RESPONSE_ENVELOPE_LIFETIME_SECONDS = int(
    os.getenv("RESPONSE_ENVELOPE_LIFETIME_SECONDS", "60")
)
MAX_REQUEST_NONCE_LENGTH = int(os.getenv("MAX_REQUEST_NONCE_LENGTH", "128"))
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
RESPONSE_SIGNING_KEY_ID = os.environ["RESPONSE_SIGNING_KEY_ID"]
RESPONSE_SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(
    base64.urlsafe_b64decode(
        os.environ["RESPONSE_SIGNING_KEY_SEED_B64"]
        + "=" * (-len(os.environ["RESPONSE_SIGNING_KEY_SEED_B64"]) % 4)
    )
)

# Signing public keys indexed by kid. This service holds NO private key
# material for access tokens and can never mint one. Keys are provided via
# env for the lab; in production they would be fetched from the issuer's
# JWKS endpoint and pinned by fingerprint.
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

# The subject policy below is the consumer's independent view of what a
# valid token looks like. It does NOT defer to the issuer's entitlement
# map. If the issuer is ever compromised or regresses, this is the last
# line of defense.
CLIENT_SUBJECTS = {"observer"}
OPERATOR_SUBJECTS = {"ops-alice", "ops-bob"}
ALLOWED_SUBJECTS = CLIENT_SUBJECTS | OPERATOR_SUBJECTS
ALLOWED_ACTORS = {"gateway"}

SUBJECT_SCOPE_POLICY = {
    "observer": {"internal.metrics.read", "debug.config.read", "token.discovery"},
    "ops-alice": {
        "admin.export.read",
        "internal.metrics.read",
        "debug.config.read",
        "audit.self.read",
    },
    "ops-bob": {"admin.export.read", "audit.self.read"},
}

AUDIT_RETENTION_SECONDS = int(os.getenv("AUDIT_RETENTION_SECONDS", "3600"))
AUDIT_QUERY_DEFAULT_WINDOW = int(os.getenv("AUDIT_QUERY_DEFAULT_WINDOW", "900"))
AUDIT_QUERY_MAX_ENTRIES = int(os.getenv("AUDIT_QUERY_MAX_ENTRIES", "500"))

TYP_ACCESS_TOKEN = "at+jwt"
TYP_RESPONSE_ENVELOPE = "ar+jwt"  # "admin response"


# -----------------------------------------------------------------------------
# Crypto helpers (inlined, same shape as token-service)
# -----------------------------------------------------------------------------


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign_compact(priv: Ed25519PrivateKey, header: dict, payload: dict) -> str:
    h_b64 = _b64e(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p_b64 = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = priv.sign(signing_input)
    return f"{h_b64}.{p_b64}.{_b64e(sig)}"


def _verify_compact(pub_by_kid, token: str, expected_typ: str):
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


def _audit_key(subject: str) -> str:
    return f"audit:op:{subject}"


def _record_audit(subject: str, entry: dict) -> None:
    """Append an audit record for this operator to Redis.

    Storage is a sorted set keyed by the operator subject and scored by
    iat, so we can query by time window and trim old records. The entry
    itself is the serialized JSON so we get free dedup-by-content.

    Fail-closed: if the audit backend cannot confirm the write, the
    caller must refuse the request. Otherwise the operator would see a
    successful response but find no audit entry for it on reconcile,
    triggering a false suppression alarm.
    """
    try:
        r = _redis()
        key = _audit_key(subject)
        payload = json.dumps(entry, separators=(",", ":"), sort_keys=True)
        now = int(time.time())
        pipe = r.pipeline()
        pipe.zadd(key, {payload: now})
        pipe.zremrangebyscore(key, "-inf", now - AUDIT_RETENTION_SECONDS)
        pipe.expire(key, AUDIT_RETENTION_SECONDS * 2)
        pipe.execute()
    except Exception:
        raise ReplayBackendUnavailable()


def _fetch_audit(subject: str, since: int):
    try:
        r = _redis()
        key = _audit_key(subject)
        raw = r.zrangebyscore(
            key, min=since, max="+inf", start=0, num=AUDIT_QUERY_MAX_ENTRIES
        )
    except Exception:
        raise ReplayBackendUnavailable()
    out = []
    for item in raw:
        try:
            out.append(json.loads(item))
        except Exception:
            continue
    return out


# -----------------------------------------------------------------------------
# Token verification
# -----------------------------------------------------------------------------


def verify_token(token: str):
    _h, payload, err = _verify_compact(TOKEN_VERIFY_KEYS, token, TYP_ACCESS_TOKEN)
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

    act = payload.get("act")
    if subject in OPERATOR_SUBJECTS:
        if not isinstance(act, dict):
            return None, "operator token missing act claim"
        actor_sub = act.get("sub")
        if actor_sub not in ALLOWED_ACTORS:
            return None, "actor not permitted"
    else:  # CLIENT_SUBJECTS
        if act is not None:
            return None, "self-minted token must not carry act claim"

    scope_claim = payload.get("scope", "")
    if not isinstance(scope_claim, str) or not scope_claim:
        return None, "missing scope"
    token_scopes = set(scope_claim.split())
    policy = SUBJECT_SCOPE_POLICY.get(subject, set())
    if not token_scopes.issubset(policy):
        return None, "subject not entitled to scope"

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
        return None, _envelope_error("forbidden", 403)
    token = auth.split(None, 1)[1].strip()
    payload, err = verify_token(token)
    if err:
        if err == "replay store unavailable":
            return None, _envelope_error(err, 503)
        return None, _envelope_error(err, 403)
    scopes = set((payload.get("scope") or "").split())
    if scope not in scopes:
        return None, _envelope_error("missing required scope", 403)
    return payload, None


# -----------------------------------------------------------------------------
# Response envelope construction
#
# Every response from a scoped endpoint - success or error - carries a
# signed envelope in the X-Response-Envelope header. The envelope is a
# compact Ed25519 JWT-shape that binds:
#
#   - This replica's identity (iss) and signing kid
#   - The HTTP path and status code (so a malicious gateway cannot
#     swap a 200 from a different endpoint into this slot)
#   - The caller-supplied X-Request-Nonce (so the same envelope cannot
#     be replayed against a different request)
#   - The actor-assertion JTI of the operator who authorized the call
#     (extracted from the access token's act_jti claim, so the operator
#     can verify "this response came from a token minted from MY actor
#     assertion")
#   - The token subject and scope
#   - A SHA-256 of the canonical JSON body bytes
#
# The body itself is serialized once with a fixed canonicalization
# (sort_keys + tight separators) so the operator can recompute the same
# digest. The envelope is a header, not part of the body, so the body
# bytes themselves are exactly what the operator hashes.
# -----------------------------------------------------------------------------


def _canonical_body(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _build_envelope(
    *,
    body_bytes: bytes,
    status: int,
    endpoint: str,
    subject: str,
    scope: str,
    actor_jti: str,
    request_nonce: str,
) -> str:
    now = int(time.time())
    body_hash = hashlib.sha256(body_bytes).digest()
    header = {
        "alg": "EdDSA",
        "typ": TYP_RESPONSE_ENVELOPE,
        "kid": RESPONSE_SIGNING_KEY_ID,
    }
    claims = {
        "iss": REPLICA_NAME,
        "iat": now,
        "exp": now + RESPONSE_ENVELOPE_LIFETIME_SECONDS,
        "endpoint": endpoint,
        "status": status,
        "request_nonce": request_nonce,
        "actor_jti": actor_jti,
        "subject": subject,
        "scope": scope,
        "body_sha256": _b64e(body_hash),
    }
    return _sign_compact(RESPONSE_SIGNING_KEY, header, claims)


def _request_nonce() -> str:
    nonce = request.headers.get("X-Request-Nonce", "") or ""
    # An attacker cannot meaningfully control the nonce field beyond
    # forcing missing / oversize, both of which the operator detects on
    # verify. We still bound size to avoid memory abuse.
    if len(nonce) > MAX_REQUEST_NONCE_LENGTH:
        return ""
    return nonce


def _envelope_response(
    payload: dict,
    status: int,
    *,
    subject: str,
    scope: str,
    actor_jti: str,
):
    body_bytes = _canonical_body(payload)
    envelope = _build_envelope(
        body_bytes=body_bytes,
        status=status,
        endpoint=request.path,
        subject=subject,
        scope=scope,
        actor_jti=actor_jti,
        request_nonce=_request_nonce(),
    )
    resp = Response(body_bytes, status=status, mimetype="application/json")
    resp.headers["X-Response-Envelope"] = envelope
    return resp


def _envelope_error(message: str, status: int):
    """Sign an error response so an operator can distinguish 'internal-
    admin really refused this' from 'gateway lied'. Subject and scope
    are blank because we may not have parsed a valid token yet.
    """
    payload = {"error": message}
    body_bytes = _canonical_body(payload)
    envelope = _build_envelope(
        body_bytes=body_bytes,
        status=status,
        endpoint=request.path,
        subject="",
        scope="",
        actor_jti="",
        request_nonce=_request_nonce(),
    )
    resp = Response(body_bytes, status=status, mimetype="application/json")
    resp.headers["X-Response-Envelope"] = envelope
    return resp


def _envelope_metadata(payload):
    """Pull (subject, scope, actor_jti) out of the verified token payload
    for inclusion in the response envelope. The act_jti claim is a token-
    service addition that lets us tie the envelope to the operator's
    original actor assertion.
    """
    return (
        payload.get("sub", ""),
        payload.get("scope", ""),
        payload.get("act_jti", ""),
    )


def _audit_write_or_refuse(payload, status: int):
    """Record an audit entry for a successfully authorized request.
    Returns None on success, or a fail-closed envelope error response on
    Redis failure. The caller MUST return that response to the caller if
    it is non-None, otherwise the operation would succeed without being
    audited and the operator's reconcile check would raise a false
    suppression alarm.
    """
    subject = payload.get("sub", "")
    actor_jti = payload.get("act_jti", "") or ""
    entry = {
        "iat": int(time.time()),
        "endpoint": request.path,
        "scope": payload.get("scope", ""),
        "subject": subject,
        "actor_jti": actor_jti,
        "token_jti": payload.get("jti", ""),
        "status": status,
        "replica": REPLICA_NAME,
    }
    try:
        _record_audit(subject, entry)
    except ReplayBackendUnavailable:
        return _envelope_error("audit store unavailable", 503)
    return None


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
    fail = _audit_write_or_refuse(payload, 200)
    if fail is not None:
        return fail
    subject, scope, actor_jti = _envelope_metadata(payload)
    body = {
        "service": REPLICA_NAME,
        "app_env": os.getenv("APP_ENV", "dev"),
        "token_audience": TOKEN_AUDIENCE,
        "replica": REPLICA_NAME,
        "caller": payload.get("sub"),
        "actor": (payload.get("act") or {}).get("sub"),
    }
    return _envelope_response(
        body, 200, subject=subject, scope=scope, actor_jti=actor_jti
    )


@app.get("/internal/metrics")
def metrics():
    payload, err = require_scope("internal.metrics.read")
    if err:
        return err
    fail = _audit_write_or_refuse(payload, 200)
    if fail is not None:
        return fail
    subject, scope, actor_jti = _envelope_metadata(payload)
    body = {
        "service": REPLICA_NAME,
        "caller": payload.get("sub"),
        "actor": (payload.get("act") or {}).get("sub"),
        "status": "ok",
        "queue_depth": 2,
    }
    return _envelope_response(
        body, 200, subject=subject, scope=scope, actor_jti=actor_jti
    )


@app.get("/admin/export")
def export():
    payload, err = require_scope("admin.export.read")
    if err:
        return err
    fail = _audit_write_or_refuse(payload, 200)
    if fail is not None:
        return fail
    subject, scope, actor_jti = _envelope_metadata(payload)
    body = {
        "service": REPLICA_NAME,
        "caller": payload.get("sub"),
        "actor": (payload.get("act") or {}).get("sub"),
        "records": 2,
        "users": [
            {"id": 1, "email": "alice@example.internal"},
            {"id": 2, "email": "bob@example.internal"},
        ],
    }
    return _envelope_response(
        body, 200, subject=subject, scope=scope, actor_jti=actor_jti
    )


@app.get("/internal/audit")
def audit_self():
    """Return the caller's own recent audit entries. The operator cross-
    checks the returned list against their local ledger to detect
    gateway-side suppression. The response itself is envelope-signed like
    every other scoped endpoint, so a relay cannot forge or prune it
    without detection.

    Accepts an optional ?since=<iat> parameter bounded to a reasonable
    window. Absent or malformed ?since=... falls back to the default
    window. A caller can only ever see their OWN log - the subject of
    the log query is pinned to the token subject, never from a URL
    parameter.
    """
    payload, err = require_scope("audit.self.read")
    if err:
        return err
    # This endpoint writes its own audit entry so reconcile() can see that
    # the audit query itself happened. Audit-of-audit prevents the gateway
    # from dropping audit queries without a corresponding gap appearing in
    # a subsequent audit.
    fail = _audit_write_or_refuse(payload, 200)
    if fail is not None:
        return fail

    now = int(time.time())
    try:
        since_raw = int(request.args.get("since", ""))
    except (TypeError, ValueError):
        since_raw = now - AUDIT_QUERY_DEFAULT_WINDOW
    # Clamp: never look further back than retention allows, never look
    # into the future.
    since = max(since_raw, now - AUDIT_RETENTION_SECONDS)
    since = min(since, now)

    subject = payload.get("sub", "")
    try:
        entries = _fetch_audit(subject, since)
    except ReplayBackendUnavailable:
        return _envelope_error("audit store unavailable", 503)

    subject_m, scope_m, actor_jti = _envelope_metadata(payload)
    body = {
        "service": REPLICA_NAME,
        "caller": subject,
        "since": since,
        "now": now,
        "count": len(entries),
        "entries": entries,
    }
    return _envelope_response(
        body, 200, subject=subject_m, scope=scope_m, actor_jti=actor_jti
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
