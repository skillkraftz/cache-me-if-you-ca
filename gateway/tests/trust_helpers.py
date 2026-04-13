"""Shared test utilities for the trust-model tests.

These helpers hold the private key material the tests need to act as:
  - the gateway client (to directly mint tokens at the token-service)
  - various operators (to produce actor assertions)
  - a rogue issuer (to craft forged tokens and prove they are rejected)

Everything here is deterministic and lab-only. Seeds map 1:1 to the public
keys wired into docker-compose.yml.
"""

import base64
import hashlib
import json
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# JOSE typ values used everywhere in the trust model. These are the
# single source of truth for tests; any assertion created via the helpers
# below automatically uses the right one, and the "attack" helpers
# deliberately use the wrong ones to prove confusion is rejected.
TYP_ACCESS_TOKEN = "at+jwt"
TYP_CLIENT_AUTH = "client-auth+jwt"
TYP_ACTOR_AUTH = "actor-auth+jwt"
TYP_RESPONSE_ENVELOPE = "ar+jwt"


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def load_private_from_seed(seed_b64: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(b64d(seed_b64))


def sign_compact(priv: Ed25519PrivateKey, header: dict, payload: dict) -> str:
    h_b64 = b64e(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p_b64 = b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = priv.sign(signing_input)
    return f"{h_b64}.{p_b64}.{b64e(sig)}"


# Seeds mirror the lab values in docker-compose.yml. In production these
# would live in an HSM / KMS and would never be visible to test code.
GATEWAY_CLIENT_SEED_B64 = "Z2F0ZXdheS1jbGllbnQwMDAwMDAwMDAwMDAwMDAwMDA"
OBSERVER_CLIENT_SEED_B64 = "b2JzZXJ2ZXItY2xpZW50MDAwMDAwMDAwMDAwMDAwMDA"
OPS_ALICE_SEED_B64 = "b3BzLWFsaWNlMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA"
OPS_BOB_SEED_B64 = "b3BzLWJvYjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA"

# Rogue seed that the token-service does NOT know about. Anything signed
# with this key must be rejected everywhere.
ROGUE_SEED_B64 = "cm9ndWUtYXR0YWNrZXItMDAwMDAwMDAwMDAwMDAwMDA"

# Legit issuer seed, mirrored from docker-compose. Tests use this to
# forge tokens that *would* pass signature verification so we can prove
# the consumer-side policy (allowlist, typ, sub-scope) catches them.
TOKEN_ISSUER_SEED_B64 = "dG9rZW4tc2lnbmluZzAwMDAwMDAwMDAwMDAwMDAwMDA"

GATEWAY_CLIENT_KEY = load_private_from_seed(GATEWAY_CLIENT_SEED_B64)
OBSERVER_CLIENT_KEY = load_private_from_seed(OBSERVER_CLIENT_SEED_B64)
OPS_ALICE_KEY = load_private_from_seed(OPS_ALICE_SEED_B64)
OPS_BOB_KEY = load_private_from_seed(OPS_BOB_SEED_B64)
ROGUE_KEY = load_private_from_seed(ROGUE_SEED_B64)
TOKEN_ISSUER_KEY = load_private_from_seed(TOKEN_ISSUER_SEED_B64)


def make_client_assertion(
    client_id: str,
    priv: Ed25519PrivateKey,
    kid: str,
    *,
    aud: str = "token-service",
    lifetime: int = 30,
    jti: str | None = None,
    iat_offset: int = 0,
    sub_override: str | None = None,
    iss_override: str | None = None,
    typ_override: str | None = None,
) -> str:
    now = int(time.time()) + iat_offset
    header = {
        "alg": "EdDSA",
        "typ": typ_override or TYP_CLIENT_AUTH,
        "kid": kid,
    }
    payload = {
        "iss": iss_override or client_id,
        "sub": sub_override or client_id,
        "aud": aud,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
        "jti": jti or str(uuid.uuid4()),
    }
    return sign_compact(priv, header, payload)


def make_actor_assertion(
    operator_id: str,
    priv: Ed25519PrivateKey,
    kid: str,
    scope: str | None,
    *,
    aud: str = "token-service",
    lifetime: int = 30,
    jti: str | None = None,
    iat_offset: int = 0,
    extra_claims: dict | None = None,
    typ_override: str | None = None,
    omit_scope: bool = False,
) -> str:
    now = int(time.time()) + iat_offset
    header = {
        "alg": "EdDSA",
        "typ": typ_override or TYP_ACTOR_AUTH,
        "kid": kid,
    }
    payload = {
        "iss": operator_id,
        "sub": operator_id,
        "aud": aud,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
        "jti": jti or str(uuid.uuid4()),
    }
    if not omit_scope:
        payload["scope"] = scope
    if extra_claims:
        payload.update(extra_claims)
    return sign_compact(priv, header, payload)


def gateway_assertion(**kw) -> str:
    return make_client_assertion(
        "gateway", GATEWAY_CLIENT_KEY, "gateway-client-v1", **kw
    )


def observer_assertion(**kw) -> str:
    return make_client_assertion(
        "observer", OBSERVER_CLIENT_KEY, "observer-client-v1", **kw
    )


def alice_assertion(scope: str, **kw) -> str:
    return make_actor_assertion("ops-alice", OPS_ALICE_KEY, "ops-alice-v1", scope, **kw)


def bob_assertion(scope: str, **kw) -> str:
    return make_actor_assertion("ops-bob", OPS_BOB_KEY, "ops-bob-v1", scope, **kw)


def rogue_assertion_as(
    iss: str, scope: str | None = None, typ: str | None = None, **kw
) -> str:
    """Assertion signed by an unknown-to-us key but claiming to come from a
    real issuer. These must always be rejected at verification time.
    """
    now = int(time.time())
    header = {"alg": "EdDSA", "typ": typ or TYP_ACTOR_AUTH, "kid": "rogue-v1"}
    payload = {
        "iss": iss,
        "sub": iss,
        "aud": "token-service",
        "iat": now,
        "nbf": now,
        "exp": now + 30,
        "jti": str(uuid.uuid4()),
    }
    if scope is not None:
        payload["scope"] = scope
    return sign_compact(ROGUE_KEY, header, payload)


def forge_issuer_token(
    *,
    sub: str,
    scope: str,
    aud: str = "internal-admin",
    kid: str = "ts-v1",
    typ: str = TYP_ACCESS_TOKEN,
    act: dict | None = None,
    lifetime: int = 30,
    jti: str | None = None,
) -> str:
    """Sign an access token with the REAL issuer seed. Used to prove that
    the consumer-side policy catches token shapes the issuer should never
    produce - compromised-issuer simulation.
    """
    now = int(time.time())
    header = {"alg": "EdDSA", "typ": typ, "kid": kid}
    payload = {
        "iss": "token-service",
        "sub": sub,
        "aud": aud,
        "scope": scope,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
        "jti": jti or str(uuid.uuid4()),
    }
    if act is not None:
        payload["act"] = act
    return sign_compact(TOKEN_ISSUER_KEY, header, payload)


def decode_token_payload(token: str) -> dict:
    _h, p, _s = token.split(".", 2)
    return json.loads(b64d(p).decode())


# -----------------------------------------------------------------------------
# Response envelope verification (operator-side)
# -----------------------------------------------------------------------------


# Operator-side pinned public keys for response signing. These are the
# *PUBLIC* halves of the per-replica response signing keys held in
# docker-compose.yml. The operator never holds the private halves; only
# the replicas do.
RESPONSE_VERIFY_KEYS = {
    "ia-a-v1": Ed25519PublicKey.from_public_bytes(
        b64d("1J4Sact6I6dwrXK7OBx36kwhIUfyKZg8aq4vvm8aA0c")
    ),
    "ia-b-v1": Ed25519PublicKey.from_public_bytes(
        b64d("IPNc7YQOXQCpP9qnxMfHoPiW2DcwWeDbt5SP2nLvu14")
    ),
}

# Map from kid to the replica name we expect to see in iss. This
# enforces that the kid and iss are not independently mutable -- a
# malicious gateway cannot claim "this came from replica B" while
# signing with replica A's key, because the operator pins both.
RESPONSE_KID_TO_REPLICA = {
    "ia-a-v1": "internal-admin-a",
    "ia-b-v1": "internal-admin-b",
}


class EnvelopeVerifyError(Exception):
    pass


def verify_response_envelope(
    *,
    envelope_jwt: str,
    body_bytes: bytes,
    expected_request_nonce: str,
    expected_actor_jti: str | None,
    expected_subject: str | None,
    expected_scope: str | None,
    expected_endpoint: str,
    expected_status: int,
    expected_replica: str | None = None,
    max_age_sec: int = 60,
):
    """Verify a backend-signed response envelope against the response
    body the operator received. This is the operator-side defense
    against a malicious relay (gateway). Any failure raises
    EnvelopeVerifyError with a specific reason -- the operator MUST
    treat such failures as untrusted responses.

    Returns the verified claims dict on success.
    """
    if not envelope_jwt or envelope_jwt.count(".") != 2:
        raise EnvelopeVerifyError("missing or malformed envelope")
    h_b64, p_b64, s_b64 = envelope_jwt.split(".", 2)
    signing_input = f"{h_b64}.{p_b64}".encode()
    try:
        header = json.loads(b64d(h_b64).decode())
        claims = json.loads(b64d(p_b64).decode())
        sig = b64d(s_b64)
    except Exception:
        raise EnvelopeVerifyError("envelope encoding")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise EnvelopeVerifyError("envelope structure")
    if header.get("alg") != "EdDSA":
        raise EnvelopeVerifyError("envelope alg")
    if header.get("typ") != TYP_RESPONSE_ENVELOPE:
        raise EnvelopeVerifyError("envelope typ")
    kid = header.get("kid")
    pub = RESPONSE_VERIFY_KEYS.get(kid)
    if pub is None:
        raise EnvelopeVerifyError("unknown response kid")
    try:
        pub.verify(sig, signing_input)
    except InvalidSignature:
        raise EnvelopeVerifyError("envelope signature")

    # Pin iss to whatever the kid says. A signature from kid=ia-a-v1
    # MUST claim iss=internal-admin-a. This blocks "swap kid headers
    # between replicas" attacks before any other claim check.
    expected_iss_from_kid = RESPONSE_KID_TO_REPLICA.get(kid)
    if claims.get("iss") != expected_iss_from_kid:
        raise EnvelopeVerifyError("iss/kid mismatch")
    if expected_replica is not None and claims.get("iss") != expected_replica:
        raise EnvelopeVerifyError("replica mismatch")

    # Time bounds.
    now = int(time.time())
    iat = claims.get("iat")
    exp = claims.get("exp")
    if not isinstance(iat, int) or not isinstance(exp, int):
        raise EnvelopeVerifyError("envelope time claims")
    if iat > now + 5:
        raise EnvelopeVerifyError("envelope from the future")
    if exp <= now - 5:
        raise EnvelopeVerifyError("envelope expired")
    if iat < now - max_age_sec:
        raise EnvelopeVerifyError("envelope stale")

    # Endpoint and status.
    if claims.get("endpoint") != expected_endpoint:
        raise EnvelopeVerifyError("endpoint mismatch")
    if claims.get("status") != expected_status:
        raise EnvelopeVerifyError("status mismatch")

    # Caller binding: the operator MUST pass the nonce they sent so a
    # captured envelope cannot be replayed onto a different request.
    if claims.get("request_nonce") != expected_request_nonce:
        raise EnvelopeVerifyError("nonce mismatch")

    # Actor / subject binding -- only checked for delegated calls.
    if expected_actor_jti is not None:
        if claims.get("actor_jti") != expected_actor_jti:
            raise EnvelopeVerifyError("actor_jti mismatch")
    if expected_subject is not None:
        if claims.get("subject") != expected_subject:
            raise EnvelopeVerifyError("subject mismatch")
    if expected_scope is not None:
        if claims.get("scope") != expected_scope:
            raise EnvelopeVerifyError("scope mismatch")

    # Body integrity: the operator recomputes the SHA-256 of the actual
    # bytes they received. The relay cannot mutate the body without
    # invalidating the envelope.
    expected_hash = b64e(hashlib.sha256(body_bytes).digest())
    if claims.get("body_sha256") != expected_hash:
        raise EnvelopeVerifyError("body hash mismatch")

    return claims
