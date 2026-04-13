"""Shared test utilities for the trust-model tests.

These helpers hold the private key material the tests need to act as:
  - the gateway client (to directly mint tokens at the token-service)
  - various operators (to produce actor assertions)
  - a rogue issuer (to craft forged tokens and prove they are rejected)

Everything here is deterministic and lab-only. Seeds map 1:1 to the public
keys wired into docker-compose.yml.
"""

import base64
import json
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


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

GATEWAY_CLIENT_KEY = load_private_from_seed(GATEWAY_CLIENT_SEED_B64)
OBSERVER_CLIENT_KEY = load_private_from_seed(OBSERVER_CLIENT_SEED_B64)
OPS_ALICE_KEY = load_private_from_seed(OPS_ALICE_SEED_B64)
OPS_BOB_KEY = load_private_from_seed(OPS_BOB_SEED_B64)
ROGUE_KEY = load_private_from_seed(ROGUE_SEED_B64)


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
) -> str:
    now = int(time.time()) + iat_offset
    header = {"alg": "EdDSA", "typ": "JWT", "kid": kid}
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
    scope: str,
    *,
    aud: str = "token-service",
    lifetime: int = 30,
    jti: str | None = None,
    iat_offset: int = 0,
    extra_claims: dict | None = None,
) -> str:
    now = int(time.time()) + iat_offset
    header = {"alg": "EdDSA", "typ": "JWT", "kid": kid}
    payload = {
        "iss": operator_id,
        "sub": operator_id,
        "aud": aud,
        "scope": scope,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
        "jti": jti or str(uuid.uuid4()),
    }
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


def rogue_assertion_as(iss: str, scope: str | None = None, **kw) -> str:
    """Assertion signed by an unknown-to-us key but claiming to come from a
    real issuer. These must always be rejected at verification time.
    """
    now = int(time.time())
    header = {"alg": "EdDSA", "typ": "JWT", "kid": "rogue-v1"}
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


def decode_token_payload(token: str) -> dict:
    _h, p, _s = token.split(".", 2)
    return json.loads(b64d(p).decode())
