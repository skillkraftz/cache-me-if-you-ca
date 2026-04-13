"""Adversarial tests targeting the trust-model refactor.

These tests replace the previous shared-secret tests. They validate:
  - Ed25519 token issuance and verification
  - Client assertions replacing client secrets
  - Operator actor assertions replacing the admin API key
  - Delegated minting with act claim propagation
  - Defense-in-depth at the consumer (internal-admin)
  - Compromised-gateway blast-radius reduction
  - Replay and forgery resistance end to end
"""

import json
import time
import uuid

import pytest
import redis as redislib
import requests

from trust_helpers import (
    b64d,
    b64e,
    decode_token_payload,
    gateway_assertion,
    observer_assertion,
    alice_assertion,
    bob_assertion,
    rogue_assertion_as,
    make_client_assertion,
    make_actor_assertion,
    sign_compact,
    GATEWAY_CLIENT_KEY,
    OBSERVER_CLIENT_KEY,
    OPS_ALICE_KEY,
    OPS_BOB_KEY,
    ROGUE_KEY,
)


GATEWAY = "http://gateway:5000"
TOKEN_SERVICE = "http://token-service:5003"
INTERNAL_A = "http://internal-admin-a:5001"
INTERNAL_B = "http://internal-admin-b:5001"
AUD_INTERNAL = "internal-admin"


def _redis_client():
    return redislib.Redis.from_url("redis://redis:6379/0", decode_responses=True)


def _clear_rate_limit(client_id: str):
    """Wipe any per-minute rate-limit counters for a client. Test-only
    helper; production code never mutates Redis from outside the service.
    """
    r = _redis_client()
    keys = list(r.scan_iter(match=f"rate:{client_id}:*"))
    if keys:
        r.delete(*keys)


@pytest.fixture(autouse=True)
def _isolate_observer_rate_limit():
    """Before every test, clear the observer rate-limit window so the
    order of tests does not accidentally starve a later test. The
    dedicated rate-limit test explicitly re-checks enforcement within its
    own body, so clearing before each test is safe.
    """
    _clear_rate_limit("observer")
    _clear_rate_limit("gateway")
    yield


# -----------------------------------------------------------------------------
# Direct token-service flows (bypassing the gateway to test the issuer itself)
# -----------------------------------------------------------------------------


def _mint(body: dict):
    return requests.post(f"{TOKEN_SERVICE}/v1/mint", json=body, timeout=5)


def test_jwks_endpoint_exposes_signing_pubkey():
    r = requests.get(f"{TOKEN_SERVICE}/.well-known/jwks", timeout=5)
    assert r.status_code == 200
    keys = r.json()["keys"]
    assert len(keys) >= 1
    k = keys[0]
    assert k["alg"] == "EdDSA"
    assert k["crv"] == "Ed25519"
    assert k["kid"]
    assert k["x"]
    assert "d" not in k and "private" not in k


def test_mint_requires_client_assertion():
    r = _mint({"audience": AUD_INTERNAL, "scope": "admin.export.read"})
    assert r.status_code == 403
    assert "client_assertion" in r.text


def test_mint_rejects_forged_gateway_assertion():
    # Rogue key signs something that *claims* to be the gateway. There is
    # no key in the token-service's client registry matching the rogue kid
    # so verification must fail at kid lookup.
    ca = rogue_assertion_as("gateway")
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
        }
    )
    assert r.status_code == 403


def test_mint_rejects_client_assertion_with_lying_iss():
    # Gateway's real signing key but iss/sub claim to be observer. The
    # verifier derives which client the assertion is for from the kid,
    # and then requires iss == sub == that client.
    ca = make_client_assertion(
        "gateway",
        GATEWAY_CLIENT_KEY,
        "gateway-client-v1",
        iss_override="observer",
        sub_override="observer",
    )
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
        }
    )
    assert r.status_code == 403


def test_mint_rejects_client_assertion_with_sub_ne_iss():
    ca = make_client_assertion(
        "gateway",
        GATEWAY_CLIENT_KEY,
        "gateway-client-v1",
        sub_override="ops-alice",
    )
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
        }
    )
    assert r.status_code == 403


def test_mint_rejects_wrong_aud_on_assertion():
    ca = gateway_assertion(aud="internal-admin")
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
        }
    )
    assert r.status_code == 403


def test_mint_rejects_expired_client_assertion():
    ca = gateway_assertion(iat_offset=-120, lifetime=30)
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
        }
    )
    assert r.status_code == 403


def test_mint_rejects_oversize_client_assertion_lifetime():
    ca = gateway_assertion(lifetime=86400)
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
        }
    )
    assert r.status_code == 403


def test_client_assertion_replay_blocked():
    ca = gateway_assertion()
    aa = alice_assertion("admin.export.read")
    r1 = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": aa,
        }
    )
    assert r1.status_code == 200, r1.text
    # Same client_assertion, fresh actor - the client jti must still be
    # burned, so this second call must fail even though the actor is new.
    aa2 = alice_assertion("admin.export.read")
    r2 = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": aa2,
        }
    )
    assert r2.status_code == 403
    assert "replay" in r2.text.lower()


def test_actor_assertion_replay_blocked():
    aa = alice_assertion("admin.export.read")
    ca1 = gateway_assertion()
    ca2 = gateway_assertion()  # different jti
    r1 = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca1,
            "actor_assertion": aa,
        }
    )
    assert r1.status_code == 200, r1.text
    r2 = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca2,
            "actor_assertion": aa,  # reused
        }
    )
    assert r2.status_code == 403
    assert "replay" in r2.text.lower()


def test_gateway_cannot_self_mint_admin_scope():
    # Gateway presents valid client_assertion but no actor_assertion.
    # Gateway's self-mint scopes are empty, so any scope request fails.
    ca = gateway_assertion()
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
        }
    )
    assert r.status_code == 403
    assert "scope" in r.text.lower()


def test_gateway_cannot_self_mint_any_scope():
    for scope in ("internal.metrics.read", "debug.config.read", "token.discovery"):
        ca = gateway_assertion()
        r = _mint(
            {
                "audience": AUD_INTERNAL,
                "scope": scope,
                "client_assertion": ca,
            }
        )
        assert r.status_code == 403, (scope, r.text)


def test_observer_can_self_mint_within_its_scopes():
    ca = observer_assertion()
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "internal.metrics.read",
            "client_assertion": ca,
        }
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["subject"] == "observer"
    claims = decode_token_payload(data["access_token"])
    assert claims["sub"] == "observer"
    assert "act" not in claims  # not delegated


def test_observer_cannot_mint_admin_scope_even_self():
    ca = observer_assertion()
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
        }
    )
    assert r.status_code == 403


def test_observer_cannot_relay_actor_assertions():
    ca = observer_assertion()
    aa = alice_assertion("admin.export.read")
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": aa,
        }
    )
    assert r.status_code == 403
    assert "relay" in r.text.lower() or "cannot relay" in r.text.lower()


def test_gateway_delegated_mint_with_alice_admin_scope():
    ca = gateway_assertion()
    aa = alice_assertion("admin.export.read")
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": aa,
        }
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["subject"] == "ops-alice"
    claims = decode_token_payload(data["access_token"])
    assert claims["sub"] == "ops-alice"
    assert claims["act"] == {"sub": "gateway"}
    assert claims["scope"] == "admin.export.read"


def test_gateway_delegated_mint_with_bob_admin_scope():
    ca = gateway_assertion()
    aa = bob_assertion("admin.export.read")
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": aa,
        }
    )
    assert r.status_code == 200, r.text
    assert r.json()["subject"] == "ops-bob"


def test_bob_cannot_delegate_metrics_scope_he_does_not_have():
    ca = gateway_assertion()
    aa = bob_assertion("internal.metrics.read")
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "internal.metrics.read",
            "client_assertion": ca,
            "actor_assertion": aa,
        }
    )
    assert r.status_code == 403
    assert "scope" in r.text.lower()


def test_actor_assertion_scope_pin_must_match_requested_scope():
    # Alice signs an assertion for metrics, gateway requests admin export.
    # Pinned scope mismatch must fail even though alice holds both scopes.
    ca = gateway_assertion()
    aa = alice_assertion("internal.metrics.read")
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": aa,
        }
    )
    assert r.status_code == 403
    assert "scope" in r.text.lower()


def test_forged_actor_assertion_rejected():
    ca = gateway_assertion()
    aa = rogue_assertion_as("ops-alice", scope="admin.export.read")
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": aa,
        }
    )
    assert r.status_code == 403


def test_actor_assertion_lifetime_cap_enforced():
    ca = gateway_assertion()
    aa = alice_assertion("admin.export.read", lifetime=86400)
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": aa,
        }
    )
    assert r.status_code == 403


def test_rate_limit_on_mint_per_client():
    # Each call uses a fresh client_assertion (unique jti).
    burst = 60
    caps = 0
    for _ in range(burst + 5):
        ca = observer_assertion()
        r = _mint(
            {
                "audience": AUD_INTERNAL,
                "scope": "internal.metrics.read",
                "client_assertion": ca,
            }
        )
        if r.status_code == 429:
            caps += 1
            break
        assert r.status_code == 200
    assert caps == 1, "rate limit should eventually reject a burst from one client"


# -----------------------------------------------------------------------------
# Consumer (internal-admin) defense-in-depth
# -----------------------------------------------------------------------------


def _issue_admin_token_via_mint(actor_priv=None, actor_kid=None, operator_id=None):
    ca = gateway_assertion()
    if actor_priv is None:
        aa = alice_assertion("admin.export.read")
    else:
        aa = make_actor_assertion(
            operator_id, actor_priv, actor_kid, "admin.export.read"
        )
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": aa,
        }
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_admin_accepts_properly_delegated_token():
    token = _issue_admin_token_via_mint()
    r = requests.get(
        f"{INTERNAL_A}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["caller"] == "ops-alice"
    assert data["actor"] == "gateway"


def test_cross_replica_replay_blocked_with_real_token():
    token = _issue_admin_token_via_mint()
    h = {"Authorization": f"Bearer {token}"}
    a = requests.get(f"{INTERNAL_A}/admin/export", headers=h, timeout=5)
    b = requests.get(f"{INTERNAL_B}/admin/export", headers=h, timeout=5)
    assert (a.status_code == 200) ^ (b.status_code == 200)
    loser = a if b.status_code == 200 else b
    assert loser.status_code == 403
    assert "replay" in loser.text.lower()


def test_same_replica_replay_blocked():
    token = _issue_admin_token_via_mint()
    h = {"Authorization": f"Bearer {token}"}
    first = requests.get(f"{INTERNAL_A}/admin/export", headers=h, timeout=5)
    second = requests.get(f"{INTERNAL_A}/admin/export", headers=h, timeout=5)
    assert first.status_code == 200
    assert second.status_code == 403


def test_admin_rejects_token_signed_by_rogue_key():
    # An attacker who somehow obtained a way to sign EdDSA tokens but with
    # a different private key than the issuer must be rejected. This
    # covers "what if token-service's secret leaked" in the old HMAC model
    # -- in the asymmetric model, only token-service's private key can
    # sign valid tokens, and the consumer's public key set is closed.
    now = int(time.time())
    header = {"alg": "EdDSA", "typ": "JWT", "kid": "ts-v1"}  # legit kid
    payload = {
        "iss": "token-service",
        "sub": "ops-alice",
        "aud": AUD_INTERNAL,
        "scope": "admin.export.read",
        "iat": now,
        "nbf": now,
        "exp": now + 30,
        "jti": str(uuid.uuid4()),
        "act": {"sub": "gateway"},
    }
    forged = sign_compact(ROGUE_KEY, header, payload)
    r = requests.get(
        f"{INTERNAL_A}/admin/export",
        headers={"Authorization": f"Bearer {forged}"},
        timeout=5,
    )
    assert r.status_code == 403
    assert "signature" in r.text.lower()


def test_admin_rejects_token_with_unknown_kid():
    # Legit issuer, different kid (simulating a key rotation where only
    # the old kid is pinned on the consumer).
    import os
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    # Load the real issuer seed from the lab so the signature would be
    # cryptographically valid, but advertise an unknown kid. The consumer
    # trusts keys by kid, so this must be rejected.
    issuer_seed = "dG9rZW4tc2lnbmluZzAwMDAwMDAwMDAwMDAwMDAwMDA"
    priv = Ed25519PrivateKey.from_private_bytes(b64d(issuer_seed))
    now = int(time.time())
    header = {"alg": "EdDSA", "typ": "JWT", "kid": "unknown-kid"}
    payload = {
        "iss": "token-service",
        "sub": "ops-alice",
        "aud": AUD_INTERNAL,
        "scope": "admin.export.read",
        "iat": now,
        "nbf": now,
        "exp": now + 30,
        "jti": str(uuid.uuid4()),
    }
    token = sign_compact(priv, header, payload)
    r = requests.get(
        f"{INTERNAL_A}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code == 403
    assert "kid" in r.text.lower()


def test_admin_rejects_token_with_bad_actor_sub():
    # Valid token signature (via the normal mint path), but the actor
    # claim points at a client that is not in ALLOWED_ACTORS. We can't
    # actually produce such a token through the legit mint (the mint
    # always sets act.sub to the relaying client), so we craft it using
    # the real signing key via the lab's known seed.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    issuer_seed = "dG9rZW4tc2lnbmluZzAwMDAwMDAwMDAwMDAwMDAwMDA"
    priv = Ed25519PrivateKey.from_private_bytes(b64d(issuer_seed))
    now = int(time.time())
    header = {"alg": "EdDSA", "typ": "JWT", "kid": "ts-v1"}
    payload = {
        "iss": "token-service",
        "sub": "ops-alice",
        "aud": AUD_INTERNAL,
        "scope": "admin.export.read",
        "iat": now,
        "nbf": now,
        "exp": now + 30,
        "jti": str(uuid.uuid4()),
        "act": {"sub": "observer"},  # not an allowed actor
    }
    token = sign_compact(priv, header, payload)
    r = requests.get(
        f"{INTERNAL_A}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code == 403
    assert "actor" in r.text.lower()


def test_admin_rejects_alg_none_or_hmac():
    # RFC 8725 'alg' confusion - an attacker tries to downgrade from
    # EdDSA to HMAC-SHA256 or none. We never accept anything but EdDSA.
    header = {"alg": "none", "typ": "JWT", "kid": "ts-v1"}
    payload = {
        "iss": "token-service",
        "sub": "ops-alice",
        "aud": AUD_INTERNAL,
        "scope": "admin.export.read",
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "exp": int(time.time()) + 30,
        "jti": str(uuid.uuid4()),
    }
    h_b64 = b64e(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p_b64 = b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    token = f"{h_b64}.{p_b64}."  # empty signature
    r = requests.get(
        f"{INTERNAL_A}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code == 403


def test_admin_rejects_debug_config_without_token():
    r = requests.get(f"{INTERNAL_A}/debug/config", timeout=5)
    assert r.status_code == 403


def test_admin_debug_config_accessible_via_observer_self_mint():
    ca = observer_assertion()
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "debug.config.read",
            "client_assertion": ca,
        }
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    dr = requests.get(
        f"{INTERNAL_A}/debug/config",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert dr.status_code == 200
    assert dr.json()["caller"] == "observer"


# -----------------------------------------------------------------------------
# Gateway /ops/* end-to-end
# -----------------------------------------------------------------------------


def test_ops_export_requires_actor_assertion():
    r = requests.get(f"{GATEWAY}/ops/export", params={"target": "a"}, timeout=5)
    assert r.status_code == 401


def test_ops_export_rejects_malformed_assertion():
    r = requests.get(
        f"{GATEWAY}/ops/export",
        params={"target": "a"},
        headers={"X-Actor-Assertion": "not.a.jwt.no.really"},
        timeout=5,
    )
    assert r.status_code in (400, 403)


def test_ops_export_rejects_rogue_actor_assertion():
    aa = rogue_assertion_as("ops-alice", scope="admin.export.read")
    r = requests.get(
        f"{GATEWAY}/ops/export",
        params={"target": "a"},
        headers={"X-Actor-Assertion": aa},
        timeout=5,
    )
    assert r.status_code == 403


def test_ops_export_rejects_observer_as_actor():
    # Observer has a valid client assertion key but it is not an operator.
    # We reuse the client assertion function by claiming operator_id the
    # token-service doesn't know about via observer's key.
    import uuid as _uuid

    now = int(time.time())
    header = {"alg": "EdDSA", "typ": "JWT", "kid": "observer-client-v1"}
    payload = {
        "iss": "observer",
        "sub": "observer",
        "aud": "token-service",
        "scope": "admin.export.read",
        "iat": now,
        "nbf": now,
        "exp": now + 30,
        "jti": str(_uuid.uuid4()),
    }
    aa = sign_compact(OBSERVER_CLIENT_KEY, header, payload)
    r = requests.get(
        f"{GATEWAY}/ops/export",
        params={"target": "a"},
        headers={"X-Actor-Assertion": aa},
        timeout=5,
    )
    assert r.status_code == 403


def test_ops_export_succeeds_with_alice_assertion():
    aa = alice_assertion("admin.export.read")
    r = requests.get(
        f"{GATEWAY}/ops/export",
        params={"target": "a"},
        headers={"X-Actor-Assertion": aa},
        timeout=5,
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["service"] == "internal-admin-a"
    assert data["caller"] == "ops-alice"
    assert data["actor"] == "gateway"


def test_ops_export_each_replica_needs_fresh_assertion():
    # Single actor assertion is single-use. You cannot drive both replicas
    # with it.
    aa = alice_assertion("admin.export.read")
    r1 = requests.get(
        f"{GATEWAY}/ops/export",
        params={"target": "a"},
        headers={"X-Actor-Assertion": aa},
        timeout=5,
    )
    assert r1.status_code == 200
    r2 = requests.get(
        f"{GATEWAY}/ops/export",
        params={"target": "b"},
        headers={"X-Actor-Assertion": aa},
        timeout=5,
    )
    assert r2.status_code == 403
    assert "replay" in r2.text.lower()


def test_ops_export_with_two_separate_assertions_reaches_both_replicas():
    aa_a = alice_assertion("admin.export.read")
    aa_b = alice_assertion("admin.export.read")
    a = requests.get(
        f"{GATEWAY}/ops/export",
        params={"target": "a"},
        headers={"X-Actor-Assertion": aa_a},
        timeout=5,
    )
    b = requests.get(
        f"{GATEWAY}/ops/export",
        params={"target": "b"},
        headers={"X-Actor-Assertion": aa_b},
        timeout=5,
    )
    assert a.status_code == 200, a.text
    assert b.status_code == 200, b.text
    assert a.json()["service"] == "internal-admin-a"
    assert b.json()["service"] == "internal-admin-b"


def test_ops_use_token_requires_actor_assertion():
    r = requests.get(
        f"{GATEWAY}/ops/use-token",
        params={"target": "a", "token": "x.y.z"},
        timeout=5,
    )
    assert r.status_code == 401


def test_ops_raw_token_still_retired():
    r = requests.get(f"{GATEWAY}/ops/raw-token", timeout=5)
    assert r.status_code in (403, 404, 410)


# -----------------------------------------------------------------------------
# Compromised-gateway threat model
# -----------------------------------------------------------------------------


def test_compromised_gateway_cannot_mint_admin_without_operator():
    # The attacker holds the gateway client private key (imported into the
    # test via conftest). Simulate them calling token-service directly.
    ca = gateway_assertion()
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
        }
    )
    assert r.status_code == 403


def test_compromised_gateway_cannot_replay_captured_operator_assertion():
    # Simulate the gateway capturing an in-flight actor assertion.
    aa = alice_assertion("admin.export.read")
    # First use is legit.
    ca1 = gateway_assertion()
    r1 = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca1,
            "actor_assertion": aa,
        }
    )
    assert r1.status_code == 200
    # Attacker tries to reuse the same actor assertion.
    ca2 = gateway_assertion()
    r2 = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca2,
            "actor_assertion": aa,
        }
    )
    assert r2.status_code == 403


def test_compromised_gateway_cannot_forge_operator_assertion():
    # The attacker only has the gateway client key. Trying to sign an
    # operator assertion with the gateway key is a signature mismatch
    # against the operator's registered public key.
    ca = gateway_assertion()
    header = {"alg": "EdDSA", "typ": "JWT", "kid": "ops-alice-v1"}
    now = int(time.time())
    payload = {
        "iss": "ops-alice",
        "sub": "ops-alice",
        "aud": "token-service",
        "scope": "admin.export.read",
        "iat": now,
        "nbf": now,
        "exp": now + 30,
        "jti": str(uuid.uuid4()),
    }
    forged = sign_compact(GATEWAY_CLIENT_KEY, header, payload)
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": forged,
        }
    )
    assert r.status_code == 403
    assert "signature" in r.text.lower()


def test_compromised_gateway_self_mint_observer_scope_is_rejected():
    # Even if the compromised gateway tries to mint a scope that observer
    # holds, it cannot because it is authenticating as gateway, not
    # observer. Cross-client escalation via kid mix-up is impossible
    # because the verifier pins iss to the kid-owning client.
    ca = gateway_assertion()
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "internal.metrics.read",
            "client_assertion": ca,
        }
    )
    assert r.status_code == 403


def test_compromised_gateway_cannot_reuse_own_client_assertion():
    ca = gateway_assertion()
    aa1 = alice_assertion("admin.export.read")
    aa2 = alice_assertion("admin.export.read")
    r1 = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": aa1,
        }
    )
    assert r1.status_code == 200
    r2 = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,  # replay
            "actor_assertion": aa2,
        }
    )
    assert r2.status_code == 403
