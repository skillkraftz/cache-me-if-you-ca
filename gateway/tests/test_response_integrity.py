"""Response-integrity tests.

These tests target the new backend-signed response envelope. They cover:

  - Operator-side verification of legitimate responses
  - Detection of body tampering
  - Detection of envelope tampering
  - Detection of missing envelope
  - Detection of cross-request envelope substitution
  - Detection of replica spoofing (kid <-> iss binding)
  - Actor-jti binding (envelope binds to the operator's actor assertion)
  - End-to-end "rogue gateway" simulation showing the operator catches
    every realistic relay-tampering scenario
  - Operator policy: a missing envelope is treated as untrusted

The "rogue gateway" simulation models a fully compromised relay that
can do anything the legit gateway can - mint tokens via the operator's
real actor assertion, talk to internal-admin, capture real responses,
substitute its own bodies. The operator-side verification must catch
every variant.
"""

import json
import time
import uuid

import pytest
import requests

from trust_helpers import (
    EnvelopeVerifyError,
    alice_assertion,
    bob_assertion,
    decode_token_payload,
    forge_issuer_token,
    gateway_assertion,
    observer_assertion,
    sign_compact,
    verify_response_envelope,
    b64d,
    b64e,
    OPS_ALICE_KEY,
    RESPONSE_VERIFY_KEYS,
    TYP_RESPONSE_ENVELOPE,
)


GATEWAY = "http://gateway:5000"
TOKEN_SERVICE = "http://token-service:5003"
INTERNAL_A = "http://internal-admin-a:5001"
INTERNAL_B = "http://internal-admin-b:5001"
AUD_INTERNAL = "internal-admin"


def _mint(body):
    return requests.post(f"{TOKEN_SERVICE}/v1/mint", json=body, timeout=5)


def _ops_export(target: str, actor_assertion: str, request_nonce: str):
    return requests.get(
        f"{GATEWAY}/ops/export",
        params={"target": target},
        headers={
            "X-Actor-Assertion": actor_assertion,
            "X-Request-Nonce": request_nonce,
        },
        timeout=5,
    )


def _direct_admin_export(token: str, request_nonce: str, base=INTERNAL_A):
    return requests.get(
        f"{base}/admin/export",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Request-Nonce": request_nonce,
        },
        timeout=5,
    )


# -----------------------------------------------------------------------------
# Token-service propagation of actor jti
# -----------------------------------------------------------------------------


def test_delegated_token_carries_act_jti():
    """The end-to-end binding requires the access token to carry the
    actor assertion's jti. Without this claim the response envelope
    cannot bind back to the operator."""
    aa = alice_assertion("admin.export.read")
    actor_jti = decode_token_payload(aa)["jti"]
    ca = gateway_assertion()
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": aa,
        }
    )
    assert r.status_code == 200, r.text
    tok = r.json()["access_token"]
    claims = decode_token_payload(tok)
    assert claims.get("act_jti") == actor_jti


def test_self_minted_token_has_no_act_jti():
    ca = observer_assertion()
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "internal.metrics.read",
            "client_assertion": ca,
        }
    )
    assert r.status_code == 200
    tok = r.json()["access_token"]
    claims = decode_token_payload(tok)
    assert "act_jti" not in claims


# -----------------------------------------------------------------------------
# Direct internal-admin envelope tests (verifies the issuer side)
# -----------------------------------------------------------------------------


def test_internal_admin_signs_success_response():
    aa = alice_assertion("admin.export.read")
    ca = gateway_assertion()
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": aa,
        }
    )
    tok = r.json()["access_token"]
    nonce = f"int-{uuid.uuid4()}"
    resp = _direct_admin_export(tok, nonce, base=INTERNAL_A)
    assert resp.status_code == 200, resp.text
    envelope = resp.headers.get("X-Response-Envelope")
    assert envelope, "internal-admin must return X-Response-Envelope"
    actor_jti = decode_token_payload(aa)["jti"]
    claims = verify_response_envelope(
        envelope_jwt=envelope,
        body_bytes=resp.content,
        expected_request_nonce=nonce,
        expected_actor_jti=actor_jti,
        expected_subject="ops-alice",
        expected_scope="admin.export.read",
        expected_endpoint="/admin/export",
        expected_status=200,
        expected_replica="internal-admin-a",
    )
    assert claims["body_sha256"]
    assert claims["iss"] == "internal-admin-a"


def test_internal_admin_signs_replica_b_with_replica_b_kid():
    aa = alice_assertion("admin.export.read")
    ca = gateway_assertion()
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": aa,
        }
    )
    tok = r.json()["access_token"]
    nonce = f"int-{uuid.uuid4()}"
    resp = _direct_admin_export(tok, nonce, base=INTERNAL_B)
    assert resp.status_code == 200
    envelope = resp.headers.get("X-Response-Envelope")
    assert envelope
    actor_jti = decode_token_payload(aa)["jti"]
    claims = verify_response_envelope(
        envelope_jwt=envelope,
        body_bytes=resp.content,
        expected_request_nonce=nonce,
        expected_actor_jti=actor_jti,
        expected_subject="ops-alice",
        expected_scope="admin.export.read",
        expected_endpoint="/admin/export",
        expected_status=200,
        expected_replica="internal-admin-b",
    )
    assert claims["iss"] == "internal-admin-b"


def test_internal_admin_signs_error_responses_too():
    """An attacker who cannot forge a valid token still wants to know
    they got 'forbidden' instead of e.g. a relay-fabricated 200. The
    error path must be signed."""
    nonce = f"int-{uuid.uuid4()}"
    resp = requests.get(
        f"{INTERNAL_A}/admin/export",
        headers={"Authorization": "Bearer x.y.z", "X-Request-Nonce": nonce},
        timeout=5,
    )
    assert resp.status_code == 403
    envelope = resp.headers.get("X-Response-Envelope")
    assert envelope
    claims = verify_response_envelope(
        envelope_jwt=envelope,
        body_bytes=resp.content,
        expected_request_nonce=nonce,
        expected_actor_jti=None,
        expected_subject=None,
        expected_scope=None,
        expected_endpoint="/admin/export",
        expected_status=403,
        expected_replica="internal-admin-a",
    )
    assert claims["status"] == 403


# -----------------------------------------------------------------------------
# End-to-end: operator -> gateway -> internal-admin
# -----------------------------------------------------------------------------


def test_ops_export_envelope_propagated_through_gateway():
    aa = alice_assertion("admin.export.read")
    actor_jti = decode_token_payload(aa)["jti"]
    nonce = f"e2e-{uuid.uuid4()}"
    r = _ops_export("a", aa, nonce)
    assert r.status_code == 200, r.text
    envelope = r.headers.get("X-Response-Envelope")
    assert envelope, "gateway must forward the envelope from internal-admin"
    claims = verify_response_envelope(
        envelope_jwt=envelope,
        body_bytes=r.content,
        expected_request_nonce=nonce,
        expected_actor_jti=actor_jti,
        expected_subject="ops-alice",
        expected_scope="admin.export.read",
        expected_endpoint="/admin/export",
        expected_status=200,
        expected_replica="internal-admin-a",
    )
    assert claims["iss"] == "internal-admin-a"


def test_ops_export_target_b_envelope_says_replica_b():
    aa = alice_assertion("admin.export.read")
    actor_jti = decode_token_payload(aa)["jti"]
    nonce = f"e2e-{uuid.uuid4()}"
    r = _ops_export("b", aa, nonce)
    assert r.status_code == 200
    envelope = r.headers["X-Response-Envelope"]
    claims = verify_response_envelope(
        envelope_jwt=envelope,
        body_bytes=r.content,
        expected_request_nonce=nonce,
        expected_actor_jti=actor_jti,
        expected_subject="ops-alice",
        expected_scope="admin.export.read",
        expected_endpoint="/admin/export",
        expected_status=200,
        expected_replica="internal-admin-b",
    )
    assert claims["iss"] == "internal-admin-b"


def test_observer_self_mint_response_envelope():
    """Self-minted tokens have no act_jti. The envelope reflects this
    by carrying actor_jti=''. Operators of self-minted tokens pass
    expected_actor_jti='' to the verifier."""
    ca = observer_assertion()
    r = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "internal.metrics.read",
            "client_assertion": ca,
        }
    )
    tok = r.json()["access_token"]
    nonce = f"sm-{uuid.uuid4()}"
    resp = requests.get(
        f"{INTERNAL_A}/internal/metrics",
        headers={
            "Authorization": f"Bearer {tok}",
            "X-Request-Nonce": nonce,
        },
        timeout=5,
    )
    assert resp.status_code == 200
    envelope = resp.headers["X-Response-Envelope"]
    claims = verify_response_envelope(
        envelope_jwt=envelope,
        body_bytes=resp.content,
        expected_request_nonce=nonce,
        expected_actor_jti="",
        expected_subject="observer",
        expected_scope="internal.metrics.read",
        expected_endpoint="/internal/metrics",
        expected_status=200,
        expected_replica="internal-admin-a",
    )
    assert claims["actor_jti"] == ""


# -----------------------------------------------------------------------------
# Tampering detection
# -----------------------------------------------------------------------------


def _fresh_legit_response_for_alice():
    aa = alice_assertion("admin.export.read")
    actor_jti = decode_token_payload(aa)["jti"]
    nonce = f"v-{uuid.uuid4()}"
    r = _ops_export("a", aa, nonce)
    assert r.status_code == 200
    return {
        "body": r.content,
        "envelope": r.headers["X-Response-Envelope"],
        "nonce": nonce,
        "actor_jti": actor_jti,
    }


def test_tampered_body_detected():
    legit = _fresh_legit_response_for_alice()
    tampered_body = legit["body"].replace(b'"records":2', b'"records":0')
    assert tampered_body != legit["body"]
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=legit["envelope"],
            body_bytes=tampered_body,
            expected_request_nonce=legit["nonce"],
            expected_actor_jti=legit["actor_jti"],
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica="internal-admin-a",
        )
    assert "body hash" in str(exc.value)


def test_envelope_signature_tamper_detected():
    legit = _fresh_legit_response_for_alice()
    h, p, s = legit["envelope"].split(".")
    sig_bytes = bytearray(b64d(s))
    sig_bytes[0] ^= 0xFF
    bad = f"{h}.{p}.{b64e(bytes(sig_bytes))}"
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=bad,
            body_bytes=legit["body"],
            expected_request_nonce=legit["nonce"],
            expected_actor_jti=legit["actor_jti"],
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica="internal-admin-a",
        )
    assert "signature" in str(exc.value)


def test_wrong_request_nonce_detected():
    legit = _fresh_legit_response_for_alice()
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=legit["envelope"],
            body_bytes=legit["body"],
            expected_request_nonce="not-the-nonce",
            expected_actor_jti=legit["actor_jti"],
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica="internal-admin-a",
        )
    assert "nonce" in str(exc.value)


def test_wrong_actor_jti_detected():
    legit = _fresh_legit_response_for_alice()
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=legit["envelope"],
            body_bytes=legit["body"],
            expected_request_nonce=legit["nonce"],
            expected_actor_jti="not-my-jti",
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica="internal-admin-a",
        )
    assert "actor_jti" in str(exc.value)


def test_wrong_subject_detected():
    legit = _fresh_legit_response_for_alice()
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=legit["envelope"],
            body_bytes=legit["body"],
            expected_request_nonce=legit["nonce"],
            expected_actor_jti=legit["actor_jti"],
            expected_subject="ops-bob",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica="internal-admin-a",
        )
    assert "subject" in str(exc.value)


def test_wrong_endpoint_detected():
    legit = _fresh_legit_response_for_alice()
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=legit["envelope"],
            body_bytes=legit["body"],
            expected_request_nonce=legit["nonce"],
            expected_actor_jti=legit["actor_jti"],
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/internal/metrics",
            expected_status=200,
            expected_replica="internal-admin-a",
        )
    assert "endpoint" in str(exc.value)


def test_wrong_status_detected():
    legit = _fresh_legit_response_for_alice()
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=legit["envelope"],
            body_bytes=legit["body"],
            expected_request_nonce=legit["nonce"],
            expected_actor_jti=legit["actor_jti"],
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=403,
            expected_replica="internal-admin-a",
        )
    assert "status" in str(exc.value)


def test_replica_spoof_detected():
    """A relay that captured a replica-A envelope cannot present it as
    a replica-B answer. The expected_replica check rejects it, AND the
    iss/kid binding inside the verifier rejects any tampering with the
    iss field.
    """
    legit = _fresh_legit_response_for_alice()
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=legit["envelope"],
            body_bytes=legit["body"],
            expected_request_nonce=legit["nonce"],
            expected_actor_jti=legit["actor_jti"],
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica="internal-admin-b",
        )
    assert "replica" in str(exc.value)


def test_kid_iss_binding():
    """Even if a relay edits the envelope claims to claim
    iss=internal-admin-b, the iss/kid map locks them together at
    verify time. (Of course this would also fail signature check, but
    the explicit pin is documented and tested.)
    """
    legit = _fresh_legit_response_for_alice()
    h, p, s = legit["envelope"].split(".")
    claims = json.loads(b64d(p).decode())
    claims["iss"] = "internal-admin-b"  # lie
    p2 = b64e(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    bad = f"{h}.{p2}.{s}"
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=bad,
            body_bytes=legit["body"],
            expected_request_nonce=legit["nonce"],
            expected_actor_jti=legit["actor_jti"],
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica="internal-admin-a",
        )
    # Either "signature" (because we changed the payload bytes the
    # signature covers) or "iss/kid" depending on which check runs first.
    assert "signature" in str(exc.value) or "iss" in str(exc.value)


def test_missing_envelope_treated_as_untrusted():
    with pytest.raises(EnvelopeVerifyError):
        verify_response_envelope(
            envelope_jwt="",
            body_bytes=b"{}",
            expected_request_nonce="x",
            expected_actor_jti=None,
            expected_subject=None,
            expected_scope=None,
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica=None,
        )


def test_envelope_replay_across_requests_detected():
    """Capture a legit envelope from one request, try to glue it onto a
    second request from the same operator (same actor jti is impossible
    because actor assertions are single-use, so use a fresh nonce on the
    second request and watch the nonce check fail)."""
    legit = _fresh_legit_response_for_alice()
    new_nonce = f"replay-{uuid.uuid4()}"
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=legit["envelope"],
            body_bytes=legit["body"],
            expected_request_nonce=new_nonce,  # operator's "fresh" request nonce
            expected_actor_jti=legit["actor_jti"],
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica="internal-admin-a",
        )
    assert "nonce" in str(exc.value)


# -----------------------------------------------------------------------------
# Rogue gateway: end-to-end simulation
# -----------------------------------------------------------------------------


def _rogue_gateway_pretend_export(actor_assertion: str, request_nonce: str):
    """Simulate what a fully compromised gateway can do:
       - Mint a real delegated token using the operator's actor assertion.
       - Call internal-admin and capture the real (signed) response.
       - Return a fabricated body to the operator, with NO envelope.
    Returns the (status_code, body, headers) tuple the operator would see.
    """
    ca = gateway_assertion()
    m = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": actor_assertion,
        }
    )
    assert m.status_code == 200, m.text
    tok = m.json()["access_token"]
    # Capture the real response so we know what's truly there - the
    # rogue gateway has full visibility.
    requests.get(
        f"{INTERNAL_A}/admin/export",
        headers={"Authorization": f"Bearer {tok}", "X-Request-Nonce": request_nonce},
        timeout=5,
    )
    # Return a lie WITHOUT the envelope.
    forged_body = json.dumps(
        {
            "service": "internal-admin-a",
            "caller": "ops-alice",
            "actor": "gateway",
            "records": 0,
            "users": [],
        }
    ).encode()
    return 200, forged_body, {}


def _rogue_gateway_mint_only(actor_assertion: str):
    """A subtler rogue gateway: do the legit mint and return a forged
    body together with a forged X-Response-Envelope (signed with the
    rogue's own key). The operator's envelope-key allowlist must
    reject."""
    ca = gateway_assertion()
    m = _mint(
        {
            "audience": AUD_INTERNAL,
            "scope": "admin.export.read",
            "client_assertion": ca,
            "actor_assertion": actor_assertion,
        }
    )
    assert m.status_code == 200
    return m.json()["access_token"]


def test_rogue_gateway_dropping_envelope_is_caught():
    aa = alice_assertion("admin.export.read")
    actor_jti = decode_token_payload(aa)["jti"]
    nonce = f"rogue-{uuid.uuid4()}"
    status, body, headers = _rogue_gateway_pretend_export(aa, nonce)
    # The operator's policy: missing envelope = untrusted, no matter
    # how plausible the body looks.
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=headers.get("X-Response-Envelope", ""),
            body_bytes=body,
            expected_request_nonce=nonce,
            expected_actor_jti=actor_jti,
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica="internal-admin-a",
        )
    assert "missing" in str(exc.value).lower() or "envelope" in str(exc.value).lower()


def test_rogue_gateway_self_signed_envelope_is_caught():
    """The rogue gateway signs its own envelope with a key it controls,
    using a kid the operator does not pin. The operator-side kid set
    rejects unknown kids before signature verification."""
    from trust_helpers import ROGUE_KEY

    aa = alice_assertion("admin.export.read")
    actor_jti = decode_token_payload(aa)["jti"]
    nonce = f"selfsign-{uuid.uuid4()}"
    # Mint a real token so the rogue knows the real actor_jti.
    _rogue_gateway_mint_only(aa)
    body_bytes = json.dumps(
        {"service": "internal-admin-a", "records": 999},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    import hashlib

    body_hash = b64e(hashlib.sha256(body_bytes).digest())
    now = int(time.time())
    forged_envelope = sign_compact(
        ROGUE_KEY,
        {"alg": "EdDSA", "typ": TYP_RESPONSE_ENVELOPE, "kid": "rogue-v1"},
        {
            "iss": "internal-admin-a",
            "iat": now,
            "exp": now + 30,
            "endpoint": "/admin/export",
            "status": 200,
            "request_nonce": nonce,
            "actor_jti": actor_jti,
            "subject": "ops-alice",
            "scope": "admin.export.read",
            "body_sha256": body_hash,
        },
    )
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=forged_envelope,
            body_bytes=body_bytes,
            expected_request_nonce=nonce,
            expected_actor_jti=actor_jti,
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica="internal-admin-a",
        )
    assert "kid" in str(exc.value)


def test_rogue_gateway_pinning_real_envelope_to_modified_body_is_caught():
    """A more sophisticated rogue: capture a real envelope (which is
    only valid for the captured body) and try to glue it to a fabricated
    body. Body hash mismatch must catch it."""
    aa = alice_assertion("admin.export.read")
    actor_jti = decode_token_payload(aa)["jti"]
    nonce = f"rebody-{uuid.uuid4()}"
    legit = _ops_export("a", aa, nonce)
    assert legit.status_code == 200
    real_envelope = legit.headers["X-Response-Envelope"]
    forged_body = json.dumps(
        {"service": "internal-admin-a", "records": 0},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=real_envelope,
            body_bytes=forged_body,
            expected_request_nonce=nonce,
            expected_actor_jti=actor_jti,
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica="internal-admin-a",
        )
    assert "body hash" in str(exc.value)


def test_rogue_gateway_swapping_replica_envelopes_caught():
    """Operator asks for target=a, but the relay actually called
    target=b. The envelope in the response will say iss=internal-admin-b.
    The operator pins expected_replica=internal-admin-a and detects."""
    aa_a = alice_assertion("admin.export.read")
    actor_jti = decode_token_payload(aa_a)["jti"]
    nonce = f"swap-{uuid.uuid4()}"
    # Operator wanted A, but the (rogue) gateway routed to B.
    rogue_call = _ops_export("b", aa_a, nonce)
    assert rogue_call.status_code == 200
    envelope = rogue_call.headers["X-Response-Envelope"]
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=envelope,
            body_bytes=rogue_call.content,
            expected_request_nonce=nonce,
            expected_actor_jti=actor_jti,
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica="internal-admin-a",  # operator wanted A
        )
    assert "replica" in str(exc.value)


def test_compromised_issuer_cannot_forge_envelope():
    """Even an attacker holding the access-token issuer key (a much
    higher level of compromise than 'just the gateway') cannot sign a
    response envelope, because internal-admin uses a separate keypair.
    """
    from trust_helpers import TOKEN_ISSUER_KEY

    aa = alice_assertion("admin.export.read")
    actor_jti = decode_token_payload(aa)["jti"]
    nonce = f"issuer-{uuid.uuid4()}"
    body_bytes = json.dumps(
        {"records": 0}, sort_keys=True, separators=(",", ":")
    ).encode()
    import hashlib

    body_hash = b64e(hashlib.sha256(body_bytes).digest())
    now = int(time.time())
    # Sign with the access-token issuer key instead of the response key.
    forged = sign_compact(
        TOKEN_ISSUER_KEY,
        {
            "alg": "EdDSA",
            "typ": TYP_RESPONSE_ENVELOPE,
            "kid": "ia-a-v1",
        },  # claims to be ia-a-v1
        {
            "iss": "internal-admin-a",
            "iat": now,
            "exp": now + 30,
            "endpoint": "/admin/export",
            "status": 200,
            "request_nonce": nonce,
            "actor_jti": actor_jti,
            "subject": "ops-alice",
            "scope": "admin.export.read",
            "body_sha256": body_hash,
        },
    )
    with pytest.raises(EnvelopeVerifyError) as exc:
        verify_response_envelope(
            envelope_jwt=forged,
            body_bytes=body_bytes,
            expected_request_nonce=nonce,
            expected_actor_jti=actor_jti,
            expected_subject="ops-alice",
            expected_scope="admin.export.read",
            expected_endpoint="/admin/export",
            expected_status=200,
            expected_replica="internal-admin-a",
        )
    assert "signature" in str(exc.value)
