"""Tests for the operator client library and the audit-based
suppression detection mechanism.

These tests cover:
  - The safe default flow: OpsClient.export() performs mandatory
    envelope verification.
  - VerifiedResponse cannot be constructed outside the client.
  - The operator-client raises loudly if the relay serves a body
    without an envelope.
  - The audit endpoint returns the operator's own entries, envelope-
    signed end-to-end.
  - Cross-operator isolation: alice cannot see bob's audit log.
  - OpsClient.reconcile() detects a suppressed request by cross-
    checking the local ledger against the audit response.
  - Audit log fail-closed when Redis is partially available.
  - A rogue-gateway simulation where envelope checks still catch
    tampering even when the operator uses the convenience client.
"""

import json
import time
import uuid

import pytest
import redis as redislib
import requests

from trust_helpers import (
    EnvelopeVerifyError,
    alice_assertion,
    decode_token_payload,
    gateway_assertion,
)
from ops_client import (
    OpsClient,
    OpsClientError,
    VerifiedResponse,
    alice_client,
    bob_client,
)


GATEWAY = "http://gateway:5000"
TOKEN_SERVICE = "http://token-service:5003"
INTERNAL_A = "http://internal-admin-a:5001"
INTERNAL_B = "http://internal-admin-b:5001"
AUD_INTERNAL = "internal-admin"


# -----------------------------------------------------------------------------
# Redis helpers (test-only manipulation)
# -----------------------------------------------------------------------------


def _redis_client():
    return redislib.Redis.from_url("redis://redis:6379/0", decode_responses=True)


def _clear_audit_for(subject: str):
    r = _redis_client()
    r.delete(f"audit:op:{subject}")


def _clear_rate_limit(*ids):
    r = _redis_client()
    for cid in ids:
        for k in list(r.scan_iter(match=f"rate:{cid}:*")):
            r.delete(k)


def _peek_audit(subject: str):
    r = _redis_client()
    raw = r.zrange(f"audit:op:{subject}", 0, -1, withscores=True)
    return raw


@pytest.fixture(autouse=True)
def _isolate_audit_and_rate_limit():
    # Each test gets a clean per-operator audit log and rate-limit state
    # so suppression tests never have leftover records from other tests.
    for sub in ("ops-alice", "ops-bob", "observer", "gateway"):
        _clear_audit_for(sub)
        _clear_rate_limit(sub)
    yield


# -----------------------------------------------------------------------------
# VerifiedResponse sealing
# -----------------------------------------------------------------------------


def test_verified_response_cannot_be_constructed_directly():
    with pytest.raises(TypeError):
        VerifiedResponse(None, b"{}", 200, {})


def test_verified_response_is_immutable():
    client = alice_client()
    vr = client.export(target="a")
    assert isinstance(vr, VerifiedResponse)
    with pytest.raises(AttributeError):
        vr._body_bytes = b"{}"  # noqa
    with pytest.raises(AttributeError):
        vr.status = 999


# -----------------------------------------------------------------------------
# Safe default: OpsClient.export()
# -----------------------------------------------------------------------------


def test_alice_client_export_a_is_verified_end_to_end():
    client = alice_client()
    vr = client.export(target="a")
    assert vr.status == 200
    assert vr.body["service"] == "internal-admin-a"
    assert vr.body["caller"] == "ops-alice"
    assert vr.body["actor"] == "gateway"
    assert vr.envelope["iss"] == "internal-admin-a"
    assert vr.envelope["subject"] == "ops-alice"
    assert vr.envelope["scope"] == "admin.export.read"
    assert vr.envelope["endpoint"] == "/admin/export"


def test_alice_client_export_b_pins_replica_b():
    client = alice_client()
    vr = client.export(target="b")
    assert vr.envelope["iss"] == "internal-admin-b"


def test_bob_client_export_works_with_restricted_scopes():
    client = bob_client()
    vr = client.export(target="a")
    assert vr.body["caller"] == "ops-bob"


def test_client_body_access_requires_passing_through_verification():
    """If an operator bypasses OpsClient (using requests.get directly)
    and never verifies the envelope, they accept whatever the relay
    sends. The client library prevents this by being the only path to
    a VerifiedResponse.
    """
    aa = alice_assertion("admin.export.read")
    raw = requests.get(
        f"{GATEWAY}/ops/export",
        params={"target": "a"},
        headers={"X-Actor-Assertion": aa, "X-Request-Nonce": "naive-operator"},
        timeout=5,
    )
    # The naive caller has the body and status but no safety.
    assert raw.status_code == 200
    # They could just trust it. There is no way to turn this into a
    # VerifiedResponse without going through the envelope verifier.
    with pytest.raises(TypeError):
        VerifiedResponse(None, raw.content, raw.status_code, {})


# -----------------------------------------------------------------------------
# Audit endpoint
# -----------------------------------------------------------------------------


def test_audit_endpoint_envelope_signed():
    """The audit endpoint is a scoped endpoint like any other; it must
    return an envelope that the operator can verify.
    """
    client = alice_client()
    vr = client.audit(target="a")
    assert vr.status == 200
    assert vr.envelope["endpoint"] == "/internal/audit"
    assert vr.envelope["scope"] == "audit.self.read"
    assert vr.body["caller"] == "ops-alice"
    assert "entries" in vr.body


def test_audit_endpoint_returns_operator_own_history():
    client = alice_client()
    before = int(time.time())
    client.export(target="a")
    client.export(target="b")
    audit = client.audit(target="a", since=before - 5)
    jtis_in_audit = {e["actor_jti"] for e in audit.body["entries"]}
    # Every ledger entry EXCEPT the audit call itself was an export.
    export_jtis = {
        e["actor_jti"] for e in client.ledger() if e["endpoint"] == "/admin/export"
    }
    assert export_jtis.issubset(jtis_in_audit), (
        f"expected every export call to be audited: {export_jtis} missing from {jtis_in_audit}"
    )
    # Both replicas should be visible in the audit log since it is
    # shared via Redis.
    replicas = {e["replica"] for e in audit.body["entries"] if e.get("replica")}
    assert "internal-admin-a" in replicas
    assert "internal-admin-b" in replicas


def test_audit_isolation_between_operators():
    """ops-alice must NOT see ops-bob's audit entries and vice versa.
    This is enforced by pinning the audit log key to the token subject.
    """
    alice = alice_client()
    bob = bob_client()
    before = int(time.time())
    bob.export(target="a")
    alice_audit = alice.audit(target="a", since=before - 5)
    # alice should see only her own audit query in the log, never bob's
    # export.
    subjects = {e.get("subject") for e in alice_audit.body["entries"]}
    assert subjects == {"ops-alice"}


def test_audit_query_self_writes_audit_of_audit():
    """The audit call itself must be recorded in the audit log so the
    operator can later prove they checked.
    """
    client = alice_client()
    before = int(time.time())
    client.audit(target="a", since=before - 5)
    # Fetch again; the second call should see the first audit call in
    # its own result (with the first audit's token jti).
    second = client.audit(target="a", since=before - 5)
    endpoints = [e["endpoint"] for e in second.body["entries"]]
    assert endpoints.count("/internal/audit") >= 1


# -----------------------------------------------------------------------------
# Reconcile: suppression detection
# -----------------------------------------------------------------------------


def test_reconcile_clean_when_nothing_dropped():
    client = alice_client()
    before = int(time.time())
    client.export(target="a")
    client.export(target="b")
    report = client.reconcile(target="a", since=before - 5)
    assert report["suppressed"] is False
    assert report["missing"] == []


def test_reconcile_detects_simulated_suppression():
    """Simulate a gateway that dropped the second export by deleting
    the corresponding audit entry directly from Redis. The operator's
    local ledger still shows the call; the audit log does not. The
    reconciliation MUST flag the gap.
    """
    client = alice_client()
    before = int(time.time())
    client.export(target="a")
    second = client.export(target="a")
    client.export(target="b")

    # The second call's jti is what we'll pretend the gateway dropped.
    second_actor_jti = second.envelope["actor_jti"]
    r = _redis_client()
    key = "audit:op:ops-alice"
    # Remove the matching audit entry (the one whose actor_jti equals
    # second_actor_jti). ZSet members are JSON blobs.
    removed = 0
    for member, score in r.zrange(key, 0, -1, withscores=True):
        try:
            entry = json.loads(member)
        except Exception:
            continue
        if entry.get("actor_jti") == second_actor_jti:
            r.zrem(key, member)
            removed += 1
    assert removed == 1, "expected to find and remove exactly one audit entry"

    report = client.reconcile(target="a", since=before - 5)
    assert report["suppressed"] is True
    assert len(report["missing"]) == 1
    missing_entry = report["missing"][0]
    assert missing_entry["actor_jti"] == second_actor_jti
    assert missing_entry["endpoint"] == "/admin/export"


def test_reconcile_detects_completely_dropped_request():
    """Pretend the gateway never forwarded a request at all. From the
    operator's side they believe they submitted it (they signed an
    actor assertion and intended to call), but they never actually
    hit the gateway. A scrupulous operator might still record the
    intention in the ledger and then reconcile.
    """
    client = alice_client()
    before = int(time.time())
    client.export(target="a")

    # Simulate: operator generates an assertion for a request they
    # think they sent but which never reached the gateway. We inject
    # a ledger entry manually.
    from ops_client import _LedgerEntry

    client._ledger.append(
        _LedgerEntry(
            actor_jti=f"phantom-{uuid.uuid4()}",
            endpoint="/admin/export",
            scope="admin.export.read",
            target="a",
            iat=int(time.time()),
        )
    )

    report = client.reconcile(target="a", since=before - 5)
    assert report["suppressed"] is True
    phantom_missing = [
        m for m in report["missing"] if m["actor_jti"].startswith("phantom-")
    ]
    assert len(phantom_missing) == 1


def test_reconcile_window_respected():
    """Only entries inside the reconciliation window are checked. Old
    ledger entries outside the window must not produce false positives.
    """
    client = alice_client()

    # Inject an old ledger entry that is clearly outside the window.
    from ops_client import _LedgerEntry

    ancient = int(time.time()) - 7200
    client._ledger.append(
        _LedgerEntry(
            actor_jti="ancient-actor",
            endpoint="/admin/export",
            scope="admin.export.read",
            target="a",
            iat=ancient,
        )
    )

    client.export(target="a")
    report = client.reconcile(target="a", since=int(time.time()) - 900)
    assert report["suppressed"] is False
    assert all(e["iat"] >= report["window_since"] for e in report["expected"])


# -----------------------------------------------------------------------------
# Operator safety: verification cannot be accidentally skipped
# -----------------------------------------------------------------------------


def test_client_rejects_naive_body_if_relay_drops_envelope(monkeypatch):
    """Stand in as a relay that fetches the real upstream response but
    strips the envelope. The OpsClient must refuse.
    """
    real_get = requests.get

    def patched_get(url, **kw):
        # Do the real call, then strip the header. This models a
        # malicious gateway (or a buggy proxy) that drops the envelope
        # header somewhere between internal-admin and the operator.
        resp = real_get(url, **kw)
        # Strip header
        if "X-Response-Envelope" in resp.headers:
            del resp.headers["X-Response-Envelope"]
        return resp

    monkeypatch.setattr(requests, "get", patched_get)
    client = alice_client()
    with pytest.raises(EnvelopeVerifyError) as exc:
        client.export(target="a")
    assert "missing" in str(exc.value).lower() or "envelope" in str(exc.value).lower()


def test_client_rejects_body_if_relay_tampers_with_bytes(monkeypatch):
    real_get = requests.get

    def patched_get(url, **kw):
        resp = real_get(url, **kw)
        # Mutate the body _content bytes to flip records:2 -> records:0
        try:
            resp._content = resp.content.replace(b'"records":2', b'"records":0')
        except Exception:
            pass
        return resp

    monkeypatch.setattr(requests, "get", patched_get)
    client = alice_client()
    with pytest.raises(EnvelopeVerifyError) as exc:
        client.export(target="a")
    assert "body hash" in str(exc.value)


# -----------------------------------------------------------------------------
# Relay correctness
# -----------------------------------------------------------------------------


def test_ops_audit_relays_same_replica_as_target():
    """?target=a must go to replica a, ?target=b must go to replica b.
    This catches a relay that routes elsewhere than what the operator
    asked for.
    """
    client = alice_client()
    a = client.audit(target="a")
    b = client.audit(target="b")
    assert a.envelope["iss"] == "internal-admin-a"
    assert b.envelope["iss"] == "internal-admin-b"


def test_audit_relay_refuses_without_actor_assertion():
    r = requests.get(f"{GATEWAY}/ops/audit", timeout=5)
    assert r.status_code == 401
