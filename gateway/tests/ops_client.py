"""Operator-side client library.

This module packages the operator-side flow so callers cannot
accidentally skip response envelope verification. All access to the
response body goes through ``VerifiedResponse``, and the only way to
construct one is via ``OpsClient`` methods, which verify every envelope
as a precondition of returning.

Why this matters: the previous turn shipped per-response envelopes but
left verification as the *caller's* responsibility. An operator that
simply called ``requests.get("/ops/export")`` and parsed the JSON body
was wide open to a compromised gateway serving any body it wanted. This
module makes the safe flow the default.

In a production deployment, this library would ship as a thin Python
package installed on every operator workstation, and the operator CLI
would wrap it. In the lab it lives next to the tests and is exercised
by ``test_operator_client.py``.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trust_helpers import (
    EnvelopeVerifyError,
    OPS_ALICE_KEY,
    OPS_BOB_KEY,
    TYP_ACTOR_AUTH,
    sign_compact,
    verify_response_envelope,
)


class OpsClientError(RuntimeError):
    """Raised when the operator client cannot return a trusted response.

    This is intentionally a distinct, loud exception type. Callers
    should NOT catch it and fall back to the raw body; the whole point
    of the client is that anything other than a ``VerifiedResponse``
    return value should be treated as a potential relay compromise.
    """


class _Sentinel:
    """Construction key for VerifiedResponse. The class only accepts an
    instance of this sentinel in its constructor, and the sentinel is
    private to this module. External code cannot forge a
    VerifiedResponse without going through the client.
    """


_VERIFIED_SENTINEL = _Sentinel()


class VerifiedResponse:
    """An immutable, fully verified HTTP response.

    The body is only exposed through the ``body`` and ``body_bytes``
    properties. It is impossible to receive a VerifiedResponse without
    the envelope having been verified against the bytes that back it,
    so once an instance exists the caller can trust what it contains.
    """

    __slots__ = ("_body_bytes", "_status", "_envelope_claims", "_parsed")

    def __init__(self, token, body_bytes: bytes, status: int, envelope_claims: dict):
        if token is not _VERIFIED_SENTINEL:
            raise TypeError(
                "VerifiedResponse cannot be constructed externally; use OpsClient"
            )
        object.__setattr__(self, "_body_bytes", bytes(body_bytes))
        object.__setattr__(self, "_status", int(status))
        object.__setattr__(self, "_envelope_claims", dict(envelope_claims))
        object.__setattr__(self, "_parsed", None)

    def __setattr__(self, *_):  # pragma: no cover - defensive
        raise AttributeError("VerifiedResponse is immutable")

    @property
    def status(self) -> int:
        return self._status

    @property
    def body_bytes(self) -> bytes:
        return self._body_bytes

    @property
    def body(self) -> Any:
        parsed = object.__getattribute__(self, "_parsed")
        if parsed is None:
            parsed = json.loads(self._body_bytes.decode())
            object.__setattr__(self, "_parsed", parsed)
        return parsed

    @property
    def envelope(self) -> dict:
        return dict(self._envelope_claims)


@dataclass
class _LedgerEntry:
    actor_jti: str
    endpoint: str
    scope: str
    target: str | None
    iat: int


@dataclass
class OpsClient:
    """Operator client.

    Holds a single operator's credentials and the pinned trust roots
    needed to verify response envelopes. Every method that talks to the
    gateway returns a ``VerifiedResponse`` or raises
    ``OpsClientError`` / ``EnvelopeVerifyError``.
    """

    operator_id: str
    operator_key: Ed25519PrivateKey
    operator_kid: str
    gateway_url: str = "http://gateway:5000"
    assertion_lifetime: int = 30
    _ledger: list[_LedgerEntry] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Internal plumbing
    # ------------------------------------------------------------------

    def _sign_actor_assertion(self, scope: str) -> tuple[str, str]:
        """Return (jti, compact-jwt) for a fresh actor assertion."""
        now = int(time.time())
        jti = str(uuid.uuid4())
        header = {"alg": "EdDSA", "typ": TYP_ACTOR_AUTH, "kid": self.operator_kid}
        payload = {
            "iss": self.operator_id,
            "sub": self.operator_id,
            "aud": "token-service",
            "scope": scope,
            "iat": now,
            "nbf": now,
            "exp": now + self.assertion_lifetime,
            "jti": jti,
        }
        return jti, sign_compact(self.operator_key, header, payload)

    def _fresh_nonce(self, tag: str) -> str:
        return f"{tag}-{uuid.uuid4()}"

    def _call(
        self,
        *,
        path: str,
        scope: str,
        expected_endpoint: str,
        target: str | None,
        extra_params: dict | None = None,
        expected_replica: str | None,
        record_ledger: bool = True,
    ) -> VerifiedResponse:
        actor_jti, assertion = self._sign_actor_assertion(scope)
        nonce = self._fresh_nonce(path.strip("/").replace("/", "-"))
        params = {}
        if target is not None:
            params["target"] = target
        if extra_params:
            params.update(extra_params)
        try:
            r = requests.get(
                f"{self.gateway_url}{path}",
                params=params,
                headers={
                    "X-Actor-Assertion": assertion,
                    "X-Request-Nonce": nonce,
                },
                timeout=5,
            )
        except requests.RequestException as e:
            if record_ledger:
                self._ledger.append(
                    _LedgerEntry(
                        actor_jti=actor_jti,
                        endpoint=expected_endpoint,
                        scope=scope,
                        target=target,
                        iat=int(time.time()),
                    )
                )
            raise OpsClientError(f"transport failure: {e}") from e
        if record_ledger:
            self._ledger.append(
                _LedgerEntry(
                    actor_jti=actor_jti,
                    endpoint=expected_endpoint,
                    scope=scope,
                    target=target,
                    iat=int(time.time()),
                )
            )
        envelope = r.headers.get("X-Response-Envelope", "")
        # Verification is MANDATORY. Missing/bad envelope raises.
        claims = verify_response_envelope(
            envelope_jwt=envelope,
            body_bytes=r.content,
            expected_request_nonce=nonce,
            expected_actor_jti=actor_jti,
            expected_subject=self.operator_id,
            expected_scope=scope,
            expected_endpoint=expected_endpoint,
            expected_status=r.status_code,
            expected_replica=expected_replica,
        )
        return VerifiedResponse(_VERIFIED_SENTINEL, r.content, r.status_code, claims)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export(self, target: str = "a") -> VerifiedResponse:
        return self._call(
            path="/ops/export",
            scope="admin.export.read",
            expected_endpoint="/admin/export",
            target=target,
            expected_replica=f"internal-admin-{target}",
        )

    def audit(self, target: str = "a", since: int | None = None) -> VerifiedResponse:
        extra = {}
        if since is not None:
            extra["since"] = str(int(since))
        return self._call(
            path="/ops/audit",
            scope="audit.self.read",
            expected_endpoint="/internal/audit",
            target=target,
            extra_params=extra,
            expected_replica=f"internal-admin-{target}",
            # audit-of-audit: we still want this call to land in the
            # ledger so operators can cross-check that they called audit
            # at all. Internal-admin writes its own audit entry for
            # audit queries.
            record_ledger=True,
        )

    # ------------------------------------------------------------------
    # Reconcile
    # ------------------------------------------------------------------

    def reconcile(
        self,
        *,
        target: str = "a",
        since: int | None = None,
    ) -> dict:
        """Fetch the audit log and compare it against the local ledger.

        Returns a dict describing:
          - audit_entries: list of entries returned by internal-admin
          - expected: list of ledger entries in the reconciliation window
          - missing: ledger entries that do not appear in the audit
          - suppressed: True if any entries are missing

        The operator's policy on ``suppressed == True`` should be to
        alert and, if possible, retry the missing requests.
        """
        now = int(time.time())
        window_since = since if since is not None else now - 900
        audit_response = self.audit(target=target, since=window_since)
        audit_body = audit_response.body
        seen_jtis = {e.get("actor_jti", "") for e in audit_body.get("entries", [])}
        expected = [e for e in self._ledger if e.iat >= window_since]
        missing = [
            {
                "actor_jti": e.actor_jti,
                "endpoint": e.endpoint,
                "scope": e.scope,
                "target": e.target,
                "iat": e.iat,
            }
            for e in expected
            if e.actor_jti not in seen_jtis
        ]
        return {
            "window_since": window_since,
            "audit_entries": audit_body.get("entries", []),
            "expected": [
                {
                    "actor_jti": e.actor_jti,
                    "endpoint": e.endpoint,
                    "scope": e.scope,
                    "target": e.target,
                    "iat": e.iat,
                }
                for e in expected
            ],
            "missing": missing,
            "suppressed": bool(missing),
        }

    def ledger(self) -> list[dict]:
        """Expose a copy of the local ledger for inspection/testing.
        Callers never get the real internal list.
        """
        return [
            {
                "actor_jti": e.actor_jti,
                "endpoint": e.endpoint,
                "scope": e.scope,
                "target": e.target,
                "iat": e.iat,
            }
            for e in self._ledger
        ]


def alice_client(**kw) -> OpsClient:
    return OpsClient(
        operator_id="ops-alice",
        operator_key=OPS_ALICE_KEY,
        operator_kid="ops-alice-v1",
        **kw,
    )


def bob_client(**kw) -> OpsClient:
    return OpsClient(
        operator_id="ops-bob",
        operator_key=OPS_BOB_KEY,
        operator_kid="ops-bob-v1",
        **kw,
    )
