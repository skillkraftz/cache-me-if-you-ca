"""Adversarial tests that extend coverage beyond the baseline security tests.

These tests assume the hardened configuration and would have failed against
the vulnerable baseline. They target root causes rather than just symptoms,
so the suite breaks loudly if a regression reopens any of the classes of
bugs covered below.
"""

import base64
import hashlib
import hmac
import json
import time
import uuid

import pytest
import requests


GATEWAY = "http://gateway:5000"
TOKEN_SERVICE = "http://token-service:5003"
INTERNAL_A = "http://internal-admin-a:5001"
INTERNAL_B = "http://internal-admin-b:5001"
ADMIN_KEY = "lab-admin-key"
GATEWAY_CLIENT_SECRET = "gateway-client-secret"
OBSERVER_CLIENT_SECRET = "observer-client-secret"
# Shared signing secret; in a real deployment this would be a KMS key and
# the test would use a minted token instead. Hardcoded here only because the
# lab treats it as configuration.
ACCESS_TOKEN_SECRET = "lab-access-token-secret"
TOKEN_AUDIENCE = "internal-admin"


def _fetch(url: str):
    return requests.get(f"{GATEWAY}/fetch", params={"url": url}, timeout=5)


def _nonce(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4()}"


def _mint(
    client_id: str, client_secret: str, scope: str, nonce: str, body_override=None
):
    body = {
        "audience": TOKEN_AUDIENCE,
        "scope": scope,
        "subject": client_id,
    }
    if body_override is not None:
        body.update(body_override)
    return requests.post(
        f"{TOKEN_SERVICE}/v1/mint",
        json=body,
        headers={
            "X-Client-Id": client_id,
            "X-Client-Secret": client_secret,
            "X-Nonce": nonce,
        },
        timeout=5,
    )


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _sign_forged(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(ACCESS_TOKEN_SECRET.encode(), body, hashlib.sha256).digest()
    return f"{_b64e(body)}.{_b64e(sig)}"


def _decode_token_body(token: str) -> dict:
    p, _ = token.split(".", 1)
    return json.loads(_b64d(p).decode())


# ----- SSRF coverage beyond the baseline -------------------------------------


def test_fetch_rejects_loopback_literal():
    r = _fetch("http://127.0.0.1:5000/health")
    assert r.status_code in (400, 403)


def test_fetch_rejects_ipv6_loopback_literal():
    r = _fetch("http://[::1]:5000/health")
    assert r.status_code in (400, 403)


def test_fetch_rejects_cloud_metadata_ip():
    r = _fetch("http://169.254.169.254/latest/meta-data/")
    assert r.status_code in (400, 403)


def test_fetch_rejects_internal_admin_b():
    # The original blocklist only mentioned replica A, so the typo let
    # attackers reach replica B unmolested.
    r = _fetch("http://internal-admin-b:5001/debug/config")
    assert r.status_code in (400, 403)


def test_fetch_rejects_redis_host():
    r = _fetch("http://redis:6379/")
    assert r.status_code in (400, 403)


def test_fetch_rejects_redirector_host():
    # Even without following the redirect, the initial host resolves to a
    # private IP and must be refused.
    r = _fetch("http://redirector:5002/bounce?to=http://example.com")
    assert r.status_code in (400, 403)


def test_fetch_rejects_file_scheme():
    r = _fetch("file:///etc/passwd")
    assert r.status_code in (400, 403)


def test_fetch_rejects_gopher_scheme():
    r = _fetch("gopher://internal-admin-a:5001/_GET%20/")
    assert r.status_code in (400, 403)


def test_fetch_rejects_userinfo_with_internal_b():
    r = _fetch("http://x:y@internal-admin-b:5001/health")
    assert r.status_code in (400, 403)


def test_fetch_refuses_to_follow_cross_origin_redirect():
    # allow_redirects=False is a primary defense; if a regression flips it
    # back on we want to know immediately. This stub route only exists on
    # the redirector host, which is already blocked at host validation, so
    # the observable outcome here is the same 4xx — but we document intent.
    r = _fetch("http://redirector:5002/to-admin-a-health")
    assert r.status_code in (400, 403)


# ----- Gateway admin helpers -------------------------------------------------


def test_ops_raw_token_retired_even_with_admin_key():
    r = requests.get(
        f"{GATEWAY}/ops/raw-token",
        params={"scope": "admin.export.read", "subject": "admin-bypass"},
        headers={"X-Admin-Api-Key": ADMIN_KEY, "X-Nonce": "whatever"},
        timeout=5,
    )
    assert r.status_code in (403, 404, 410)


def test_ops_export_still_works_on_both_replicas():
    # Legitimate functional path: gateway mints a fresh token per request
    # and uses it on a single replica. Running against A and B individually
    # must still work because each mint uses a unique JTI.
    a = requests.get(
        f"{GATEWAY}/ops/export",
        params={"target": "a"},
        headers={"X-Admin-Api-Key": ADMIN_KEY},
        timeout=5,
    )
    b = requests.get(
        f"{GATEWAY}/ops/export",
        params={"target": "b"},
        headers={"X-Admin-Api-Key": ADMIN_KEY},
        timeout=5,
    )
    assert a.status_code == 200, a.text
    assert b.status_code == 200, b.text
    assert a.json()["service"] == "internal-admin-a"
    assert b.json()["service"] == "internal-admin-b"


def test_ops_use_token_rejects_without_admin_key():
    r = requests.get(
        f"{GATEWAY}/ops/use-token",
        params={"target": "a", "token": "x"},
        timeout=5,
    )
    assert r.status_code == 403


# ----- Token-service hardening ----------------------------------------------


def test_mint_requires_nonce_header():
    r = requests.post(
        f"{TOKEN_SERVICE}/v1/mint",
        json={"audience": TOKEN_AUDIENCE, "scope": "admin.export.read"},
        headers={"X-Client-Id": "gateway", "X-Client-Secret": GATEWAY_CLIENT_SECRET},
        timeout=5,
    )
    assert r.status_code == 400


def test_mint_rejects_unknown_client():
    r = _mint("attacker", "whatever", "admin.export.read", _nonce("unknown"))
    assert r.status_code == 403


def test_mint_rejects_bad_secret():
    r = _mint("gateway", "wrong", "admin.export.read", _nonce("badsec"))
    assert r.status_code == 403


def test_nonce_replay_blocked_at_mint():
    nonce = _nonce("replay")
    first = _mint("gateway", GATEWAY_CLIENT_SECRET, "admin.export.read", nonce)
    second = _mint("gateway", GATEWAY_CLIENT_SECRET, "admin.export.read", nonce)
    assert first.status_code == 200, first.text
    assert second.status_code == 403


def test_subject_field_is_ignored_in_favor_of_client_id():
    nonce = _nonce("subj")
    r = _mint(
        "gateway",
        GATEWAY_CLIENT_SECRET,
        "admin.export.read",
        nonce,
        body_override={"subject": "admin-bypass"},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["subject"] == "gateway"
    claims = _decode_token_body(data["access_token"])
    assert claims["sub"] == "gateway"
    assert claims["jti"]
    # JTI must not be influenced by attacker-supplied nonce.
    assert nonce not in claims["jti"]


def test_scope_not_permitted_for_observer():
    # observer does not hold admin.export.read
    r = _mint("observer", OBSERVER_CLIENT_SECRET, "admin.export.read", _nonce("obs"))
    assert r.status_code == 403


def test_mesh_endpoint_requires_client_credentials():
    r = requests.get(f"{TOKEN_SERVICE}/.well-known/mesh", timeout=5)
    assert r.status_code == 403
    r2 = requests.get(
        f"{TOKEN_SERVICE}/.well-known/mesh",
        headers={"X-Client-Id": "gateway", "X-Client-Secret": GATEWAY_CLIENT_SECRET},
        timeout=5,
    )
    assert r2.status_code == 200
    # Response must not enumerate other clients.
    assert "clients" not in r2.json()


# ----- Internal-admin hardening ---------------------------------------------


def test_internal_admin_debug_config_requires_scope():
    r = requests.get(f"{INTERNAL_A}/debug/config", timeout=5)
    assert r.status_code == 403
    r2 = requests.get(f"{INTERNAL_B}/debug/config", timeout=5)
    assert r2.status_code == 403


def test_cross_replica_replay_blocked_with_real_token():
    # Mint a real token from the token service and confirm a single token
    # cannot be spent against both replicas.
    nonce = _nonce("xrep")
    r = _mint("gateway", GATEWAY_CLIENT_SECRET, "admin.export.read", nonce)
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    a = requests.get(f"{INTERNAL_A}/admin/export", headers=h, timeout=5)
    b = requests.get(f"{INTERNAL_B}/admin/export", headers=h, timeout=5)
    # First replica succeeds, the second must be rejected.
    assert (a.status_code == 200) ^ (b.status_code == 200)
    loser = a if b.status_code == 200 else b
    assert loser.status_code == 403
    assert "replay" in loser.text.lower()


def test_same_replica_replay_blocked_with_real_token():
    nonce = _nonce("arep")
    r = _mint("gateway", GATEWAY_CLIENT_SECRET, "admin.export.read", nonce)
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    a1 = requests.get(f"{INTERNAL_A}/admin/export", headers=h, timeout=5)
    a2 = requests.get(f"{INTERNAL_A}/admin/export", headers=h, timeout=5)
    assert a1.status_code == 200
    assert a2.status_code == 403


def test_forged_token_with_bad_subject_rejected_by_admin():
    # Simulate a compromised issuer minting a token with an out-of-policy
    # subject. The internal-admin must refuse it purely on ALLOWED_SUBJECTS
    # (defense-in-depth).
    now = int(time.time())
    payload = {
        "iss": "token-service",
        "sub": "admin-bypass",
        "aud": TOKEN_AUDIENCE,
        "scope": "admin.export.read",
        "iat": now,
        "nbf": now,
        "exp": now + 30,
        "jti": str(uuid.uuid4()),
    }
    token = _sign_forged(payload)
    r = requests.get(
        f"{INTERNAL_A}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code == 403
    assert "subject" in r.text.lower()


def test_forged_token_with_oversized_lifetime_rejected():
    now = int(time.time())
    payload = {
        "iss": "token-service",
        "sub": "gateway",
        "aud": TOKEN_AUDIENCE,
        "scope": "admin.export.read",
        "iat": now,
        "nbf": now,
        "exp": now + 86400,  # 1 day
        "jti": str(uuid.uuid4()),
    }
    token = _sign_forged(payload)
    r = requests.get(
        f"{INTERNAL_A}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code == 403


def test_tampered_signature_rejected():
    nonce = _nonce("tamper")
    r = _mint("gateway", GATEWAY_CLIENT_SECRET, "admin.export.read", nonce)
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    # Decode the signature, flip a whole byte, re-encode. Avoids the
    # base64-padding edge case where modifying the last character may not
    # change the decoded bytes.
    body_b64, sig_b64 = token.split(".", 1)
    sig_bytes = bytearray(_b64d(sig_b64))
    sig_bytes[0] ^= 0xFF
    bad_sig = _b64e(bytes(sig_bytes))
    bad = f"{body_b64}.{bad_sig}"
    r2 = requests.get(
        f"{INTERNAL_A}/admin/export",
        headers={"Authorization": f"Bearer {bad}"},
        timeout=5,
    )
    assert r2.status_code == 403


def test_expired_token_rejected():
    now = int(time.time())
    payload = {
        "iss": "token-service",
        "sub": "gateway",
        "aud": TOKEN_AUDIENCE,
        "scope": "admin.export.read",
        "iat": now - 120,
        "nbf": now - 120,
        "exp": now - 60,
        "jti": str(uuid.uuid4()),
    }
    token = _sign_forged(payload)
    r = requests.get(
        f"{INTERNAL_A}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code == 403


def test_wrong_audience_rejected():
    now = int(time.time())
    payload = {
        "iss": "token-service",
        "sub": "gateway",
        "aud": "wrong-audience",
        "scope": "admin.export.read",
        "iat": now,
        "nbf": now,
        "exp": now + 30,
        "jti": str(uuid.uuid4()),
    }
    token = _sign_forged(payload)
    r = requests.get(
        f"{INTERNAL_A}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code == 403
