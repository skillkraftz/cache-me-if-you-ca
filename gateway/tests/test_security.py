import requests
import uuid

BASE = "http://gateway:5000"
TOKEN_SERVICE = "http://token-service:5003"


def _fetch(url: str):
    return requests.get(f"{BASE}/fetch", params={"url": url}, timeout=5)


def test_userinfo_bypass_to_admin_a_blocked():
    r = _fetch("http://gateway@internal-admin-a:5001/health")
    assert r.status_code in (400, 403)


def test_redirect_ssrf_to_admin_a_blocked():
    r = _fetch("http://redirector:5002/to-admin-a-health")
    assert r.status_code in (400, 403)


def test_redirect_ssrf_to_token_service_blocked():
    r = _fetch("http://redirector:5002/to-token-discovery")
    assert r.status_code in (400, 403)


def test_token_service_discovery_blocked():
    r = _fetch("http://token-service:5003/.well-known/mesh")
    assert r.status_code in (400, 403)


def test_internal_admin_b_debug_config_blocked():
    r = _fetch("http://internal-admin-b:5001/debug/config")
    assert r.status_code in (400, 403)


def test_raw_token_helper_retired_or_locked_down():
    r = requests.get(f"{BASE}/ops/raw-token", timeout=5)
    assert r.status_code in (403, 404, 410)


def test_same_token_cannot_work_across_replicas():
    nonce = f"pytest-replay-{uuid.uuid4().hex}"
    r = requests.post(
        f"{TOKEN_SERVICE}/v1/mint",
        json={
            "audience": "internal-admin",
            "scope": "admin.export.read",
            "subject": "gateway",
        },
        headers={
            "X-Client-Id": "gateway",
            "X-Client-Secret": "gateway-client-secret",
            "X-Nonce": nonce,
        },
        timeout=5,
    )
    assert r.status_code == 200
    token = r.json()["access_token"]
    r1 = requests.get(
        f"{BASE}/ops/use-token",
        params={"target": "a", "token": token},
        headers={"X-Admin-Api-Key": "lab-admin-key"},
        timeout=5,
    )
    r2 = requests.get(
        f"{BASE}/ops/use-token",
        params={"target": "b", "token": token},
        headers={"X-Admin-Api-Key": "lab-admin-key"},
        timeout=5,
    )
    assert not (r1.status_code == 200 and r2.status_code == 200)
