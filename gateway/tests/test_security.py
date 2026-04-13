import requests

BASE = "http://gateway:5000"


def _fetch(url: str):
    return requests.get(f"{BASE}/fetch", params={"url": url}, timeout=5)


def test_userinfo_bypass_to_admin_a_blocked():
    r = _fetch("http://gateway@internal-admin-a:5001/health")
    assert r.status_code in (400, 403)


def test_redirect_ssrf_to_admin_a_blocked():
    r = _fetch("http://redirector:5002/to-admin-a-health")
    assert r.status_code in (400, 403)


def test_token_service_discovery_blocked():
    r = _fetch("http://token-service:5003/.well-known/mesh")
    assert r.status_code in (400, 403)


def test_raw_token_helper_retired_or_locked_down():
    r = requests.get(f"{BASE}/ops/raw-token", timeout=5)
    assert r.status_code in (403, 404, 410)


def test_same_token_cannot_work_across_replicas():
    hdrs = {"X-Admin-Api-Key": "lab-admin-key", "X-Nonce": "pytest-replay"}
    r = requests.get(f"{BASE}/ops/raw-token", params={"scope": "admin.export.read"}, headers=hdrs, timeout=5)
    token = r.json().get("access_token", "")
    r1 = requests.get(f"{BASE}/ops/use-token", params={"target": "a", "token": token}, headers={"X-Admin-Api-Key": "lab-admin-key"}, timeout=5)
    r2 = requests.get(f"{BASE}/ops/use-token", params={"target": "b", "token": token}, headers={"X-Admin-Api-Key": "lab-admin-key"}, timeout=5)
    assert not (r1.status_code == 200 and r2.status_code == 200)
