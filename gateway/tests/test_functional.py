import requests

BASE = "http://gateway:5000"


def test_health():
    r = requests.get(f"{BASE}/health", timeout=5)
    assert r.status_code == 200


def test_proxy_health_still_works():
    r = requests.get(f"{BASE}/proxy-health", timeout=5)
    assert r.status_code == 200
    assert r.json()["body"]["service"] == "internal-admin-a"


def test_allowlisted_proxy_still_works():
    r = requests.get(
        f"{BASE}/proxy-allowlisted",
        params={"target": "http://internal-admin-a:5001/health"},
        timeout=5,
    )
    assert r.status_code == 200


def test_ops_export_still_works():
    r = requests.get(
        f"{BASE}/ops/export",
        params={"target": "a"},
        headers={"X-Admin-Api-Key": "lab-admin-key"},
        timeout=5,
    )
    assert r.status_code == 200
    assert r.json()["service"] == "internal-admin-a"
