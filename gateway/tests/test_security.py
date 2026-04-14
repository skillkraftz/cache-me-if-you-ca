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


def test_ops_export_requires_operator_assertion():
    r = requests.get(f"{BASE}/ops/export", params={"target": "a"}, timeout=5)
    assert r.status_code == 403


def test_ops_use_token_requires_operator_assertion():
    r = requests.get(
        f"{BASE}/ops/use-token",
        params={"target": "a", "token": "placeholder"},
        timeout=5,
    )
    assert r.status_code == 403
