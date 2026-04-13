import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "app.py"


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.counters = {}

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    def incr(self, key):
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    def expire(self, key, ttl):
        return True


@pytest.fixture()
def module_and_client():
    spec = importlib.util.spec_from_file_location("token_service_app_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.app.config.update(TESTING=True)
    with module.app.test_client() as client:
        yield module, client


def test_mesh_requires_authenticated_discovery_client(module_and_client):
    _, client = module_and_client

    r = client.get("/.well-known/mesh")
    assert r.status_code == 403

    r = client.get(
        "/.well-known/mesh",
        headers={
            "X-Client-Id": "gateway",
            "X-Client-Secret": "gateway-client-secret",
        },
    )
    assert r.status_code == 200
    assert r.get_json() == {
        "service": "token-service",
        "audience": "internal-admin",
        "client_id": "gateway",
    }


def test_mint_requires_nonce(module_and_client, monkeypatch):
    module, client = module_and_client
    monkeypatch.setattr(module, "_redis", lambda: FakeRedis())

    r = client.post(
        "/v1/mint",
        json={"audience": "internal-admin", "scope": "admin.export.read"},
        headers={
            "X-Client-Id": "gateway",
            "X-Client-Secret": "gateway-client-secret",
        },
    )
    assert r.status_code == 400
    assert r.get_json()["error"] == "missing nonce"


def test_nonce_replay_is_blocked_with_shared_state(module_and_client, monkeypatch):
    module, client = module_and_client
    fake_redis = FakeRedis()
    monkeypatch.setattr(module, "_redis", lambda: fake_redis)
    headers = {
        "X-Client-Id": "gateway",
        "X-Client-Secret": "gateway-client-secret",
        "X-Nonce": "nonce-1",
    }

    first = client.post(
        "/v1/mint",
        json={"audience": "internal-admin", "scope": "admin.export.read"},
        headers=headers,
    )
    second = client.post(
        "/v1/mint",
        json={"audience": "internal-admin", "scope": "admin.export.read"},
        headers=headers,
    )

    assert first.status_code == 200
    assert second.status_code == 403
    assert second.get_json()["error"] == "nonce replay"


def test_mint_fails_closed_when_redis_is_unavailable(module_and_client, monkeypatch):
    module, client = module_and_client

    def broken_redis():
        raise RuntimeError("redis down")

    monkeypatch.setattr(module, "_redis", broken_redis)

    r = client.post(
        "/v1/mint",
        json={"audience": "internal-admin", "scope": "admin.export.read"},
        headers={
            "X-Client-Id": "gateway",
            "X-Client-Secret": "gateway-client-secret",
            "X-Nonce": "nonce-redis-down",
        },
    )
    assert r.status_code == 503
    assert r.get_json()["error"] == "redis unavailable"
