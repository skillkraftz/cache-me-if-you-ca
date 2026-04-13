import base64
import hashlib
import hmac
import importlib.util
import json
import time
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "app.py"


class FakeRedis:
    def __init__(self):
        self.values = {}

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(b"lab-access-token-secret", body, hashlib.sha256).digest()
    return f"{_b64e(body)}.{_b64e(sig)}"


def _token(scope: str, client_id: str = "gateway", jti: str = "jti-1") -> str:
    now = int(time.time())
    payload = {
        "iss": "token-service",
        "sub": client_id,
        "client_id": client_id,
        "aud": "internal-admin",
        "scope": scope,
        "iat": now,
        "exp": now + 30,
        "jti": jti,
    }
    return _sign(payload)


@pytest.fixture()
def module_and_client():
    spec = importlib.util.spec_from_file_location(
        "internal_admin_app_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.app.config.update(TESTING=True)
    with module.app.test_client() as client:
        yield module, client


def test_debug_config_requires_scope(module_and_client):
    _, client = module_and_client

    r = client.get("/debug/config")
    assert r.status_code == 403


def test_debug_config_allows_authorized_reader(module_and_client, monkeypatch):
    module, client = module_and_client
    monkeypatch.setattr(module, "_redis", lambda: FakeRedis())

    r = client.get(
        "/debug/config",
        headers={
            "Authorization": f"Bearer {_token('debug.config.read', jti='debug-jti')}"
        },
    )
    assert r.status_code == 200
    assert r.get_json()["service"] == module.REPLICA_NAME


def test_replay_detection_survives_local_state_loss(module_and_client, monkeypatch):
    module, client = module_and_client
    fake_redis = FakeRedis()
    monkeypatch.setattr(module, "_redis", lambda: fake_redis)
    token = _token("admin.export.read", jti="shared-jti")
    headers = {"Authorization": f"Bearer {token}"}

    first = client.get("/admin/export", headers=headers)
    used = getattr(module, "_USED", None)
    if isinstance(used, dict):
        used.clear()
    second = client.get("/admin/export", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 403
    assert second.get_json()["error"] == "replay detected"


def test_export_fails_closed_when_token_state_is_unavailable(
    module_and_client, monkeypatch
):
    module, client = module_and_client

    def broken_redis():
        raise RuntimeError("redis down")

    monkeypatch.setattr(module, "_redis", broken_redis)

    r = client.get(
        "/admin/export",
        headers={
            "Authorization": f"Bearer {_token('admin.export.read', jti='redis-down')}"
        },
    )
    assert r.status_code == 503
    assert r.get_json()["error"] == "token state unavailable"


def test_admin_export_rejects_unapproved_client(module_and_client, monkeypatch):
    module, client = module_and_client
    monkeypatch.setattr(module, "_redis", lambda: FakeRedis())

    r = client.get(
        "/admin/export",
        headers={
            "Authorization": f"Bearer {_token('admin.export.read', client_id='observer', jti='observer-jti')}"
        },
    )
    assert r.status_code == 403
    assert r.get_json()["error"] == "caller not permitted"
