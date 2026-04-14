import importlib.util
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from shared.auth import canonical_json_bytes, new_jti, now_ts, sha256_hex, sign_payload

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


def _keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


def _client_assertion(
    private_key_pem: str, client_id: str, method: str, path: str, body: bytes
):
    now = now_ts()
    return sign_payload(
        {
            "iss": client_id,
            "sub": client_id,
            "aud": "token-service",
            "iat": now,
            "exp": now + 30,
            "jti": new_jti(),
            "method": method,
            "path": path,
            "body_sha256": sha256_hex(body),
        },
        private_key_pem,
    )


def _operator_assertion(
    private_key_pem: str, client_id: str = "gateway", target: str = "a"
):
    now = now_ts()
    return sign_payload(
        {
            "iss": "ops-admin",
            "sub": "ops-admin",
            "aud": "mesh-operator-approval",
            "scope": "admin.export.read",
            "client_id": client_id,
            "resource": "/admin/export",
            "target": target,
            "iat": now,
            "exp": now + 30,
            "jti": new_jti(),
        },
        private_key_pem,
    )


@pytest.fixture()
def module_and_client(monkeypatch):
    gateway_private, gateway_public = _keypair()
    observer_private, observer_public = _keypair()
    operator_private, operator_public = _keypair()
    token_private, _ = _keypair()
    monkeypatch.setenv("GATEWAY_CLIENT_PUBLIC_KEY_PEM", gateway_public)
    monkeypatch.setenv("OBSERVER_CLIENT_PUBLIC_KEY_PEM", observer_public)
    monkeypatch.setenv("OPERATOR_PUBLIC_KEY_PEM", operator_public)
    monkeypatch.setenv("ACCESS_TOKEN_PRIVATE_KEY_PEM", token_private)
    monkeypatch.setenv("SERVICE_ASSERTION_AUDIENCE", "token-service")
    monkeypatch.setenv("OPERATOR_ASSERTION_AUDIENCE", "mesh-operator-approval")
    monkeypatch.setenv("ALLOWED_OPERATOR_IDS", "ops-admin")
    spec = importlib.util.spec_from_file_location("token_service_app_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.app.config.update(TESTING=True)
    keys = {
        "gateway_private": gateway_private,
        "observer_private": observer_private,
        "operator_private": operator_private,
    }
    with module.app.test_client() as client:
        yield module, client, keys


def test_mesh_requires_authorized_discovery_client(module_and_client):
    _, client, keys = module_and_client
    gateway_headers = {
        "X-Client-Id": "gateway",
        "X-Client-Assertion": _client_assertion(
            keys["gateway_private"], "gateway", "GET", "/.well-known/mesh", b""
        ),
    }
    observer_headers = {
        "X-Client-Id": "observer",
        "X-Client-Assertion": _client_assertion(
            keys["observer_private"], "observer", "GET", "/.well-known/mesh", b""
        ),
    }

    blocked = client.get("/.well-known/mesh", headers=gateway_headers)
    allowed = client.get("/.well-known/mesh", headers=observer_headers)

    assert blocked.status_code == 403
    assert blocked.get_json()["error"] == "discovery not permitted"
    assert allowed.status_code == 200
    assert allowed.get_json()["client_id"] == "observer"


def test_client_assertion_replay_is_blocked(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    fake_redis = FakeRedis()
    monkeypatch.setattr(module, "_redis", lambda: fake_redis)
    body = canonical_json_bytes(
        {"audience": "internal-admin", "scope": "debug.config.read"}
    )
    assertion = _client_assertion(
        keys["observer_private"], "observer", "POST", "/v1/mint", body
    )
    headers = {
        "Content-Type": "application/json",
        "X-Client-Id": "observer",
        "X-Client-Assertion": assertion,
    }

    first = client.post("/v1/mint", data=body, headers=headers)
    second = client.post("/v1/mint", data=body, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 403
    assert second.get_json()["error"] == "client assertion replay"


def test_gateway_export_requires_operator_approval(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    monkeypatch.setattr(module, "_redis", lambda: FakeRedis())
    body = canonical_json_bytes(
        {
            "audience": "internal-admin",
            "scope": "admin.export.read",
            "target_replica": "a",
        }
    )

    r = client.post(
        "/v1/mint",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Client-Id": "gateway",
            "X-Client-Assertion": _client_assertion(
                keys["gateway_private"], "gateway", "POST", "/v1/mint", body
            ),
        },
    )
    assert r.status_code == 403
    assert r.get_json()["error"] == "operator approval required"


def test_operator_approval_replay_is_blocked(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    fake_redis = FakeRedis()
    monkeypatch.setattr(module, "_redis", lambda: fake_redis)
    approval = _operator_assertion(keys["operator_private"], target="a")
    body = canonical_json_bytes(
        {
            "audience": "internal-admin",
            "scope": "admin.export.read",
            "operator_assertion": approval,
            "target_replica": "a",
        }
    )

    first = client.post(
        "/v1/mint",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Client-Id": "gateway",
            "X-Client-Assertion": _client_assertion(
                keys["gateway_private"], "gateway", "POST", "/v1/mint", body
            ),
        },
    )
    second = client.post(
        "/v1/mint",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Client-Id": "gateway",
            "X-Client-Assertion": _client_assertion(
                keys["gateway_private"], "gateway", "POST", "/v1/mint", body
            ),
        },
    )

    assert first.status_code == 200
    assert second.status_code == 403
    assert second.get_json()["error"] == "operator approval replay"


def test_operator_target_mismatch_is_rejected(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    monkeypatch.setattr(module, "_redis", lambda: FakeRedis())
    approval = _operator_assertion(keys["operator_private"], target="a")
    body = canonical_json_bytes(
        {
            "audience": "internal-admin",
            "scope": "admin.export.read",
            "operator_assertion": approval,
            "target_replica": "b",
        }
    )

    r = client.post(
        "/v1/mint",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Client-Id": "gateway",
            "X-Client-Assertion": _client_assertion(
                keys["gateway_private"], "gateway", "POST", "/v1/mint", body
            ),
        },
    )
    assert r.status_code == 403
    assert r.get_json()["error"] == "operator target mismatch"


def test_mint_fails_closed_when_redis_is_unavailable(module_and_client, monkeypatch):
    module, client, keys = module_and_client

    def broken_redis():
        raise RuntimeError("redis down")

    monkeypatch.setattr(module, "_redis", broken_redis)
    body = canonical_json_bytes(
        {"audience": "internal-admin", "scope": "debug.config.read"}
    )

    r = client.post(
        "/v1/mint",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Client-Id": "observer",
            "X-Client-Assertion": _client_assertion(
                keys["observer_private"], "observer", "POST", "/v1/mint", body
            ),
        },
    )
    assert r.status_code == 503
    assert r.get_json()["error"] == "redis unavailable"
