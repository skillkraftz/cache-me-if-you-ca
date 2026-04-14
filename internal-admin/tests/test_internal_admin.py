import importlib.util
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from shared.auth import new_jti, now_ts, sign_payload

MODULE_PATH = Path(__file__).resolve().parents[1] / "app.py"


class FakeRedis:
    def __init__(self):
        self.values = {}

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = value
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


def _access_token(
    private_key_pem: str,
    scope: str,
    client_id: str = "gateway",
    audience: str = "internal-admin",
    operator_assertion: str | None = None,
    actor: str | None = None,
    target_replica: str | None = None,
    jti: str | None = None,
):
    now = now_ts()
    payload = {
        "iss": "token-service",
        "sub": client_id,
        "client_id": client_id,
        "aud": audience,
        "scope": scope,
        "iat": now,
        "exp": now + 30,
        "jti": jti or new_jti(),
    }
    if operator_assertion is not None:
        payload["operator_assertion"] = operator_assertion
    if actor is not None:
        payload["actor"] = actor
    if target_replica is not None:
        payload["target_replica"] = target_replica
    return sign_payload(payload, private_key_pem)


@pytest.fixture()
def module_and_client(monkeypatch):
    token_private, token_public = _keypair()
    operator_private, operator_public = _keypair()
    response_private, response_public = _keypair()
    wrong_private, _ = _keypair()
    monkeypatch.setenv("ACCESS_TOKEN_PUBLIC_KEY_PEM", token_public)
    monkeypatch.setenv("RESPONSE_SIGNING_PRIVATE_KEY_PEM", response_private)
    monkeypatch.setenv("RESPONSE_PROOF_AUDIENCE", "gateway")
    monkeypatch.setenv("OPERATOR_PUBLIC_KEY_PEM", operator_public)
    monkeypatch.setenv("TOKEN_AUDIENCE", "internal-admin")
    monkeypatch.setenv("REPLICA_TARGET", "a")
    monkeypatch.setenv("OPERATOR_ASSERTION_AUDIENCE", "mesh-operator-approval")
    monkeypatch.setenv("ALLOWED_OPERATOR_IDS", "ops-admin")
    spec = importlib.util.spec_from_file_location(
        "internal_admin_app_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.app.config.update(TESTING=True)
    keys = {
        "token_private": token_private,
        "operator_private": operator_private,
        "response_public": response_public,
        "wrong_private": wrong_private,
    }
    with module.app.test_client() as client:
        yield module, client, keys


def test_debug_config_requires_observer_scope(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    monkeypatch.setattr(module, "_redis", lambda: FakeRedis())
    token = _access_token(
        keys["token_private"], "debug.config.read", client_id="observer"
    )

    r = client.get("/debug/config", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.get_json()["service"]


def test_wrong_access_token_signer_is_rejected(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    monkeypatch.setattr(module, "_redis", lambda: FakeRedis())
    token = _access_token(
        keys["wrong_private"], "debug.config.read", client_id="observer"
    )

    r = client.get("/debug/config", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.get_json()["error"] == "bad token signature"


def test_wrong_audience_is_rejected(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    monkeypatch.setattr(module, "_redis", lambda: FakeRedis())
    token = _access_token(
        keys["token_private"],
        "debug.config.read",
        client_id="observer",
        audience="wrong-audience",
    )

    r = client.get("/debug/config", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.get_json()["error"] == "bad audience"


def test_wrong_scope_is_rejected(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    monkeypatch.setattr(module, "_redis", lambda: FakeRedis())
    token = _access_token(
        keys["token_private"], "debug.config.read", client_id="observer"
    )

    r = client.get("/internal/metrics", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.get_json()["error"] == "missing required scope"


def test_export_requires_operator_approval(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    monkeypatch.setattr(module, "_redis", lambda: FakeRedis())
    token = _access_token(keys["token_private"], "admin.export.read")

    r = client.get("/admin/export", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.get_json()["error"] == "missing operator approval"


def test_export_rejects_invalid_nested_operator_assertion(
    module_and_client, monkeypatch
):
    module, client, keys = module_and_client
    monkeypatch.setattr(module, "_redis", lambda: FakeRedis())
    bogus_approval = _operator_assertion(keys["wrong_private"], target="a")
    token = _access_token(
        keys["token_private"],
        "admin.export.read",
        operator_assertion=bogus_approval,
        actor="ops-admin",
        target_replica="a",
    )

    r = client.get("/admin/export", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.get_json()["error"] == "bad operator assertion"


def test_operator_approval_replay_blocks_multiple_tokens(
    module_and_client, monkeypatch
):
    module, client, keys = module_and_client
    fake_redis = FakeRedis()
    monkeypatch.setattr(module, "_redis", lambda: fake_redis)
    approval = _operator_assertion(keys["operator_private"], target="a")
    first_token = _access_token(
        keys["token_private"],
        "admin.export.read",
        operator_assertion=approval,
        actor="ops-admin",
        target_replica="a",
        jti="token-a",
    )
    second_token = _access_token(
        keys["token_private"],
        "admin.export.read",
        operator_assertion=approval,
        actor="ops-admin",
        target_replica="a",
        jti="token-b",
    )

    first = client.get(
        "/admin/export", headers={"Authorization": f"Bearer {first_token}"}
    )
    second = client.get(
        "/admin/export", headers={"Authorization": f"Bearer {second_token}"}
    )

    assert first.status_code == 200
    assert second.status_code == 403
    assert second.get_json()["error"] == "operator approval replay"


def test_export_rejects_wrong_target_replica(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    monkeypatch.setattr(module, "_redis", lambda: FakeRedis())
    approval = _operator_assertion(keys["operator_private"], target="a")
    token = _access_token(
        keys["token_private"],
        "admin.export.read",
        operator_assertion=approval,
        actor="ops-admin",
        target_replica="b",
    )

    r = client.get("/admin/export", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.get_json()["error"] == "wrong target replica"
