import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from shared.auth import (
    canonical_json_bytes,
    new_jti,
    now_ts,
    sha256_hex,
    sign_payload,
    verify_payload,
)

MODULE_PATH = Path(__file__).resolve().parents[1] / "app.py"


class FakeRedis:
    def __init__(self):
        self.values = {}

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True


class FakeResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)
        self.headers = {"Content-Type": "application/json"}

    def json(self):
        return self._payload


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


def _query_hash(params: dict[str, str]) -> str:
    return sha256_hex(
        canonical_json_bytes({key: [value] for key, value in sorted(params.items())})
    )


def _operator_assertion(
    private_key_pem: str, path: str, params: dict[str, str], target: str
):
    now = now_ts()
    return sign_payload(
        {
            "iss": "ops-admin",
            "sub": "ops-admin",
            "aud": "mesh-operator-approval",
            "scope": "admin.export.read",
            "client_id": "gateway",
            "resource": "/admin/export",
            "target": target,
            "method": "GET",
            "path": path,
            "query_sha256": _query_hash(params),
            "body_sha256": sha256_hex(b""),
            "iat": now,
            "exp": now + 30,
            "jti": new_jti(),
        },
        private_key_pem,
    )


def _export_token(private_key_pem: str, target: str, operator_assertion: str):
    now = now_ts()
    return sign_payload(
        {
            "iss": "token-service",
            "sub": "gateway",
            "client_id": "gateway",
            "aud": "internal-admin",
            "scope": "admin.export.read",
            "target_replica": target,
            "actor": "ops-admin",
            "operator_assertion": operator_assertion,
            "iat": now,
            "exp": now + 30,
            "jti": new_jti(),
        },
        private_key_pem,
    )


def _response_proof(private_key_pem: str, body: dict, target: str, token_jti: str):
    now = now_ts()
    return sign_payload(
        {
            "iss": body["service"],
            "sub": body["service"],
            "aud": "gateway",
            "path": "/admin/export",
            "target_replica": target,
            "client_id": "gateway",
            "actor": "ops-admin",
            "token_jti": token_jti,
            "body_sha256": sha256_hex(canonical_json_bytes(body)),
            "iat": now,
            "exp": now + 60,
            "jti": new_jti(),
        },
        private_key_pem,
    )


@pytest.fixture()
def module_and_client(monkeypatch):
    gateway_private, _ = _keypair()
    operator_private, operator_public = _keypair()
    token_private, token_public = _keypair()
    admin_a_private, admin_a_public = _keypair()
    admin_b_private, admin_b_public = _keypair()
    monkeypatch.setenv("GATEWAY_CLIENT_PRIVATE_KEY_PEM", gateway_private)
    monkeypatch.setenv("OPERATOR_PUBLIC_KEY_PEM", operator_public)
    monkeypatch.setenv("ACCESS_TOKEN_PUBLIC_KEY_PEM", token_public)
    monkeypatch.setenv("TOKEN_AUDIENCE", "internal-admin")
    monkeypatch.setenv("GATEWAY_CLIENT_ID", "gateway")
    monkeypatch.setenv("OPERATOR_ASSERTION_AUDIENCE", "mesh-operator-approval")
    monkeypatch.setenv("ALLOWED_OPERATOR_IDS", "ops-admin")
    monkeypatch.setenv("INTERNAL_ADMIN_A_RESPONSE_PUBLIC_KEY_PEM", admin_a_public)
    monkeypatch.setenv("INTERNAL_ADMIN_B_RESPONSE_PUBLIC_KEY_PEM", admin_b_public)
    monkeypatch.setenv("RESPONSE_PROOF_AUDIENCE", "gateway")
    spec = importlib.util.spec_from_file_location("gateway_app_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.app.config.update(TESTING=True)
    fake_redis = FakeRedis()
    monkeypatch.setattr(module, "_redis", lambda: fake_redis)
    keys = {
        "operator_private": operator_private,
        "token_private": token_private,
        "admin_a_private": admin_a_private,
        "admin_b_private": admin_b_private,
    }
    with module.app.test_client() as client:
        yield module, client, keys


def test_export_rejects_minted_token_for_wrong_target(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    approval = _operator_assertion(
        keys["operator_private"], "/ops/export", {"target": "a"}, "a"
    )
    monkeypatch.setattr(
        module,
        "_token_service_post",
        lambda path, payload: FakeResponse(
            200,
            {
                "access_token": _export_token(
                    keys["token_private"], target="b", operator_assertion=approval
                )
            },
        ),
    )
    monkeypatch.setattr(
        module,
        "_request",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("unexpected upstream call")
        ),
    )

    r = client.get(
        "/ops/export",
        query_string={"target": "a"},
        headers={"X-Operator-Assertion": approval},
        environ_overrides={"operator_transport_verified": "1"},
    )

    assert r.status_code == 502
    assert r.get_json()["error"] == "wrong target replica"


def test_use_token_rejects_wrong_target_token(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    token = _export_token(
        keys["token_private"],
        target="b",
        operator_assertion=_operator_assertion(
            keys["operator_private"], "/ops/export", {"target": "b"}, "b"
        ),
    )
    params = {"target": "a", "token": token}
    approval = _operator_assertion(
        keys["operator_private"], "/ops/use-token", params, "a"
    )
    monkeypatch.setattr(
        module,
        "_request",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("unexpected upstream call")
        ),
    )

    r = client.get(
        "/ops/use-token",
        query_string=params,
        headers={"X-Operator-Assertion": approval},
        environ_overrides={"operator_transport_verified": "1"},
    )

    assert r.status_code == 403
    assert r.get_json()["error"] == "wrong target replica"


def test_use_token_rejects_replayed_operator_proof(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    params = {"target": "a", "token": "placeholder"}
    approval = _operator_assertion(
        keys["operator_private"], "/ops/use-token", params, "a"
    )
    monkeypatch.setattr(
        module,
        "_request",
        lambda *args, **kwargs: FakeResponse(403, {"error": "bad token signature"}),
    )

    first = client.get(
        "/ops/use-token",
        query_string=params,
        headers={"X-Operator-Assertion": approval},
        environ_overrides={"operator_transport_verified": "1"},
    )
    second = client.get(
        "/ops/use-token",
        query_string=params,
        headers={"X-Operator-Assertion": approval},
        environ_overrides={"operator_transport_verified": "1"},
    )

    assert first.status_code == 403
    assert second.status_code == 403
    assert second.get_json()["error"] == "operator proof replay"


def test_export_rejects_invalid_response_proof(module_and_client, monkeypatch):
    module, client, keys = module_and_client
    approval = _operator_assertion(
        keys["operator_private"], "/ops/export", {"target": "a"}, "a"
    )
    token = _export_token(
        keys["token_private"], target="a", operator_assertion=approval
    )
    unsigned_body = {
        "service": "internal-admin-a",
        "caller": "gateway",
        "actor": "ops-admin",
        "target_replica": "a",
        "records": 2,
        "users": [{"id": 1, "email": "alice@example.internal"}],
    }
    response_body = dict(unsigned_body)
    response_body["response_proof"] = _response_proof(
        keys["admin_b_private"],
        unsigned_body,
        "a",
        verify_payload(token, module.ACCESS_TOKEN_PUBLIC_KEY_PEM)["jti"],
    )
    monkeypatch.setattr(
        module,
        "_token_service_post",
        lambda path, payload: FakeResponse(200, {"access_token": token}),
    )
    monkeypatch.setattr(
        module,
        "_request",
        lambda *args, **kwargs: FakeResponse(200, response_body),
    )

    r = client.get(
        "/ops/export",
        query_string={"target": "a"},
        headers={"X-Operator-Assertion": approval},
        environ_overrides={"operator_transport_verified": "1"},
    )

    assert r.status_code == 502
    assert r.get_json()["error"] == "bad response proof"
