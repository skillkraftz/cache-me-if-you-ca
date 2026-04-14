import os
import tempfile
from pathlib import Path

import pytest
import requests

from shared.auth import (
    canonical_json_bytes,
    new_jti,
    now_ts,
    sha256_hex,
    sign_payload,
    verify_payload,
)

GATEWAY_BASE = "http://gateway:5000"
GATEWAY_OPERATOR_BASE = "https://gateway:5443"
TOKEN_SERVICE_BASE = "http://token-service:5003"
ADMIN_A_BASE = "http://internal-admin-a:5001"
ADMIN_B_BASE = "http://internal-admin-b:5001"
GATEWAY_CLIENT_PRIVATE_KEY_PEM = os.environ["GATEWAY_CLIENT_PRIVATE_KEY_PEM"]
OBSERVER_CLIENT_PRIVATE_KEY_PEM = os.environ["OBSERVER_CLIENT_PRIVATE_KEY_PEM"]
OPERATOR_PRIVATE_KEY_PEM = os.environ["OPERATOR_PRIVATE_KEY_PEM"]
SERVICE_ASSERTION_AUDIENCE = os.getenv("SERVICE_ASSERTION_AUDIENCE", "token-service")
OPERATOR_ASSERTION_AUDIENCE = os.getenv(
    "OPERATOR_ASSERTION_AUDIENCE", "mesh-operator-approval"
)
RESPONSE_PROOF_AUDIENCE = os.getenv("RESPONSE_PROOF_AUDIENCE", "gateway")
ADMIN_A_RESPONSE_PUBLIC_KEY_PEM = os.environ["INTERNAL_ADMIN_A_RESPONSE_PUBLIC_KEY_PEM"]
ADMIN_B_RESPONSE_PUBLIC_KEY_PEM = os.environ["INTERNAL_ADMIN_B_RESPONSE_PUBLIC_KEY_PEM"]
GATEWAY_TLS_CA_CERT_PEM = os.environ["GATEWAY_TLS_CA_CERT_PEM"]
OPERATOR_CLIENT_CERT_PEM = os.environ["OPERATOR_CLIENT_CERT_PEM"]
OPERATOR_CLIENT_KEY_PEM = os.environ["OPERATOR_CLIENT_KEY_PEM"]

_CERT_DIR = Path(tempfile.mkdtemp(prefix="cache-me-if-you-ca-tester-mtls-"))


def _write_pem(name: str, content: str) -> str:
    path = _CERT_DIR / name
    path.write_text(content, encoding="utf-8")
    return str(path)


GATEWAY_TLS_CA_CERT_FILE = _write_pem("gateway-ca.crt", GATEWAY_TLS_CA_CERT_PEM)
OPERATOR_CLIENT_CERT_FILE = _write_pem("operator-client.crt", OPERATOR_CLIENT_CERT_PEM)
OPERATOR_CLIENT_KEY_FILE = _write_pem("operator-client.key", OPERATOR_CLIENT_KEY_PEM)


def _operator_tls_kwargs():
    return {
        "verify": GATEWAY_TLS_CA_CERT_FILE,
        "cert": (OPERATOR_CLIENT_CERT_FILE, OPERATOR_CLIENT_KEY_FILE),
    }


def _operator_get(path: str, params: dict[str, str], proof: str):
    return requests.get(
        f"{GATEWAY_OPERATOR_BASE}{path}",
        params=params,
        headers={"X-Operator-Assertion": proof},
        timeout=5,
        **_operator_tls_kwargs(),
    )


def _gateway_query_hash(params: dict[str, str]) -> str:
    return sha256_hex(
        canonical_json_bytes({key: [value] for key, value in sorted(params.items())})
    )


def _operator_assertion(
    path: str, params: dict[str, str], target: str, client_id: str = "gateway"
):
    now = now_ts()
    return sign_payload(
        {
            "iss": "ops-admin",
            "sub": "ops-admin",
            "aud": OPERATOR_ASSERTION_AUDIENCE,
            "scope": "admin.export.read",
            "client_id": client_id,
            "resource": "/admin/export",
            "target": target,
            "method": "GET",
            "path": path,
            "query_sha256": _gateway_query_hash(params),
            "body_sha256": sha256_hex(b""),
            "iat": now,
            "exp": now + 30,
            "jti": new_jti(),
        },
        OPERATOR_PRIVATE_KEY_PEM,
    )


def _mint_operator_assertion(client_id: str = "gateway", target: str = "a"):
    now = now_ts()
    return sign_payload(
        {
            "iss": "ops-admin",
            "sub": "ops-admin",
            "aud": OPERATOR_ASSERTION_AUDIENCE,
            "scope": "admin.export.read",
            "client_id": client_id,
            "resource": "/admin/export",
            "target": target,
            "iat": now,
            "exp": now + 30,
            "jti": new_jti(),
        },
        OPERATOR_PRIVATE_KEY_PEM,
    )


def _client_assertion(
    private_key_pem: str, client_id: str, method: str, path: str, body: bytes
):
    now = now_ts()
    return sign_payload(
        {
            "iss": client_id,
            "sub": client_id,
            "aud": SERVICE_ASSERTION_AUDIENCE,
            "iat": now,
            "exp": now + 30,
            "jti": new_jti(),
            "method": method,
            "path": path,
            "body_sha256": sha256_hex(body),
        },
        private_key_pem,
    )


def _mint(
    scope: str,
    client_id: str,
    private_key_pem: str,
    operator_assertion: str | None = None,
    target_replica: str | None = None,
):
    payload = {"audience": "internal-admin", "scope": scope}
    if operator_assertion is not None:
        payload["operator_assertion"] = operator_assertion
    if target_replica is not None:
        payload["target_replica"] = target_replica
    body = canonical_json_bytes(payload)
    return requests.post(
        f"{TOKEN_SERVICE_BASE}/v1/mint",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Client-Id": client_id,
            "X-Client-Assertion": _client_assertion(
                private_key_pem, client_id, "POST", "/v1/mint", body
            ),
        },
        timeout=5,
    )


def _verify_response_proof(body: dict, public_key_pem: str, expected_target: str):
    proof = body["response_proof"]
    payload = verify_payload(proof, public_key_pem)
    assert payload is not None
    assert payload["aud"] == RESPONSE_PROOF_AUDIENCE
    assert payload["path"] == "/admin/export"
    assert payload["target_replica"] == expected_target
    unsigned = dict(body)
    unsigned.pop("response_proof", None)
    assert payload["body_sha256"] == sha256_hex(canonical_json_bytes(unsigned))


def test_ops_export_still_works_with_operator_assertion():
    params = {"target": "a"}
    r = _operator_get(
        "/ops/export", params, _operator_assertion("/ops/export", params, "a")
    )
    assert r.status_code == 200
    assert r.json()["service"] == "internal-admin-a"
    _verify_response_proof(r.json(), ADMIN_A_RESPONSE_PUBLIC_KEY_PEM, "a")


def test_compromised_gateway_cannot_mint_export_without_operator_approval():
    r = _mint("admin.export.read", "gateway", GATEWAY_CLIENT_PRIVATE_KEY_PEM)
    assert r.status_code == 403
    assert r.json()["error"] == "operator approval required"


def test_compromised_gateway_cannot_mint_observer_scopes():
    r = _mint("debug.config.read", "gateway", GATEWAY_CLIENT_PRIVATE_KEY_PEM)
    assert r.status_code == 403
    assert r.json()["error"] == "scope not permitted"


def test_gateway_cannot_query_token_discovery_with_service_identity_alone():
    r = requests.get(
        f"{TOKEN_SERVICE_BASE}/.well-known/mesh",
        headers={
            "X-Client-Id": "gateway",
            "X-Client-Assertion": _client_assertion(
                GATEWAY_CLIENT_PRIVATE_KEY_PEM,
                "gateway",
                "GET",
                "/.well-known/mesh",
                b"",
            ),
        },
        timeout=5,
    )
    assert r.status_code == 403
    assert r.json()["error"] == "discovery not permitted"


def test_operator_approval_is_single_use_for_token_minting():
    approval = _mint_operator_assertion(target="a")
    first = _mint(
        "admin.export.read",
        "gateway",
        GATEWAY_CLIENT_PRIVATE_KEY_PEM,
        approval,
        target_replica="a",
    )
    second = _mint(
        "admin.export.read",
        "gateway",
        GATEWAY_CLIENT_PRIVATE_KEY_PEM,
        approval,
        target_replica="a",
    )
    assert first.status_code == 200
    assert second.status_code == 403
    assert second.json()["error"] == "operator approval replay"


def test_same_export_token_cannot_be_replayed_across_replicas():
    approval = _mint_operator_assertion(target="a")
    mint = _mint(
        "admin.export.read",
        "gateway",
        GATEWAY_CLIENT_PRIVATE_KEY_PEM,
        approval,
        target_replica="a",
    )
    assert mint.status_code == 200
    token = mint.json()["access_token"]

    first = requests.get(
        f"{ADMIN_A_BASE}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    second = requests.get(
        f"{ADMIN_B_BASE}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )

    assert first.status_code == 200
    assert second.status_code == 403


def test_operator_approval_cannot_be_redirected_to_other_replica():
    params = {"target": "b"}
    r = _operator_get(
        "/ops/export",
        params,
        _operator_assertion("/ops/export", {"target": "a"}, "a"),
    )
    assert r.status_code == 403
    assert r.json()["error"] == "operator target mismatch"


def test_export_token_is_bound_to_target_replica():
    approval = _mint_operator_assertion(target="a")
    mint = _mint(
        "admin.export.read",
        "gateway",
        GATEWAY_CLIENT_PRIVATE_KEY_PEM,
        approval,
        target_replica="a",
    )
    assert mint.status_code == 200
    token = mint.json()["access_token"]

    r = requests.get(
        f"{ADMIN_B_BASE}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code == 403
    assert r.json()["error"] == "wrong target replica"


def test_operator_proof_is_single_use_at_gateway():
    params = {"target": "a"}
    proof = _operator_assertion("/ops/export", params, "a")

    first = _operator_get("/ops/export", params, proof)
    second = _operator_get("/ops/export", params, proof)

    assert first.status_code == 200
    assert second.status_code == 403
    assert second.json()["error"] == "operator proof replay"


def test_operator_proof_cannot_be_rebound_to_use_token_request():
    export_params = {"target": "a"}
    proof = _operator_assertion("/ops/export", export_params, "a")

    r = _operator_get("/ops/use-token", {"target": "a", "token": "placeholder"}, proof)

    assert r.status_code == 403
    assert r.json()["error"] == "operator request mismatch"


def test_operator_routes_require_mtls_transport():
    params = {"target": "a"}
    proof = _operator_assertion("/ops/export", params, "a")
    r = requests.get(
        f"{GATEWAY_BASE}/ops/export",
        params=params,
        headers={"X-Operator-Assertion": proof},
        timeout=5,
    )
    assert r.status_code == 403
    assert r.json()["error"] == "mTLS required"


def test_operator_tls_without_client_cert_is_rejected():
    params = {"target": "a"}
    proof = _operator_assertion("/ops/export", params, "a")
    with pytest.raises(requests.exceptions.SSLError):
        requests.get(
            f"{GATEWAY_OPERATOR_BASE}/ops/export",
            params=params,
            headers={"X-Operator-Assertion": proof},
            timeout=5,
            verify=GATEWAY_TLS_CA_CERT_FILE,
        )


def test_observer_can_still_read_debug_config():
    mint = _mint("debug.config.read", "observer", OBSERVER_CLIENT_PRIVATE_KEY_PEM)
    assert mint.status_code == 200
    token = mint.json()["access_token"]

    r = requests.get(
        f"{ADMIN_A_BASE}/debug/config",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code == 200
    assert r.json()["service"] == "internal-admin-a"
