import os

import requests

from shared.auth import canonical_json_bytes, new_jti, now_ts, sha256_hex, sign_payload

GATEWAY_BASE = "http://gateway:5000"
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


def _operator_assertion(client_id: str = "gateway", target: str = "a"):
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


def test_ops_export_still_works_with_operator_assertion():
    r = requests.get(
        f"{GATEWAY_BASE}/ops/export",
        params={"target": "a"},
        headers={"X-Operator-Assertion": _operator_assertion(target="a")},
        timeout=5,
    )
    assert r.status_code == 200
    assert r.json()["service"] == "internal-admin-a"


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
    approval = _operator_assertion(target="a")
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
    approval = _operator_assertion(target="a")
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
    r = requests.get(
        f"{GATEWAY_BASE}/ops/export",
        params={"target": "b"},
        headers={"X-Operator-Assertion": _operator_assertion(target="a")},
        timeout=5,
    )
    assert r.status_code == 403
    assert r.json()["error"] == "operator target mismatch"


def test_export_token_is_bound_to_target_replica():
    approval = _operator_assertion(target="a")
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
