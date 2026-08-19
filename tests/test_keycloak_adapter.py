from pathlib import Path

import httpx
import pytest

from app.adapters import PermanentAdapterError
from app.keycloak import KeycloakAdminAdapter


def adapter(tmp_path: Path, handler=None):
    secret = tmp_path / "client-secret"
    secret.write_text("staging-secret")
    secret.chmod(0o600)
    client = None
    if handler:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return KeycloakAdminAdapter(
        base_url="http://keycloak:8080",
        realm="codestra",
        client_id="codestra-provisioning-service-staging",
        client_secret_file=str(secret),
        approved_group_prefixes=["/provisioning-staging/teams"],
        approved_realm_roles=["codestra_agent"],
        approved_client_roles={"codestra-agent-desktop": ["agent"]},
        client=client,
    )


def test_group_and_role_isolation(tmp_path):
    instance = adapter(tmp_path)
    instance._validate_entitlements(
        {
            "groups": ["/provisioning-staging/teams/team-1"],
            "realm_roles": ["codestra_agent"],
            "client_roles": {"codestra-agent-desktop": ["agent"]},
        }
    )
    with pytest.raises(PermanentAdapterError, match="keycloak_group_not_approved"):
        instance._validate_entitlements(
            {
                "groups": ["/privileged-mfa-required"],
                "realm_roles": [],
                "client_roles": {},
            }
        )
    with pytest.raises(PermanentAdapterError, match="keycloak_realm_role_not_approved"):
        instance._validate_entitlements(
            {"groups": [], "realm_roles": ["realm-admin"], "client_roles": {}}
        )
    with pytest.raises(PermanentAdapterError, match="keycloak_client_role_not_approved"):
        instance._validate_entitlements(
            {
                "groups": [],
                "realm_roles": [],
                "client_roles": {"realm-management": ["realm-admin"]},
            }
        )


@pytest.mark.asyncio
async def test_disabled_or_wrong_client_is_rejected(tmp_path):
    instance = adapter(
        tmp_path,
        lambda request: httpx.Response(
            401, json={"error": "invalid_client"}, request=request
        ),
    )
    with pytest.raises(
        PermanentAdapterError, match="keycloak_client_authentication_failed"
    ):
        await instance._token(instance.client)
    await instance.client.aclose()


@pytest.mark.asyncio
async def test_missing_admin_scope_is_sanitized(tmp_path):
    def handler(request):
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(
                200, json={"access_token": "opaque"}, request=request
            )
        return httpx.Response(403, json={}, request=request)

    instance = adapter(tmp_path, handler)
    with pytest.raises(PermanentAdapterError, match="keycloak_admin_scope_missing"):
        await instance._request("GET", "users")
    await instance.client.aclose()


def test_identity_attributes_never_contain_password(tmp_path):
    instance = adapter(tmp_path)
    attributes = instance._attributes(
        {
            "attributes": {
                "employee_id": "E-1",
                "company_id": "C-1",
                "business_unit_id": "BU-1",
                "department_id": "D-1",
                "team_id": "T-1",
                "supervisor_id": "S-1",
                "campaign_ids": ["CAM-1"],
                "role_template": "AGENT",
                "agent_desktop_roles": ["agent"],
            }
        },
        "idempotency",
    )
    assert "password" not in attributes
    assert attributes["lifecycle_state"] == ["activation_pending"]
