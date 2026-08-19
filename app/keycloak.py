import hashlib
import json
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .adapters import (
    PermanentAdapterError,
    ProvisioningAdapter,
    RetryableAdapterError,
)
from .contracts import StepCommand
from .secrets import read_secret_file

IDENTITY_ATTRIBUTES = {
    "employee_id",
    "company_id",
    "business_unit_id",
    "department_id",
    "team_id",
    "supervisor_id",
    "campaign_ids",
    "role_template",
    "agent_desktop_roles",
}
REQUIRED_ACTIONS = {"UPDATE_PASSWORD", "CONFIGURE_TOTP"}


class KeycloakAdminAdapter(ProvisioningAdapter):
    """Staging-only Keycloak Admin REST adapter with explicit entitlement allowlists."""

    def __init__(
        self,
        base_url: str,
        realm: str,
        client_id: str,
        client_secret_file: str,
        approved_group_prefixes: list[str],
        approved_realm_roles: list[str],
        approved_client_roles: dict[str, list[str]],
        activation_clients: dict[str, list[str]] | None = None,
        client: httpx.AsyncClient | None = None,
    ):
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            raise ValueError("invalid Keycloak URL")
        if parsed.scheme == "http" and parsed.hostname not in {
            "keycloak",
            "localhost",
            "127.0.0.1",
        }:
            raise ValueError("plaintext Keycloak URL is restricted to the private staging network")
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret_file = client_secret_file
        self.group_prefixes = tuple(prefix.rstrip("/") + "/" for prefix in approved_group_prefixes)
        self.realm_roles = frozenset(approved_realm_roles)
        self.client_roles = {
            name: frozenset(roles) for name, roles in approved_client_roles.items()
        }
        self.activation_clients = activation_clients or {}
        self.client = client

    async def _owned_client(self):
        return self.client or httpx.AsyncClient(
            timeout=httpx.Timeout(15, connect=3), follow_redirects=False
        )

    async def _token(self, client: httpx.AsyncClient) -> str:
        try:
            response = await client.post(
                f"{self.base_url}/realms/{quote(self.realm)}/protocol/openid-connect/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": read_secret_file(self.client_secret_file),
                },
            )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise RetryableAdapterError("keycloak_token_transport_unavailable") from exc
        if response.status_code in {408, 425, 429} or response.status_code >= 500:
            raise RetryableAdapterError("keycloak_token_unavailable")
        if response.status_code != 200:
            raise PermanentAdapterError("keycloak_client_authentication_failed")
        token = response.json().get("access_token")
        if not isinstance(token, str):
            raise PermanentAdapterError("keycloak_token_invalid")
        return token

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        expected: tuple[int, ...] = (200,),
    ) -> httpx.Response:
        owned = self.client is None
        client = await self._owned_client()
        try:
            token = await self._token(client)
            response = await client.request(
                method,
                f"{self.base_url}/admin/realms/{quote(self.realm)}/{path.lstrip('/')}",
                params=params,
                json=json_body,
                headers={"Authorization": f"Bearer {token}"},
            )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise RetryableAdapterError("keycloak_admin_transport_unavailable") from exc
        finally:
            if owned:
                await client.aclose()
        if response.status_code in {408, 425, 429} or response.status_code >= 500:
            raise RetryableAdapterError(f"keycloak_admin_http_{response.status_code}")
        if response.status_code == 403:
            raise PermanentAdapterError("keycloak_admin_scope_missing")
        if response.status_code not in expected:
            raise PermanentAdapterError(f"keycloak_admin_http_{response.status_code}")
        return response

    @staticmethod
    def _attributes(payload: dict[str, Any], idempotency_key: str) -> dict[str, list[str]]:
        raw = payload.get("attributes")
        if not isinstance(raw, dict):
            raise PermanentAdapterError("keycloak_identity_attributes_required")
        missing = IDENTITY_ATTRIBUTES - set(raw)
        if missing:
            raise PermanentAdapterError("keycloak_identity_attributes_incomplete")
        attributes: dict[str, list[str]] = {}
        for key in IDENTITY_ATTRIBUTES:
            value = raw[key]
            values = value if isinstance(value, list) else [value]
            if not values or any(not isinstance(item, str | int) for item in values):
                raise PermanentAdapterError("keycloak_identity_attribute_invalid")
            attributes[key] = [str(item) for item in values]
        attributes["provisioning_idempotency_key"] = [idempotency_key]
        attributes["lifecycle_state"] = ["activation_pending"]
        return attributes

    def _validate_entitlements(self, payload: dict[str, Any]):
        groups = payload.get("groups", [])
        realm_roles = payload.get("realm_roles", [])
        client_roles = payload.get("client_roles", {})
        if not isinstance(groups, list) or any(
            not isinstance(path, str)
            or not any(path.startswith(prefix) for prefix in self.group_prefixes)
            for path in groups
        ):
            raise PermanentAdapterError("keycloak_group_not_approved")
        if not isinstance(realm_roles, list) or not set(realm_roles) <= self.realm_roles:
            raise PermanentAdapterError("keycloak_realm_role_not_approved")
        if not isinstance(client_roles, dict):
            raise PermanentAdapterError("keycloak_client_role_not_approved")
        for client_id, roles in client_roles.items():
            if (
                client_id not in self.client_roles
                or not isinstance(roles, list)
                or not set(roles) <= self.client_roles[client_id]
            ):
                raise PermanentAdapterError("keycloak_client_role_not_approved")

    async def _find(self, username: str | None = None, employee_id: str | None = None):
        params: dict[str, str] = {"max": "20"}
        if username:
            params.update({"username": username, "exact": "true"})
        elif employee_id:
            params["q"] = f"employee_id:{employee_id}"
        response = await self._request("GET", "users", params=params)
        users = response.json()
        if not isinstance(users, list):
            raise PermanentAdapterError("keycloak_user_search_invalid")
        return users

    async def _user_for_command(self, command: StepCommand) -> dict[str, Any]:
        users = await self._find(employee_id=command.employee_id)
        if len(users) != 1:
            raise PermanentAdapterError(
                "keycloak_identity_not_found" if not users else "keycloak_duplicate_identity"
            )
        return users[0]

    async def _group(self, path: str) -> dict[str, Any]:
        response = await self._request(
            "GET", f"group-by-path/{quote(path, safe='')}"
        )
        return response.json()

    async def _client_by_id(self, client_id: str) -> dict[str, Any]:
        response = await self._request(
            "GET", "clients", params={"clientId": client_id}
        )
        clients = response.json()
        if not isinstance(clients, list) or len(clients) != 1:
            raise PermanentAdapterError("keycloak_entitlement_client_not_found")
        return clients[0]

    async def _apply_entitlements(
        self, user_id: str, payload: dict[str, Any]
    ):
        self._validate_entitlements(payload)
        for path in payload.get("groups", []):
            group = await self._group(path)
            await self._request(
                "PUT", f"users/{user_id}/groups/{group['id']}", expected=(204,)
            )
        realm_roles = []
        for name in payload.get("realm_roles", []):
            realm_roles.append(
                (await self._request("GET", f"roles/{quote(name)}")).json()
            )
        if realm_roles:
            await self._request(
                "POST",
                f"users/{user_id}/role-mappings/realm",
                json_body=realm_roles,
                expected=(204,),
            )
        for client_id, names in payload.get("client_roles", {}).items():
            target = await self._client_by_id(client_id)
            roles = [
                (
                    await self._request(
                        "GET", f"clients/{target['id']}/roles/{quote(name)}"
                    )
                ).json()
                for name in names
            ]
            if roles:
                await self._request(
                    "POST",
                    f"users/{user_id}/role-mappings/clients/{target['id']}",
                    json_body=roles,
                    expected=(204,),
                )

    @staticmethod
    def _result(user_id: str, state: str, evidence: dict[str, Any] | None = None):
        document = evidence or {"state": state}
        return {
            "state": state,
            "external_id": user_id,
            "external_reference": state,
            "response_hash": hashlib.sha256(
                json.dumps(document, sort_keys=True, default=str).encode()
            ).hexdigest(),
        }

    async def create_disabled(self, command: StepCommand) -> dict[str, Any]:
        payload = command.payload
        username = payload.get("username")
        if not isinstance(username, str) or not username:
            raise PermanentAdapterError("keycloak_username_required")
        self._validate_entitlements(payload)
        same_username = await self._find(username=username)
        if same_username:
            keys = same_username[0].get("attributes", {}).get(
                "provisioning_idempotency_key", []
            )
            if command.idempotency_key in keys:
                return self._result(same_username[0]["id"], "activation_pending")
            raise PermanentAdapterError("keycloak_duplicate_username")
        same_identity = await self._find(employee_id=command.employee_id)
        if same_identity:
            raise PermanentAdapterError("keycloak_duplicate_identity")
        attributes = self._attributes(payload, command.idempotency_key)
        representation = {
            "username": username,
            "email": payload.get("email"),
            "firstName": payload.get("first_name"),
            "lastName": payload.get("last_name"),
            "enabled": False,
            "emailVerified": False,
            "requiredActions": sorted(REQUIRED_ACTIONS),
            "attributes": attributes,
        }
        response = await self._request(
            "POST", "users", json_body=representation, expected=(201,)
        )
        location = response.headers.get("location", "")
        user_id = location.rstrip("/").rsplit("/", 1)[-1]
        if not user_id:
            created = await self._find(username=username)
            if len(created) != 1:
                raise PermanentAdapterError("keycloak_created_user_not_found")
            user_id = created[0]["id"]
        await self._apply_entitlements(user_id, payload)
        return self._result(user_id, "activation_pending")

    async def update(self, command: StepCommand) -> dict[str, Any]:
        user = await self._user_for_command(command)
        self._validate_entitlements(command.payload)
        representation: dict[str, Any] = {}
        if "attributes" in command.payload:
            representation["attributes"] = self._attributes(
                command.payload, command.idempotency_key
            )
        for source, target in (
            ("email", "email"), ("first_name", "firstName"), ("last_name", "lastName")
        ):
            if source in command.payload:
                representation[target] = command.payload[source]
        if representation:
            await self._request(
                "PUT", f"users/{user['id']}", json_body=representation, expected=(204,)
            )
        await self._apply_entitlements(user["id"], command.payload)
        return self._result(user["id"], "updated")

    async def activate(self, command: StepCommand) -> dict[str, Any]:
        user = await self._user_for_command(command)
        actions = sorted(REQUIRED_ACTIONS)
        await self._request(
            "PUT",
            f"users/{user['id']}",
            json_body={
                "enabled": True,
                "requiredActions": actions,
                "attributes": {
                    **user.get("attributes", {}),
                    "lifecycle_state": ["activation_pending"],
                },
            },
            expected=(204,),
        )
        if command.payload.get("send_activation_link"):
            client_id = command.payload.get("activation_client")
            redirect_uri = command.payload.get("redirect_uri")
            if (
                client_id not in self.activation_clients
                or redirect_uri not in self.activation_clients[client_id]
            ):
                raise PermanentAdapterError("keycloak_activation_redirect_not_approved")
            await self._request(
                "PUT",
                f"users/{user['id']}/execute-actions-email",
                params={
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "lifespan": "900",
                },
                json_body=actions,
                expected=(204,),
            )
        return self._result(user["id"], "awaiting_required_actions")

    async def _set_enabled(
        self, command: StepCommand, enabled: bool, lifecycle_state: str
    ) -> dict[str, Any]:
        user = await self._user_for_command(command)
        await self._request(
            "PUT",
            f"users/{user['id']}",
            json_body={
                "enabled": enabled,
                "attributes": {
                    **user.get("attributes", {}),
                    "lifecycle_state": [lifecycle_state],
                },
            },
            expected=(204,),
        )
        if not enabled:
            await self._request("POST", f"users/{user['id']}/logout", expected=(204,))
        return self._result(user["id"], lifecycle_state)

    async def suspend(self, command: StepCommand) -> dict[str, Any]:
        return await self._set_enabled(command, False, "suspended")

    async def reactivate(self, command: StepCommand) -> dict[str, Any]:
        return await self._set_enabled(command, True, "active")

    async def terminate(self, command: StepCommand) -> dict[str, Any]:
        return await self._set_enabled(command, False, "terminated")

    async def rotate_credentials(self, command: StepCommand) -> dict[str, Any]:
        user = await self._user_for_command(command)
        await self._request(
            "PUT",
            f"users/{user['id']}",
            json_body={
                "requiredActions": sorted(
                    set(user.get("requiredActions", [])) | REQUIRED_ACTIONS
                )
            },
            expected=(204,),
        )
        await self._request("POST", f"users/{user['id']}/logout", expected=(204,))
        return self._result(user["id"], "credential_actions_required")

    async def _snapshot(self, user: dict[str, Any]) -> dict[str, Any]:
        user_id = user["id"]
        groups = (
            await self._request("GET", f"users/{user_id}/groups")
        ).json()
        realm_roles = (
            await self._request("GET", f"users/{user_id}/role-mappings/realm")
        ).json()
        client_mappings = (
            await self._request("GET", f"users/{user_id}/role-mappings")
        ).json().get("clientMappings", {})
        return {
            "enabled": bool(user.get("enabled")),
            "required_actions": sorted(user.get("requiredActions", [])),
            "attributes": user.get("attributes", {}),
            "groups": sorted(group.get("path") for group in groups),
            "realm_roles": sorted(role.get("name") for role in realm_roles),
            "client_roles": {
                client_id: sorted(role.get("name") for role in mapping.get("mappings", []))
                for client_id, mapping in client_mappings.items()
            },
        }

    async def reconcile(self, command: StepCommand) -> dict[str, Any]:
        user = await self._user_for_command(command)
        snapshot = await self._snapshot(user)
        desired = command.payload.get("desired", {})
        drift: dict[str, Any] = {}
        if isinstance(desired, dict):
            for key in ("enabled", "required_actions", "groups", "realm_roles"):
                if key in desired and desired[key] != snapshot[key]:
                    drift[key] = {"expected": desired[key], "actual": snapshot[key]}
            if "attributes" in desired:
                attribute_drift = {
                    key: {"expected": value, "actual": snapshot["attributes"].get(key)}
                    for key, value in desired["attributes"].items()
                    if snapshot["attributes"].get(key) != value
                }
                if attribute_drift:
                    drift["attributes"] = attribute_drift
            if "client_roles" in desired and desired["client_roles"] != snapshot["client_roles"]:
                drift["client_roles"] = {
                    "expected": desired["client_roles"],
                    "actual": snapshot["client_roles"],
                }
        state = "privilege_drift" if drift else "aligned"
        return self._result(user["id"], state, {"snapshot": snapshot, "drift": drift})

    async def verify(self, command: StepCommand) -> dict[str, Any]:
        user = await self._user_for_command(command)
        snapshot = await self._snapshot(user)
        required = set(snapshot["required_actions"])
        if not REQUIRED_ACTIONS <= required:
            raise PermanentAdapterError("keycloak_required_actions_missing")
        return self._result(user["id"], "verified", snapshot)
