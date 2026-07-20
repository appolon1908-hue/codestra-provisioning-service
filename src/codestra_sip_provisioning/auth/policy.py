from collections.abc import Awaitable, Callable

from .principal import Principal, PrincipalKind

ROUTE_SCOPES = {
    "create": "sip:session:create",
    "renew": "sip:session:renew",
    "revoke": "sip:session:revoke",
}
MUTATING_ROLES = frozenset(
    {"agent", "closer", "supervisor", "manager", "platform_admin", "service_sip"}
)
SERVICE_SCOPES = {
    "service_sip": frozenset(ROUTE_SCOPES.values()),
    "service_vicidial": frozenset(),
    "service_n8n": frozenset(),
}


class AuthorizationDenied(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code, self.detail = code, detail


class AuthorizationPolicy:
    async def authorize(
        self,
        principal: Principal,
        operation: str,
        *,
        owner: Callable[[], Awaitable[bool]] | None = None,
    ) -> None:
        required = ROUTE_SCOPES[operation]
        if required not in principal.scopes:
            raise AuthorizationDenied("missing_scope", "required scope is missing")
        if principal.kind is PrincipalKind.SERVICE:
            permitted = frozenset().union(
                *(SERVICE_SCOPES.get(role, frozenset()) for role in principal.roles)
            )
            if required not in permitted:
                raise AuthorizationDenied(
                    "service_scope_restricted", "service principal is restricted"
                )
        elif "compliance_auditor" in principal.roles or not principal.roles & MUTATING_ROLES:
            raise AuthorizationDenied("role_forbidden", "role cannot mutate SIP sessions")
        if owner is not None and not await owner():
            raise AuthorizationDenied("ownership_required", "session is not owned by principal")

    @staticmethod
    def may_retrieve_existing_credential(principal: Principal) -> bool:
        del principal
        return False
