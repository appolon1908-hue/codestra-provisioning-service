from functools import lru_cache
from typing import Literal, Self

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROLES = frozenset(
    {
        "agent",
        "closer",
        "supervisor",
        "manager",
        "compliance_auditor",
        "platform_admin",
        "service_vicidial",
        "service_n8n",
        "service_sip",
    }
)
SCOPES = frozenset(
    {
        "crm:read",
        "crm:write",
        "calls:read",
        "calls:disposition",
        "callbacks:create",
        "callbacks:update",
        "transfer:request",
        "transfer:approve",
        "compliance:write",
        "ai:recommendation:read",
        "ai:recommendation:accept",
        "sip:session:create",
        "sip:session:renew",
        "sip:session:revoke",
        "supervisor:monitor",
        "supervisor:whisper",
        "supervisor:barge",
        "audit:read",
    }
)


class MTLSPrincipalDefinition(BaseModel):
    subject: str = Field(min_length=1, max_length=255)
    roles: frozenset[str]
    scopes: frozenset[str]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="forbid")

    app_env: Literal["test", "preproduction", "production"]
    service_name: str = "codestra-sip-provisioning"
    service_version: str = "0.2.0"
    listen_host: str = "0.0.0.0"  # noqa: S104 - container-internal listener
    listen_port: int = 8110
    auth_mode: Literal["test", "jwt", "mtls", "disabled_trusted"] = "disabled_trusted"
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    jwt_jwks_url: str | None = None
    jwt_pinned_public_key: str | None = None
    jwt_allowed_algorithms: frozenset[str] = frozenset()
    jwt_token_type_claim: str = "token_type"  # noqa: S105 - public JWT claim name
    jwt_expected_token_type: str = "access"  # noqa: S105 - public token classification
    jwt_clock_skew_seconds: int = Field(default=30, ge=0, le=120)
    jwt_role_claim: str = "roles"
    jwt_scope_claim: str = "scope"
    mtls_principals: dict[str, MTLSPrincipalDefinition] = Field(default_factory=dict)

    database_url: str
    redis_url: str
    credential_encryption_key_v1: str
    credential_encryption_key_version: str = "v1"
    audit_hmac_key: str = Field(min_length=32)
    subject_hash_key: str = Field(min_length=32)
    credential_fingerprint_key: str = Field(min_length=32)

    sip_provisioning_api_enabled: bool = True
    sip_provisioning_mock_mode: bool = True
    live_authorization_enabled: bool = False
    live_asterisk_provisioning_enabled: bool = False
    live_endpoint_install_enabled: bool = False
    live_endpoint_reload_enabled: bool = False
    live_endpoint_delete_enabled: bool = False
    endpoint_6101_allowed: bool = False
    public_session_route_enabled: bool = False

    session_ttl_default_seconds: int = 600
    session_ttl_min_seconds: int = 300
    session_ttl_max_seconds: int = 1800
    session_max_lifetime_seconds: int = 28800
    credential_overlap_seconds: int = 15
    max_renewals: int = 24
    redis_namespace: str = "codestra:sip:v1"
    reconciliation_interval_seconds: int = 30
    migration_revision: str = "0001_durable_state"
    schema_version: str = "1"
    max_request_bytes: int = 16384
    mock_wss_url: str = "wss://mock.invalid/ws"
    mock_realm: str = "mock.invalid"

    @property
    def allowed_roles(self) -> frozenset[str]:
        return ROLES

    @property
    def allowed_scopes(self) -> frozenset[str]:
        return SCOPES

    @field_validator("jwt_allowed_algorithms", mode="before")
    @classmethod
    def parse_algorithms(cls, value: object) -> object:
        if isinstance(value, str):
            return frozenset(item.strip() for item in value.split(",") if item.strip())
        return value

    @model_validator(mode="after")
    def fail_closed(self) -> Self:
        if self.auth_mode == "test" and self.app_env != "test":
            raise ValueError("test authentication is allowed only in APP_ENV=test")
        if self.auth_mode == "jwt":
            if not self.jwt_issuer or not self.jwt_audience:
                raise ValueError("JWT issuer and audience are required")
            if not self.jwt_issuer.startswith("https://"):
                raise ValueError("JWT issuer must use HTTPS")
            if self.jwt_jwks_url and not self.jwt_jwks_url.startswith("https://"):
                raise ValueError("JWKS URL must use HTTPS")
            if bool(self.jwt_jwks_url) == bool(self.jwt_pinned_public_key):
                raise ValueError("configure exactly one JWT verification key source")
            if not self.jwt_allowed_algorithms or "none" in {
                item.lower() for item in self.jwt_allowed_algorithms
            }:
                raise ValueError("explicit signed JWT algorithms are required")
            if not self.jwt_allowed_algorithms <= {
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512",
            }:
                raise ValueError("only asymmetric JWT algorithms are allowed")
        if self.auth_mode == "mtls":
            if not self.mtls_principals:
                raise ValueError("mTLS principal allowlist is required")
            for fingerprint, definition in self.mtls_principals.items():
                if len(fingerprint) != 64 or any(
                    character not in "0123456789abcdef" for character in fingerprint
                ):
                    raise ValueError("mTLS fingerprints must be lowercase SHA-256")
                if not definition.roles <= ROLES or not definition.scopes <= SCOPES:
                    raise ValueError("mTLS authority contains unknown role or scope")
        trusted = self.auth_mode in {"jwt", "mtls"}
        if self.live_authorization_enabled != trusted:
            raise ValueError("LIVE_AUTHORIZATION_ENABLED must exactly match trusted auth mode")
        if self.public_session_route_enabled and not self.live_authorization_enabled:
            raise ValueError("public sessions require approved trusted authentication")
        if any(
            (
                self.live_asterisk_provisioning_enabled,
                self.live_endpoint_install_enabled,
                self.live_endpoint_reload_enabled,
                self.live_endpoint_delete_enabled,
                self.endpoint_6101_allowed,
            )
        ):
            raise ValueError("live provisioning and endpoint 6101 are forbidden")
        if not self.sip_provisioning_mock_mode:
            raise ValueError("MockProvisioner must remain active")
        if self.credential_encryption_key_version != "v1":
            raise ValueError("configured encryption key version is unavailable")
        if not (
            300
            <= self.session_ttl_min_seconds
            <= self.session_ttl_default_seconds
            <= self.session_ttl_max_seconds
            <= 1800
        ):
            raise ValueError("invalid TTL policy")
        if not 0 <= self.credential_overlap_seconds <= 15:
            raise ValueError("invalid credential overlap")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
