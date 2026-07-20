from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="forbid")

    app_env: Literal["test", "preproduction", "production"]
    service_name: str = "codestra-sip-provisioning"
    service_version: str = "0.2.0"
    listen_host: str = "0.0.0.0"
    listen_port: int = 8110
    auth_mode: Literal["test", "disabled_trusted"] = "disabled_trusted"

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

    @model_validator(mode="after")
    def fail_closed(self) -> Self:
        if self.auth_mode == "test" and self.app_env != "test":
            raise ValueError("test authentication is allowed only in APP_ENV=test")
        if self.public_session_route_enabled and not self.live_authorization_enabled:
            raise ValueError("public sessions require approved trusted authentication")
        if any((self.live_asterisk_provisioning_enabled, self.live_endpoint_install_enabled,
                self.live_endpoint_reload_enabled, self.live_endpoint_delete_enabled,
                self.endpoint_6101_allowed)):
            raise ValueError("live provisioning and endpoint 6101 are forbidden")
        if not self.sip_provisioning_mock_mode:
            raise ValueError("MockProvisioner must remain active")
        if self.credential_encryption_key_version != "v1":
            raise ValueError("configured encryption key version is unavailable")
        if not (300 <= self.session_ttl_min_seconds <= self.session_ttl_default_seconds
                <= self.session_ttl_max_seconds <= 1800):
            raise ValueError("invalid TTL policy")
        if not 0 <= self.credential_overlap_seconds <= 15:
            raise ValueError("invalid credential overlap")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
