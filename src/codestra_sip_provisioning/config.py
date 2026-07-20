from functools import lru_cache
from typing import Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="forbid")

    environment: str = "test"
    service_version: str = "0.1.0"
    database_url: str
    redis_url: str
    credential_encryption_key: str
    fingerprint_hmac_key: str = Field(min_length=32)
    actor_hmac_key: str = Field(min_length=32)
    mock_wss_url: str = "wss://mock.invalid/ws"
    mock_realm: str = "mock.invalid"

    sip_provisioning_api_enabled: bool = True
    sip_provisioning_mock_mode: bool = True
    live_authorization_enabled: bool = False
    live_asterisk_provisioning_enabled: bool = False
    live_endpoint_install_enabled: bool = False
    live_endpoint_reload_enabled: bool = False
    live_endpoint_delete_enabled: bool = False
    endpoint_6101_allowed: bool = False
    public_route_enabled: bool = False
    audit_enabled: bool = True
    metrics_enabled: bool = True

    default_ttl_seconds: int = 600
    min_ttl_seconds: int = 300
    max_ttl_seconds: int = 1800
    max_session_seconds: int = 28800
    old_credential_overlap_seconds: int = 15
    max_request_bytes: int = 16384
    redis_namespace: str = "codestra:sip:v1"

    @model_validator(mode="after")
    def fail_closed(self) -> Self:
        live = (
            self.live_authorization_enabled
            or self.live_asterisk_provisioning_enabled
            or self.live_endpoint_install_enabled
            or self.live_endpoint_reload_enabled
            or self.live_endpoint_delete_enabled
            or self.endpoint_6101_allowed
            or self.public_route_enabled
        )
        if live:
            raise ValueError("live SIP, endpoint 6101, and public-route flags are forbidden")
        if not self.sip_provisioning_mock_mode:
            raise ValueError("mock mode must remain enabled")
        if not (300 <= self.min_ttl_seconds <= self.default_ttl_seconds <= self.max_ttl_seconds <= 1800):
            raise ValueError("invalid credential TTL policy")
        if self.old_credential_overlap_seconds > 15:
            raise ValueError("credential overlap exceeds policy")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
