from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class CreateSessionRequest(BaseModel):
    ttl_seconds: int = Field(default=600, ge=300, le=1800)


class RenewSessionRequest(BaseModel):
    session_id: UUID
    ttl_seconds: int = Field(default=600, ge=300, le=1800)


class RevokeSessionRequest(BaseModel):
    session_id: UUID
    reason: str = Field(min_length=1, max_length=120)


class SessionResponse(BaseModel):
    session_id: UUID
    endpoint: str
    sip_username: str
    sip_password: str | None
    wss_url: str
    realm: str
    expires_at: datetime
    renew_after: datetime
    credential_rotated: bool = False
    credential_delivered: bool = True
    mock_mode: Literal[True] = True
    storage_requirement: Literal["memory-only"] = "memory-only"
    request_id: str
    correlation_id: str
