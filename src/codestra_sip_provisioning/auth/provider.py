from fastapi import Header, HTTPException

from ..config import Settings
from .principal import Principal


class PrincipalProvider:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def authenticate(self, authorization: str | None = Header(default=None)) -> Principal:
        if self.settings.auth_mode != "test" or self.settings.app_env != "test":
            raise HTTPException(503, "trusted authentication is not approved")
        if not authorization or not authorization.startswith("Bearer test:"):
            raise HTTPException(401, "authentication required")
        subject = authorization.removeprefix("Bearer test:")
        if not subject or len(subject) > 255:
            raise HTTPException(401, "invalid test principal")
        return Principal(subject, frozenset({"sip_session_user"}))
