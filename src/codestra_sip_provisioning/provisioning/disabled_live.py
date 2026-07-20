from ..errors import DisabledFeatureError
from .base import IssuedCredential


class DisabledLiveProvisioner:
    async def issue(self, endpoint: str) -> IssuedCredential:
        raise DisabledFeatureError()

    async def rotate(self, endpoint: str) -> IssuedCredential:
        raise DisabledFeatureError()

    async def revoke(self, endpoint: str) -> None:
        raise DisabledFeatureError()

    async def validate(self, endpoint: str) -> bool:
        raise DisabledFeatureError()

    def describe_capabilities(self) -> dict[str, object]:
        return {"mock": False, "enabled": False, "network": False, "asterisk": False}
