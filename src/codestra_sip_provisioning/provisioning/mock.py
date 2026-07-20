import secrets

from .base import IssuedCredential


class MockProvisioner:
    """Pure local mock. It has no network or shell capability."""

    async def issue(self, endpoint: str) -> IssuedCredential:
        return IssuedCredential(username=endpoint, password=secrets.token_urlsafe(32))

    async def rotate(self, endpoint: str) -> IssuedCredential:
        return IssuedCredential(username=endpoint, password=secrets.token_urlsafe(32))

    async def revoke(self, endpoint: str) -> None:
        return None

    async def validate(self, endpoint: str) -> bool:
        return endpoint.startswith("mock-") and endpoint != "6101"

    def describe_capabilities(self) -> dict[str, object]:
        return {"mock": True, "network": False, "asterisk": False, "endpoint_creation": False}
