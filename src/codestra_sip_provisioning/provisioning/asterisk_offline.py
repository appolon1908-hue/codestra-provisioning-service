from dataclasses import dataclass
from .base import IssuedCredential

@dataclass(frozen=True)
class OfflineArtifact:
    endpoint: str
    username: str
    action: str

class AsteriskOfflineProvisioner:
    """Produces review artifacts only; it has no socket or shell capability."""
    async def issue(self, endpoint: str) -> IssuedCredential:
        if endpoint == "6101": raise ValueError("endpoint 6101 is forbidden")
        return IssuedCredential(username=endpoint, password="offline-artifact-not-a-secret")
    async def rotate(self, endpoint: str) -> IssuedCredential: return await self.issue(endpoint)
    async def revoke(self, endpoint: str) -> None: return None
    async def validate(self, endpoint: str) -> bool: return endpoint != "6101"
    def describe_capabilities(self) -> dict[str, object]: return {"offline": True, "network": False, "asterisk": False}
