from dataclasses import dataclass
from enum import StrEnum


class PrincipalKind(StrEnum):
    USER = "user"
    SERVICE = "service"
    TEST = "test"


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]
    scopes: frozenset[str]
    kind: PrincipalKind
    issuer: str

    @property
    def primary_role(self) -> str | None:
        return sorted(self.roles)[0] if self.roles else None
