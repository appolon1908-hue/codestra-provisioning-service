from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]

    def may_issue(self) -> bool:
        return bool(self.roles & {"sip_session_user", "sip_session_service"})
