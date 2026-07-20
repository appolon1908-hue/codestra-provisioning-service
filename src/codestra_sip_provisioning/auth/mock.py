from dataclasses import dataclass

from fastapi import Header, HTTPException


@dataclass(frozen=True)
class Identity:
    subject: str
    roles: frozenset[str]


async def mock_identity(
    x_test_subject: str | None = Header(default=None, min_length=1, max_length=255),
    x_test_roles: str = Header(default="sip_session_user"),
) -> Identity:
    if not x_test_subject:
        raise HTTPException(status_code=401, detail="mock identity required")
    roles = frozenset(item.strip() for item in x_test_roles.split(",") if item.strip())
    if not roles.intersection({"sip_session_user", "sip_session_service"}):
        raise HTTPException(status_code=403, detail="SIP session role required")
    return Identity(subject=x_test_subject, roles=roles)
