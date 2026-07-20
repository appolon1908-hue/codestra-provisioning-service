"""Durable-state service boundaries.

All production implementations receive an AsyncSession and redis-py client;
these classes intentionally contain no fallback dictionaries. A dependency
failure raises and callers must fail closed.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import SipEndpointAssignment, SipSession
from ..state.guards import LockManager, RateLimitService, ReplayGuard
from ..state.crypto import CredentialCipher, fingerprint

class CredentialStore(Protocol):
    async def set(self, name: str, value: str, ex: int, nx: bool = False) -> Any: ...
    async def get(self, name: str) -> Any: ...
    async def delete(self, *names: str) -> Any: ...

@dataclass(frozen=True)
class Assignment:
    subject: str
    endpoint: str

class AssignmentService:
    def __init__(self, db: AsyncSession) -> None: self.db = db
    async def get(self, subject: str) -> Assignment | None:
        row = (await self.db.execute(select(SipEndpointAssignment).where(SipEndpointAssignment.user_subject == subject))).scalar_one_or_none()
        return Assignment(row.user_subject, row.endpoint_name) if row else None
    async def create(self, subject: str, endpoint: str) -> Assignment:
        row = SipEndpointAssignment(user_subject=subject, endpoint_name=endpoint, created_at=datetime.utcnow())
        self.db.add(row); await self.db.flush()
        return Assignment(subject, endpoint)

class SessionService:
    def __init__(self, db: AsyncSession) -> None: self.db = db
    async def get(self, session_id: UUID) -> SipSession | None:
        return (await self.db.execute(select(SipSession).where(SipSession.id == session_id))).scalar_one_or_none()
    async def active_for_subject(self, subject: str) -> SipSession | None:
        return (await self.db.execute(select(SipSession).where(SipSession.user_subject == subject, SipSession.status == "active"))).scalar_one_or_none()
    async def add(self, **values: Any) -> SipSession:
        row = SipSession(**values); self.db.add(row); await self.db.flush(); return row

class CredentialService:
    def __init__(self, redis: CredentialStore, cipher: CredentialCipher, keyspace: Any, hmac_key: bytes) -> None:
        self.redis, self.cipher, self.keys, self.hmac_key = redis, cipher, keyspace, hmac_key
    async def put(self, session_id: str, credential: str, ttl: int) -> str:
        if ttl <= 0: raise ValueError("credential TTL must be positive")
        await self.redis.set(self.keys.credential(session_id), self.cipher.encrypt(credential), ex=ttl)
        return fingerprint(credential, self.hmac_key)
    async def get(self, session_id: str) -> str | None:
        value = await self.redis.get(self.keys.credential(session_id))
        return self.cipher.decrypt(value) if value else None
    async def revoke(self, session_id: str) -> None: await self.redis.delete(self.keys.credential(session_id))

class IdempotencyService:
    """Repository-backed idempotency belongs in PostgreSQL unique constraints."""
    def __init__(self, db: AsyncSession) -> None: self.db = db

class AuditService:
    def __init__(self, db: AsyncSession) -> None: self.db = db

