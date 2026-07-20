import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from redis.asyncio import Redis
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..config import Settings
from ..models import (
    SipAuditEvent,
    SipCredentialRotation,
    SipEndpointAssignment,
    SipIdempotencyRecord,
    SipSession,
)
from ..provisioning.mock import MockProvisioner
from ..security.redaction import redact
from ..state.crypto import CredentialCipher, fingerprint, keyed_hash
from ..state.guards import LockManager, RateLimitService, RedisLike
from ..state.redis_keys import RedisKeyspace


class LifecycleError(Exception):
    def __init__(
        self, status: int, code: str, detail: str, reference: uuid.UUID | None = None
    ) -> None:
        super().__init__(detail)
        self.status, self.code, self.detail, self.reference = status, code, detail, reference


class DurableSessionService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        redis: Redis,
        settings: Settings,
        cipher: CredentialCipher,
    ) -> None:
        self.sessions, self.redis, self.settings, self.cipher = sessions, redis, settings, cipher
        self.keys = RedisKeyspace(settings.redis_namespace)
        shared_redis = cast(RedisLike, redis)
        self.locks = LockManager(shared_redis, self.keys)
        self.rates = RateLimitService(shared_redis, self.keys)
        self.provisioner = MockProvisioner()

    def digest(self, value: str, domain: str) -> str:
        return keyed_hash(value, self.settings.subject_hash_key.encode(), domain)

    @staticmethod
    def request_hash(payload: dict[str, object]) -> str:
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    async def _idempotency(
        self,
        db: AsyncSession,
        subject_hash: str,
        operation: str,
        key: str,
        payload_hash: str,
        now: datetime,
    ) -> SipIdempotencyRecord:
        key_hash = self.digest(key, "codestra:sip:idempotency:v1")
        existing = (
            await db.execute(
                select(SipIdempotencyRecord).where(
                    SipIdempotencyRecord.subject_hash == subject_hash,
                    SipIdempotencyRecord.operation == operation,
                    SipIdempotencyRecord.key_hash == key_hash,
                )
            )
        ).scalar_one_or_none()
        if existing:
            if not hmac.compare_digest(existing.request_hash, payload_hash):
                raise LifecycleError(
                    409, "idempotency_conflict", "idempotency key payload conflict"
                )
            raise LifecycleError(
                409,
                "credential_already_delivered",
                "request was already completed; credential cannot be replayed",
                existing.response_reference,
            )
        row = SipIdempotencyRecord(
            key_hash=key_hash,
            subject_hash=subject_hash,
            operation=operation,
            request_hash=payload_hash,
            state="pending",
            created_at=now,
            expires_at=now + timedelta(hours=24),
        )
        db.add(row)
        await db.flush()
        return row

    async def _audit(
        self,
        db: AsyncSession,
        *,
        action: str,
        result: str,
        subject_hash: str | None,
        session_id: uuid.UUID | None,
        assignment_id: uuid.UUID | None,
        request_id: uuid.UUID | None,
        correlation_id: uuid.UUID | None,
        metadata: dict[str, object],
        actor_role: str | None = "sip_session_user",
    ) -> None:
        await db.execute(text("SELECT pg_advisory_xact_lock(81254021)"))
        previous = (
            await db.execute(
                select(SipAuditEvent.event_hash)
                .order_by(SipAuditEvent.occurred_at.desc(), SipAuditEvent.id.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        clean = redact(metadata)
        payload = {
            "action": action,
            "result": result,
            "subject": subject_hash,
            "session_id": str(session_id) if session_id else None,
            "assignment_id": str(assignment_id) if assignment_id else None,
            "request_id": str(request_id) if request_id else None,
            "correlation_id": str(correlation_id) if correlation_id else None,
            "metadata": clean,
            "policy_version": "v1",
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        event_hash = hmac.new(
            self.settings.audit_hmac_key.encode(),
            ((previous or "") + canonical).encode(),
            hashlib.sha256,
        ).hexdigest()
        db.add(
            SipAuditEvent(
                occurred_at=datetime.now(UTC),
                actor_subject_hash=subject_hash,
                actor_role=actor_role,
                action=action,
                result=result,
                session_id=session_id,
                assignment_id=assignment_id,
                request_id=request_id,
                correlation_id=correlation_id,
                policy_version="v1",
                metadata_json=clean,
                previous_hash=previous,
                event_hash=event_hash,
            )
        )

    async def audit_authorization(
        self,
        *,
        subject: str | None,
        role: str | None,
        action: str,
        result: str,
        reason: str,
        request_id: uuid.UUID,
    ) -> None:
        subject_hash = (
            self.digest(subject, "codestra:sip:subject:v1") if subject is not None else None
        )
        async with self.sessions() as db, db.begin():
            await self._audit(
                db,
                action=action,
                result=result,
                subject_hash=subject_hash,
                session_id=None,
                assignment_id=None,
                request_id=request_id,
                correlation_id=request_id,
                metadata={"reason_code": reason},
                actor_role=role,
            )

    async def owns_session(self, subject: str, session_id: uuid.UUID) -> bool:
        subject_hash = self.digest(subject, "codestra:sip:subject:v1")
        async with self.sessions() as db:
            return (
                await db.execute(
                    select(SipSession.id).where(
                        SipSession.id == session_id, SipSession.subject_hash == subject_hash
                    )
                )
            ).scalar_one_or_none() is not None

    async def create(
        self,
        subject: str,
        client_id: str,
        idempotency_key: str,
        ttl: int,
        request_id: uuid.UUID,
        correlation_id: uuid.UUID,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        subject_hash = self.digest(subject, "codestra:sip:subject:v1")
        client_hash = self.digest(client_id, "codestra:sip:client:v1")
        try:
            await self.rates.check(subject_hash, "create", 5, 600)
            token = await self.locks.acquire(subject_hash, "create")
        except PermissionError as exc:
            raise LifecycleError(429, "rate_limited", "rate limit exceeded") from exc
        except Exception as exc:
            raise LifecycleError(503, "state_unavailable", "shared state unavailable") from exc
        sid: uuid.UUID | None = None
        try:
            async with self.sessions() as db, db.begin():
                idem = await self._idempotency(
                    db,
                    subject_hash,
                    "create",
                    idempotency_key,
                    self.request_hash({"ttl": ttl}),
                    now,
                )
                assignment = (
                    await db.execute(
                        select(SipEndpointAssignment)
                        .where(SipEndpointAssignment.subject_hash == subject_hash)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                endpoint = f"mock-{subject_hash[:12]}"
                if endpoint == "6101":
                    raise LifecycleError(403, "endpoint_forbidden", "endpoint is prohibited")
                if assignment is None:
                    assignment = SipEndpointAssignment(
                        subject_hash=subject_hash,
                        endpoint_name=endpoint,
                        status="assigned",
                        assigned_at=now,
                        updated_at=now,
                        source="mock",
                        metadata_json={},
                    )
                    db.add(assignment)
                    await db.flush()
                active = (
                    await db.execute(
                        select(SipSession)
                        .where(
                            SipSession.subject_hash == subject_hash,
                            SipSession.state.in_(("issued", "active", "renewing", "renewed")),
                            SipSession.expires_at > now,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if active:
                    raise LifecycleError(
                        409, "active_session_exists", "an active session already exists"
                    )
                issued = await self.provisioner.issue(endpoint)
                sid, expires = uuid.uuid4(), now + timedelta(seconds=ttl)
                fp = fingerprint(issued.password, self.settings.credential_fingerprint_key.encode())
                row = SipSession(
                    id=sid,
                    assignment_id=assignment.id,
                    subject_hash=subject_hash,
                    credential_fingerprint=fp,
                    state="active",
                    created_at=now,
                    activated_at=now,
                    expires_at=expires,
                    request_id=request_id,
                    correlation_id=correlation_id,
                    client_instance_hash=client_hash,
                    mock_mode=True,
                    provisioner_type="mock",
                )
                db.add(row)
                envelope = self.cipher.encrypt(
                    issued.password, str(sid), subject_hash, endpoint, expires
                )
                await self._write_runtime(sid, subject_hash, endpoint, envelope, ttl)
                idem.state, idem.response_status, idem.response_reference = "completed", 201, sid
                assignment.last_session_at, assignment.updated_at = now, now
                await self._audit(
                    db,
                    action="create",
                    result="success",
                    subject_hash=subject_hash,
                    session_id=sid,
                    assignment_id=assignment.id,
                    request_id=request_id,
                    correlation_id=correlation_id,
                    metadata={"mock_mode": True},
                )
                return self._response(
                    row,
                    endpoint,
                    issued.username,
                    issued.password,
                    request_id,
                    correlation_id,
                    rotated=False,
                )
        except IntegrityError as exc:
            raise LifecycleError(409, "concurrent_conflict", "concurrent request conflict") from exc
        except LifecycleError:
            raise
        except Exception as exc:
            if sid:
                await self._delete_runtime(sid, subject_hash)
            raise LifecycleError(
                503, "dependency_failure", "session creation failed closed"
            ) from exc
        finally:
            await self.locks.release(token)

    async def _write_runtime(
        self, sid: uuid.UUID, subject_hash: str, endpoint: str, envelope: str, ttl: int
    ) -> None:
        pipe = self.redis.pipeline(transaction=True)
        pipe.set(
            self.keys.session(str(sid)),
            json.dumps({"state": "active", "endpoint": endpoint}),
            ex=ttl + 60,
        )
        pipe.set(self.keys.credential(str(sid)), envelope, ex=ttl)
        pipe.set(self.keys.lease(subject_hash), str(sid), ex=ttl)
        pipe.set(self.keys.endpoint(endpoint), subject_hash, ex=min(ttl, 1800))
        await pipe.execute()

    async def _delete_runtime(self, sid: uuid.UUID, subject_hash: str) -> None:
        await self.redis.delete(
            self.keys.credential(str(sid)),
            self.keys.old_credential(str(sid)),
            self.keys.session(str(sid)),
            self.keys.lease(subject_hash),
        )

    def _response(
        self,
        row: SipSession,
        endpoint: str,
        username: str,
        password: str,
        request_id: uuid.UUID,
        correlation_id: uuid.UUID,
        rotated: bool,
    ) -> dict[str, Any]:
        return {
            "session_id": str(row.id),
            "endpoint": endpoint,
            "sip_username": username,
            "sip_password": password,
            "wss_url": self.settings.mock_wss_url,
            "realm": self.settings.mock_realm,
            "expires_at": row.expires_at.isoformat(),
            "renew_after": (row.expires_at - timedelta(seconds=120)).isoformat(),
            "credential_rotated": rotated,
            "credential_delivered": True,
            "mock_mode": True,
            "storage_requirement": "memory-only",
            "request_id": str(request_id),
            "correlation_id": str(correlation_id),
        }

    async def renew(
        self,
        subject: str,
        session_id: uuid.UUID,
        client_id: str,
        idempotency_key: str,
        ttl: int,
        request_id: uuid.UUID,
        correlation_id: uuid.UUID,
    ) -> dict[str, Any]:
        now, subject_hash = datetime.now(UTC), self.digest(subject, "codestra:sip:subject:v1")
        await self.rates.check(subject_hash, "renew", 12, 3600)
        token = await self.locks.acquire(subject_hash, "renew")
        try:
            async with self.sessions() as db, db.begin():
                idem = await self._idempotency(
                    db,
                    subject_hash,
                    "renew",
                    idempotency_key,
                    self.request_hash({"session_id": str(session_id), "ttl": ttl}),
                    now,
                )
                row = (
                    await db.execute(
                        select(SipSession)
                        .where(SipSession.id == session_id, SipSession.subject_hash == subject_hash)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if not row or row.state not in {"active", "renewed"} or row.expires_at <= now:
                    raise LifecycleError(404, "session_not_found", "session not found")
                if row.renewal_count >= self.settings.max_renewals or now + timedelta(
                    seconds=ttl
                ) > row.created_at + timedelta(seconds=self.settings.session_max_lifetime_seconds):
                    raise LifecycleError(409, "renewal_limit", "session lifetime limit reached")
                assignment = await db.get(SipEndpointAssignment, row.assignment_id)
                if assignment is None:
                    raise LifecycleError(
                        503, "assignment_missing", "durable assignment is unavailable"
                    )
                issued, old_fp = (
                    await self.provisioner.rotate(assignment.endpoint_name),
                    row.credential_fingerprint,
                )
                expires = now + timedelta(seconds=ttl)
                fp = fingerprint(issued.password, self.settings.credential_fingerprint_key.encode())
                existing = await self.redis.get(self.keys.credential(str(row.id)))
                if existing and self.settings.credential_overlap_seconds:
                    await self.redis.set(
                        self.keys.old_credential(str(row.id)),
                        existing,
                        ex=self.settings.credential_overlap_seconds,
                    )
                envelope = self.cipher.encrypt(
                    issued.password, str(row.id), subject_hash, assignment.endpoint_name, expires
                )
                await self._write_runtime(
                    row.id, subject_hash, assignment.endpoint_name, envelope, ttl
                )
                row.credential_fingerprint, row.expires_at, row.renewed_at = fp, expires, now
                row.state, row.renewal_count, row.version = (
                    "renewed",
                    row.renewal_count + 1,
                    row.version + 1,
                )
                db.add(
                    SipCredentialRotation(
                        session_id=row.id,
                        previous_fingerprint=old_fp,
                        new_fingerprint=fp,
                        encryption_key_version=self.cipher.active_version,
                        rotated_at=now,
                        overlap_expires_at=now
                        + timedelta(seconds=self.settings.credential_overlap_seconds),
                        reason="renew",
                        request_id=request_id,
                    )
                )
                idem.state, idem.response_status, idem.response_reference = "completed", 200, row.id
                await self._audit(
                    db,
                    action="renew",
                    result="success",
                    subject_hash=subject_hash,
                    session_id=row.id,
                    assignment_id=row.assignment_id,
                    request_id=request_id,
                    correlation_id=correlation_id,
                    metadata={"renewal_count": row.renewal_count},
                )
                return self._response(
                    row,
                    assignment.endpoint_name,
                    issued.username,
                    issued.password,
                    request_id,
                    correlation_id,
                    rotated=True,
                )
        finally:
            await self.locks.release(token)

    async def revoke(
        self,
        subject: str,
        session_id: uuid.UUID,
        idempotency_key: str,
        request_id: uuid.UUID,
        correlation_id: uuid.UUID,
    ) -> None:
        now, subject_hash = datetime.now(UTC), self.digest(subject, "codestra:sip:subject:v1")
        await self.rates.check(subject_hash, "revoke", 20, 3600)
        token = await self.locks.acquire(subject_hash, "revoke")
        try:
            async with self.sessions() as db, db.begin():
                existing = (
                    await db.execute(
                        select(SipIdempotencyRecord).where(
                            SipIdempotencyRecord.subject_hash == subject_hash,
                            SipIdempotencyRecord.operation == "revoke",
                            SipIdempotencyRecord.key_hash
                            == self.digest(idempotency_key, "codestra:sip:idempotency:v1"),
                        )
                    )
                ).scalar_one_or_none()
                if existing:
                    return
                idem = await self._idempotency(
                    db,
                    subject_hash,
                    "revoke",
                    idempotency_key,
                    self.request_hash({"session_id": str(session_id)}),
                    now,
                )
                row = (
                    await db.execute(
                        select(SipSession)
                        .where(SipSession.id == session_id, SipSession.subject_hash == subject_hash)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if row and row.state != "revoked":
                    await self.provisioner.revoke("mock")
                    await self._delete_runtime(row.id, subject_hash)
                    row.state, row.revoked_at, row.revoke_reason = "revoked", now, "client_request"
                    await self._audit(
                        db,
                        action="revoke",
                        result="success",
                        subject_hash=subject_hash,
                        session_id=row.id,
                        assignment_id=row.assignment_id,
                        request_id=request_id,
                        correlation_id=correlation_id,
                        metadata={},
                    )
                idem.state, idem.response_status, idem.response_reference = (
                    "completed",
                    204,
                    session_id,
                )
        finally:
            await self.locks.release(token)

    async def reconcile(self) -> int:
        now, count = datetime.now(UTC), 0
        leader = await self.locks.acquire("0" * 64, "reconcile", wait_seconds=0.05)
        try:
            async with self.sessions() as db, db.begin():
                rows = (
                    (
                        await db.execute(
                            select(SipSession)
                            .where(
                                SipSession.expires_at <= now,
                                SipSession.state.in_(("active", "renewed")),
                            )
                            .with_for_update(skip_locked=True)
                        )
                    )
                    .scalars()
                    .all()
                )
                for row in rows:
                    row.state = "expired"
                    await self._delete_runtime(row.id, row.subject_hash)
                    await self._audit(
                        db,
                        action="expire",
                        result="success",
                        subject_hash=row.subject_hash,
                        session_id=row.id,
                        assignment_id=row.assignment_id,
                        request_id=None,
                        correlation_id=None,
                        metadata={},
                    )
                    count += 1
            return count
        finally:
            await self.locks.release(leader)
