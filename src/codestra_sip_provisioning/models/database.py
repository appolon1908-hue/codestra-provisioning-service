import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class SipEndpointAssignment(Base):
    __tablename__ = "endpoint_assignment"
    __table_args__ = (CheckConstraint("endpoint_name <> '6101'", name="ck_endpoint_not_6101"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subject_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    endpoint_name: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    endpoint_numeric_id: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="assigned")
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_session_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="mock")
    created_by_hash: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    metadata_json: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )


class SipSession(Base):
    __tablename__ = "sip_session"
    __table_args__ = (
        CheckConstraint("renewal_count >= 0", name="ck_renewal_nonnegative"),
        Index(
            "uq_one_active_session_per_subject",
            "subject_hash",
            unique=True,
            postgresql_where=text("state IN ('issued','active','renewing','renewed')"),
        ),
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assignment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoint_assignment.id"), nullable=False
    )
    subject_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    credential_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    renewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(String(120))
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    correlation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    client_instance_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ip_network: Mapped[str | None] = mapped_column(INET)
    user_agent_hash: Mapped[str | None] = mapped_column(String(64))
    mock_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    provisioner_type: Mapped[str] = mapped_column(String(32), nullable=False, default="mock")
    renewal_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class SipAuditEvent(Base):
    __tablename__ = "audit_event"
    __table_args__ = (Index("ix_audit_event_occurred_at", "occurred_at"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_subject_hash: Mapped[str | None] = mapped_column(String(64))
    actor_role: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    assignment_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    request_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    source_ip_network: Mapped[str | None] = mapped_column(INET)
    reason_code: Mapped[str | None] = mapped_column(String(80))
    policy_version: Mapped[str] = mapped_column(String(24), nullable=False)
    metadata_json: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class SipIdempotencyRecord(Base):
    __tablename__ = "idempotency_record"
    __table_args__ = (UniqueConstraint("subject_hash", "operation", "key_hash"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    subject_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    operation: Mapped[str] = mapped_column(String(24), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_reference: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    state: Mapped[str] = mapped_column(String(24), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SipCredentialRotation(Base):
    __tablename__ = "credential_rotation"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sip_session.id"), nullable=False)
    previous_fingerprint: Mapped[str | None] = mapped_column(String(64))
    new_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    encryption_key_version: Mapped[str] = mapped_column(String(24), nullable=False)
    rotated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    overlap_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(String(40), nullable=False)
    request_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class SipSchemaState(Base):
    __tablename__ = "schema_state"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(40), nullable=False)
    service_min_version: Mapped[str] = mapped_column(String(40), nullable=False)
    service_max_version: Mapped[str | None] = mapped_column(String(40))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
