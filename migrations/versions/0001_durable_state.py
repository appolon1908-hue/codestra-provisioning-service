"""durable SIP state tables"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision = "0001_durable_state"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    uid = postgresql.UUID(as_uuid=True); dt = sa.DateTime(timezone=True)
    op.create_table("sip_endpoint_assignments", sa.Column("id", uid, primary_key=True), sa.Column("user_subject", sa.String(255), nullable=False, unique=True), sa.Column("endpoint_name", sa.String(80), nullable=False, unique=True), sa.Column("created_at", dt, nullable=False))
    op.create_table("sip_sessions", sa.Column("id", uid, primary_key=True), sa.Column("assignment_id", uid, sa.ForeignKey("sip_endpoint_assignments.id"), nullable=False), sa.Column("user_subject", sa.String(255), nullable=False), sa.Column("client_instance_hash", sa.String(64), nullable=False), sa.Column("credential_fingerprint", sa.String(64), nullable=False), sa.Column("status", sa.String(20), nullable=False), sa.Column("created_at", dt, nullable=False), sa.Column("expires_at", dt, nullable=False), sa.Column("absolute_expires_at", dt, nullable=False), sa.Column("revoked_at", dt), sa.Column("revoke_reason", sa.String(120)))
    op.create_index("ix_sip_sessions_user_subject", "sip_sessions", ["user_subject"])
    op.create_table("sip_audit_events", sa.Column("id", uid, primary_key=True), sa.Column("event_type", sa.String(80), nullable=False), sa.Column("actor_hash", sa.String(64), nullable=False), sa.Column("session_id", uid), sa.Column("request_id", sa.String(36), nullable=False), sa.Column("metadata_json", postgresql.JSONB, nullable=False), sa.Column("created_at", dt, nullable=False))
    op.create_table("sip_idempotency_records", sa.Column("id", uid, primary_key=True), sa.Column("actor_hash", sa.String(64), nullable=False), sa.Column("operation", sa.String(24), nullable=False), sa.Column("key_hash", sa.String(64), nullable=False), sa.Column("request_hash", sa.String(64), nullable=False), sa.Column("session_id", uid), sa.Column("safe_response", postgresql.JSONB, nullable=False), sa.Column("status_code", sa.Integer, nullable=False), sa.Column("completed", sa.Boolean, nullable=False), sa.Column("created_at", dt, nullable=False), sa.UniqueConstraint("actor_hash", "operation", "key_hash"))
    op.create_table("sip_credential_rotations", sa.Column("id", uid, primary_key=True), sa.Column("session_id", uid, sa.ForeignKey("sip_sessions.id"), nullable=False), sa.Column("credential_fingerprint", sa.String(64), nullable=False), sa.Column("issued_at", dt, nullable=False), sa.Column("expires_at", dt, nullable=False), sa.Column("revoked_at", dt))
    op.create_table("sip_schema_state", sa.Column("key", sa.String(80), primary_key=True), sa.Column("value", sa.String(255), nullable=False), sa.Column("updated_at", dt, nullable=False))

def downgrade() -> None:
    for table in ("sip_credential_rotations", "sip_idempotency_records", "sip_audit_events", "sip_sessions", "sip_endpoint_assignments", "sip_schema_state"): op.drop_table(table)
