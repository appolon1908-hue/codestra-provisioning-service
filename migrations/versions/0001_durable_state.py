"""Durable PostgreSQL state for mock SIP provisioning."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_durable_state"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    uid, dt = postgresql.UUID(as_uuid=True), sa.DateTime(timezone=True)
    op.create_table(
        "endpoint_assignment",
        sa.Column("id", uid, primary_key=True),
        sa.Column("subject_hash", sa.String(64), nullable=False),
        sa.Column("endpoint_name", sa.String(80), nullable=False),
        sa.Column("endpoint_numeric_id", sa.Integer),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("assigned_at", dt, nullable=False),
        sa.Column("updated_at", dt, nullable=False),
        sa.Column("last_session_at", dt),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("created_by_hash", sa.String(64)),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.Column(
            "metadata_json", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.UniqueConstraint("subject_hash"),
        sa.UniqueConstraint("endpoint_name"),
        sa.CheckConstraint("endpoint_name <> '6101'", name="ck_endpoint_not_6101"),
    )
    op.create_table(
        "sip_session",
        sa.Column("id", uid, primary_key=True),
        sa.Column("assignment_id", uid, sa.ForeignKey("endpoint_assignment.id"), nullable=False),
        sa.Column("subject_hash", sa.String(64), nullable=False),
        sa.Column("credential_fingerprint", sa.String(64), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("created_at", dt, nullable=False),
        sa.Column("activated_at", dt),
        sa.Column("expires_at", dt, nullable=False),
        sa.Column("renewed_at", dt),
        sa.Column("revoked_at", dt),
        sa.Column("revoke_reason", sa.String(120)),
        sa.Column("request_id", uid, nullable=False),
        sa.Column("correlation_id", uid, nullable=False),
        sa.Column("client_instance_hash", sa.String(64), nullable=False),
        sa.Column("source_ip_network", postgresql.INET),
        sa.Column("user_agent_hash", sa.String(64)),
        sa.Column("mock_mode", sa.Boolean, nullable=False),
        sa.Column("provisioner_type", sa.String(32), nullable=False),
        sa.Column("renewal_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.CheckConstraint("renewal_count >= 0", name="ck_renewal_nonnegative"),
    )
    op.create_index("ix_sip_session_subject_hash", "sip_session", ["subject_hash"])
    op.create_index("ix_sip_session_expires_at", "sip_session", ["expires_at"])
    op.create_index(
        "uq_one_active_session_per_subject",
        "sip_session",
        ["subject_hash"],
        unique=True,
        postgresql_where=sa.text("state IN ('issued','active','renewing','renewed')"),
    )
    op.create_table(
        "audit_event",
        sa.Column("id", uid, primary_key=True),
        sa.Column("occurred_at", dt, nullable=False),
        sa.Column("actor_subject_hash", sa.String(64)),
        sa.Column("actor_role", sa.String(64)),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("result", sa.String(32), nullable=False),
        sa.Column("session_id", uid),
        sa.Column("assignment_id", uid),
        sa.Column("request_id", uid),
        sa.Column("correlation_id", uid),
        sa.Column("source_ip_network", postgresql.INET),
        sa.Column("reason_code", sa.String(80)),
        sa.Column("policy_version", sa.String(24), nullable=False),
        sa.Column(
            "metadata_json", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("previous_hash", sa.String(64)),
        sa.Column("event_hash", sa.String(64), nullable=False, unique=True),
    )
    op.create_index("ix_audit_event_occurred_at", "audit_event", ["occurred_at"])
    op.create_table(
        "idempotency_record",
        sa.Column("id", uid, primary_key=True),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("subject_hash", sa.String(64), nullable=False),
        sa.Column("operation", sa.String(24), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("response_status", sa.Integer),
        sa.Column("response_reference", uid),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("created_at", dt, nullable=False),
        sa.Column("expires_at", dt, nullable=False),
        sa.UniqueConstraint("subject_hash", "operation", "key_hash"),
    )
    op.create_table(
        "credential_rotation",
        sa.Column("id", uid, primary_key=True),
        sa.Column("session_id", uid, sa.ForeignKey("sip_session.id"), nullable=False),
        sa.Column("previous_fingerprint", sa.String(64)),
        sa.Column("new_fingerprint", sa.String(64), nullable=False),
        sa.Column("encryption_key_version", sa.String(24), nullable=False),
        sa.Column("rotated_at", dt, nullable=False),
        sa.Column("overlap_expires_at", dt),
        sa.Column("reason", sa.String(40), nullable=False),
        sa.Column("request_id", uid),
    )
    op.create_table(
        "schema_state",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("schema_version", sa.String(40), nullable=False),
        sa.Column("service_min_version", sa.String(40), nullable=False),
        sa.Column("service_max_version", sa.String(40)),
        sa.Column("updated_at", dt, nullable=False),
    )
    op.execute(
        "INSERT INTO schema_state "
        "(id,schema_version,service_min_version,updated_at) "
        "VALUES (1,'1','0.2.0',now())"
    )


def downgrade() -> None:
    op.drop_table("schema_state")
    op.drop_table("credential_rotation")
    op.drop_table("idempotency_record")
    op.drop_table("audit_event")
    op.drop_index("uq_one_active_session_per_subject", table_name="sip_session")
    op.drop_index("ix_sip_session_expires_at", table_name="sip_session")
    op.drop_index("ix_sip_session_subject_hash", table_name="sip_session")
    op.drop_table("sip_session")
    op.drop_table("endpoint_assignment")
