"""Create the initial HoneyForge schema.

Revision ID: 20261012_0001
Revises:
Create Date: 2026-10-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20261012_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "trap_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("interaction_level", sa.String(16), nullable=False),
        sa.Column("services", postgresql.JSONB, nullable=False),
        sa.Column("banners", postgresql.JSONB, nullable=False),
        sa.Column("config", postgresql.JSONB, nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("is_archived", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("interaction_level IN ('low', 'medium')", name="interaction_level"),
    )
    op.create_table(
        "operators",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.String(128), nullable=False, unique=True),
        sa.Column("password_hash", sa.String, nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "traps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("trap_profile_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("trap_profiles.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("ip_address", postgresql.INET),
        sa.Column("hostname", sa.String(255)),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("is_archived", sa.Boolean, nullable=False),
        sa.Column("agent_version", sa.String(64)),
        sa.Column("region", sa.String(128)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("agent_meta", postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('provisioning', 'online', 'degraded', 'offline', 'revoked')", name="status"),
    )
    op.create_index("idx_traps_status", "traps", ["status"], postgresql_where=sa.text("status <> 'offline'"))
    op.create_table(
        "attack_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("trap_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("traps.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("source_ip", postgresql.INET, nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
        sa.Column("protocol", sa.String(32), nullable=False),
        sa.Column("metadata", postgresql.JSONB, nullable=False),
    )
    op.create_index("idx_attack_sessions_trap", "attack_sessions", ["trap_id", "started_at"])
    op.create_index("idx_attack_sessions_source_ip", "attack_sessions", ["source_ip"])
    op.create_table(
        "security_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("schema_version", sa.Integer, nullable=False),
        sa.Column("trap_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("traps.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("attack_session_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("attack_sessions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", postgresql.INET, nullable=False),
        sa.Column("source_port", sa.Integer),
        sa.Column("target_service", sa.String(32)),
        sa.Column("target_port", sa.Integer, nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False),
        sa.CheckConstraint("event_type IN ('connection_opened', 'authentication_attempt', 'command_entered', 'http_request', 'connection_closed')", name="event_type"),
    )
    op.create_index("idx_security_events_received_at", "security_events", ["received_at"])
    op.create_index("idx_security_events_trap", "security_events", ["trap_id", "received_at"])
    op.create_index("idx_security_events_source_ip", "security_events", ["source_ip", "received_at"])
    op.create_index("idx_security_events_type", "security_events", ["event_type"])
    op.create_table(
        "audit_entries",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("operator_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("operators.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("entity", sa.String(64), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True)),
        sa.Column("details", postgresql.JSONB, nullable=False),
        sa.Column("source_ip", postgresql.INET),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    for table_name in (
        "audit_entries",
        "security_events",
        "attack_sessions",
        "traps",
        "operators",
        "trap_profiles",
    ):
        op.drop_table(table_name)

