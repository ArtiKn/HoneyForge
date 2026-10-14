"""Index stable Security Event investigation queries.

Revision ID: 20261015_0003
Revises: 20261014_0002
Create Date: 2026-10-15
"""

from collections.abc import Sequence

from alembic import op


revision: str = "20261015_0003"
down_revision: str | None = "20261014_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "idx_security_events_received_id",
        "security_events",
        ["received_at", "id"],
    )
    op.create_index(
        "idx_security_events_attack_session",
        "security_events",
        ["attack_session_id", "received_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_security_events_attack_session", table_name="security_events")
    op.drop_index("idx_security_events_received_id", table_name="security_events")
