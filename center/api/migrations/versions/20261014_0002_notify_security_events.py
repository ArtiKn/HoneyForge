"""Notify API processes after Security Events commit.

Revision ID: 20261014_0002
Revises: 20261012_0001
Create Date: 2026-10-14
"""

from collections.abc import Sequence

from alembic import op


revision: str = "20261014_0002"
down_revision: str | None = "20261012_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION notify_security_event_inserted()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            PERFORM pg_notify('security_events', NEW.id::text);
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER security_events_notify_after_insert
        AFTER INSERT ON security_events
        FOR EACH ROW EXECUTE FUNCTION notify_security_event_inserted()
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER security_events_notify_after_insert ON security_events"
    )
    op.execute("DROP FUNCTION notify_security_event_inserted()")
