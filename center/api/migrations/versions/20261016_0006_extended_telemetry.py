"""Support bounded payload captures and fake database queries (wire v2)."""
from alembic import op

revision = "20261016_0006"
down_revision = "20261015_0005"
branch_labels = None
depends_on = None

BASE = "'connection_opened', 'authentication_attempt', 'command_entered', 'http_request', 'connection_closed'"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_security_events_event_type"), "security_events", type_="check")
    op.create_check_constraint("event_type", "security_events", f"event_type IN ({BASE}, 'payload_received', 'database_query')")


def downgrade() -> None:
    # Old readers cannot deserialize v2 observations; never discard history.
    if op.get_bind().exec_driver_sql(
        "SELECT EXISTS (SELECT 1 FROM security_events WHERE schema_version = 2)"
    ).scalar():
        raise RuntimeError("Cannot downgrade while schema_version 2 Security Events exist")
    op.drop_constraint(op.f("ck_security_events_event_type"), "security_events", type_="check")
    op.create_check_constraint("event_type", "security_events", f"event_type IN ({BASE})")
