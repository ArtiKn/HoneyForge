"""Create the initial HoneyForge schema.

Revision ID: 20261012_0001
Revises:
Create Date: 2026-10-12
"""

from collections.abc import Sequence

from alembic import op

from center.api.models import Base

revision: str = "20261012_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind(), checkfirst=False)


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind(), checkfirst=False)

