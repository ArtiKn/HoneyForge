"""Add the Trap Profile decoy, logging, and masking settings (FR-C1).

Revision ID: 20261015_0005
Revises: 20261015_0004
Create Date: 2026-10-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20261015_0005"
down_revision: str | None = "20261015_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "trap_profiles",
        sa.Column(
            "decoy_credentials",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "trap_profiles",
        sa.Column(
            "logging",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.add_column(
        "trap_profiles",
        sa.Column(
            "masking",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("trap_profiles", "masking")
    op.drop_column("trap_profiles", "logging")
    op.drop_column("trap_profiles", "decoy_credentials")
