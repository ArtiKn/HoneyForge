import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, String, text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from center.api.models.base import Base, CreatedAtMixin


class Trap(CreatedAtMixin, Base):
    __tablename__ = "traps"
    __table_args__ = (
        Index("idx_traps_status", "status", postgresql_where=text("status <> 'offline'")),
        CheckConstraint(
            "status IN ('provisioning', 'online', 'degraded', 'offline', 'revoked')",
            name="status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    trap_profile_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("trap_profiles.id", ondelete="RESTRICT"), nullable=False
    )
    ip_address: Mapped[str | None] = mapped_column(INET)
    hostname: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="provisioning", nullable=False)
    is_archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    agent_version: Mapped[str | None] = mapped_column(String(64))
    region: Mapped[str | None] = mapped_column(String(128))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    agent_meta: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    trap_profile: Mapped["TrapProfile"] = relationship(back_populates="traps")  # noqa: F821
    security_events: Mapped[list["SecurityEvent"]] = relationship(  # noqa: F821
        back_populates="trap"
    )
    attack_sessions: Mapped[list["AttackSession"]] = relationship(  # noqa: F821
        back_populates="trap"
    )

