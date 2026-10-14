import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from center.api.models.base import Base


class AttackSession(Base):
    __tablename__ = "attack_sessions"
    __table_args__ = (
        Index("idx_attack_sessions_trap", "trap_id", "started_at"),
        Index("idx_attack_sessions_source_ip", "source_ip"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trap_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("traps.id", ondelete="RESTRICT"), nullable=False
    )
    source_ip: Mapped[str] = mapped_column(INET, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    session_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )

    trap: Mapped["Trap"] = relationship(back_populates="attack_sessions")  # noqa: F821
    security_events: Mapped[list["SecurityEvent"]] = relationship(  # noqa: F821
        back_populates="attack_session"
    )

