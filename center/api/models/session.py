import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from center.api.models.base import Base


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (
        Index("idx_sessions_honeypot", "honeypot_id", "started_at"),
        Index("idx_sessions_src_ip", "src_ip"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False
    )
    src_ip: Mapped[str] = mapped_column(INET, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    credentials: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    commands_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    meta: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    honeypot: Mapped["Honeypot"] = relationship(back_populates="sessions")  # noqa: F821
    events: Mapped[list["Event"]] = relationship(back_populates="session")  # noqa: F821

