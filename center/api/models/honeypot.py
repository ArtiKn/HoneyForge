import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from center.api.models.base import Base, CreatedAtMixin


class Honeypot(CreatedAtMixin, Base):
    __tablename__ = "honeypots"
    __table_args__ = (
        Index("idx_honeypots_status", "status", postgresql_where=text("status <> 'offline'")),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    profile_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="RESTRICT"), nullable=False
    )
    ip_address: Mapped[str | None] = mapped_column(INET)
    hostname: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="offline", nullable=False)
    agent_version: Mapped[str | None] = mapped_column(String(64))
    region: Mapped[str | None] = mapped_column(String(128))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    agent_meta: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    profile: Mapped["Profile"] = relationship(back_populates="honeypots")  # noqa: F821
    events: Mapped[list["Event"]] = relationship(back_populates="honeypot")  # noqa: F821
    sessions: Mapped[list["Session"]] = relationship(back_populates="honeypot")  # noqa: F821
    honeytokens: Mapped[list["Honeytoken"]] = relationship(back_populates="honeypot")  # noqa: F821

