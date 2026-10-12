import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from center.api.models.base import Base


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("idx_events_ts", "ts"),
        Index("idx_events_honeypot", "honeypot_id", "ts"),
        Index("idx_events_src_ip", "src_ip", "ts"),
        Index("idx_events_type_sev", "type", "severity"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False
    )
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="SET NULL")
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    src_ip: Mapped[str] = mapped_column(INET, nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False)
    proto: Mapped[str] = mapped_column(String(8), nullable=False)
    service: Mapped[str | None] = mapped_column(String(32))
    username: Mapped[str | None] = mapped_column(String(255))
    password: Mapped[str | None] = mapped_column(String(255))
    command: Mapped[str | None] = mapped_column(String)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="info", nullable=False)
    geo_country: Mapped[str | None] = mapped_column(String(2))
    geo_city: Mapped[str | None] = mapped_column(String(128))
    geo_lat: Mapped[float | None] = mapped_column(Float)
    geo_lon: Mapped[float | None] = mapped_column(Float)

    honeypot: Mapped["Honeypot"] = relationship(back_populates="events")  # noqa: F821
    session: Mapped["Session | None"] = relationship(back_populates="events")  # noqa: F821

