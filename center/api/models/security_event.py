import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from center.api.models.base import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("idx_security_events_received_at", "received_at"),
        Index("idx_security_events_received_id", "received_at", "id"),
        Index("idx_security_events_trap", "trap_id", "received_at"),
        Index(
            "idx_security_events_attack_session", "attack_session_id", "received_at"
        ),
        Index("idx_security_events_source_ip", "source_ip", "received_at"),
        Index("idx_security_events_type", "event_type"),
        CheckConstraint(
            "event_type IN ('connection_opened', 'authentication_attempt', "
            "'command_entered', 'http_request', 'connection_closed', 'payload_received', 'database_query')",
            name="event_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    schema_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    trap_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("traps.id", ondelete="RESTRICT"), nullable=False
    )
    attack_session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("attack_sessions.id", ondelete="RESTRICT"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ip: Mapped[str] = mapped_column(INET, nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer)
    target_service: Mapped[str | None] = mapped_column(String(32))
    target_port: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    trap: Mapped["Trap"] = relationship(back_populates="security_events")  # noqa: F821
    attack_session: Mapped["AttackSession"] = relationship(  # noqa: F821
        back_populates="security_events"
    )

