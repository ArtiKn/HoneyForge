import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from center.api.models.base import Base, CreatedAtMixin


class TrapProfile(CreatedAtMixin, Base):
    __tablename__ = "trap_profiles"
    __table_args__ = (
        CheckConstraint("interaction_level IN ('low', 'medium')", name="interaction_level"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    interaction_level: Mapped[str] = mapped_column(String(16), nullable=False)
    services: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    banners: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict, nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    decoy_credentials: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    logging: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    masking: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    version: Mapped[int] = mapped_column(default=1, nullable=False)
    is_archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    traps: Mapped[list["Trap"]] = relationship(back_populates="trap_profile")  # noqa: F821

