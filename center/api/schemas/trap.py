from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from center.api.schemas.trap_profile import TrapServiceDefinition


class TrapCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    trap_profile_id: UUID
    ip_address: str | None = None
    hostname: str | None = None
    region: str | None = None
    agent_meta: dict[str, Any] = Field(default_factory=dict)


class TrapRead(TrapCreate):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: Literal["provisioning", "online", "degraded", "offline", "revoked"]
    display_status: Literal[
        "provisioning", "online", "degraded", "offline", "revoked", "stopped"
    ]
    enabled: bool
    is_archived: bool
    agent_version: str | None = None
    last_seen_at: datetime | None = None
    created_at: datetime


class TrapUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=128)
    hostname: str | None = Field(default=None, max_length=255)
    region: str | None = Field(default=None, max_length=128)
    agent_meta: dict[str, Any] | None = None
    trap_profile_id: UUID | None = None

    @field_validator("name", "agent_meta")
    @classmethod
    def _reject_null(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("must not be null")
        return value


class TrapProvisioned(TrapRead):
    enrollment_token: str


class EnrollmentTokenResponse(BaseModel):
    enrollment_token: str


class EnrollmentRequest(BaseModel):
    enrollment_token: str = Field(min_length=32, max_length=256)


class EnrollmentResponse(BaseModel):
    trap_id: UUID
    trap_secret: str


class BufferLossReport(BaseModel):
    dropped_events: int = Field(ge=1)
    dropped_bytes: int = Field(ge=1)
    first_dropped_at: datetime
    last_dropped_at: datetime

    @field_validator("first_dropped_at", "last_dropped_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("buffer loss timestamps must include a UTC offset")
        return value

    @model_validator(mode="after")
    def require_ordered_interval(self) -> "BufferLossReport":
        if self.last_dropped_at < self.first_dropped_at:
            raise ValueError("buffer loss interval is reversed")
        return self


class AgentHealthReport(BaseModel):
    agent_version: str = Field(min_length=1, max_length=64)
    active_profile_version: int = Field(ge=1)
    buffer_depth: int = Field(ge=0)
    configuration_errors: list[str] = Field(default_factory=list, max_length=20)
    buffer_loss: BufferLossReport | None = None
    enabled: bool | None = None


class RotationResponse(BaseModel):
    trap_secret: str


class AgentConfiguration(BaseModel):
    trap_id: UUID
    profile_version: int
    interaction_level: Literal["low", "medium"]
    enabled: bool
    services: list[TrapServiceDefinition]

