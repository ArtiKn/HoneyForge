from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

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
    is_archived: bool
    agent_version: str | None = None
    last_seen_at: datetime | None = None
    created_at: datetime


class TrapProvisioned(TrapRead):
    enrollment_token: str


class EnrollmentRequest(BaseModel):
    enrollment_token: str = Field(min_length=32, max_length=256)


class EnrollmentResponse(BaseModel):
    trap_id: UUID
    trap_secret: str


class AgentHealthReport(BaseModel):
    agent_version: str = Field(min_length=1, max_length=64)
    active_profile_version: int = Field(ge=1)
    buffer_depth: int = Field(ge=0)
    configuration_errors: list[str] = Field(default_factory=list, max_length=20)


class RotationResponse(BaseModel):
    trap_secret: str


class AgentConfiguration(BaseModel):
    trap_id: UUID
    profile_version: int
    interaction_level: Literal["low", "medium"]
    services: list[TrapServiceDefinition]

