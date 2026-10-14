from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


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

