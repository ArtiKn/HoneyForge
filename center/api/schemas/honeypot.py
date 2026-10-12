from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class HoneypotCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    profile_id: UUID
    ip_address: str | None = None
    hostname: str | None = None
    region: str | None = None
    agent_meta: dict[str, Any] = Field(default_factory=dict)


class HoneypotRead(HoneypotCreate):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: Literal["online", "offline", "degraded"] | str
    agent_version: str | None = None
    last_seen_at: datetime | None = None
    created_at: datetime

