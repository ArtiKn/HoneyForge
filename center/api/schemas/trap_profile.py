from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TrapProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    interaction_level: Literal["low", "medium"]
    services: list[dict[str, Any]] = Field(default_factory=list)
    banners: dict[str, str] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)


class TrapProfileRead(TrapProfileCreate):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    version: int
    is_archived: bool
    created_at: datetime
    updated_at: datetime

