from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TrapEmulatorSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    shell: Literal["fixed"] | None = None
    max_attempts: int | None = Field(default=None, ge=1, le=100)
    response_delay_ms: int | None = Field(default=None, ge=0, le=10_000)


class TrapServiceDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: Literal["ssh", "http", "mysql"]
    internal_port: int = Field(ge=1, le=65535)
    banner: str | None = Field(default=None, max_length=1024)
    emulator_settings: TrapEmulatorSettings = Field(
        default_factory=TrapEmulatorSettings
    )


class TrapProfileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    interaction_level: Literal["low", "medium"]
    services: list[TrapServiceDefinition] = Field(min_length=1)


class TrapProfileRead(TrapProfileCreate):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    version: int
    is_archived: bool
    created_at: datetime
    updated_at: datetime


class TrapProfileUpdate(TrapProfileCreate):
    pass

