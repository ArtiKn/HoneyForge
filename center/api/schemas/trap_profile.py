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


class DecoyCredential(BaseModel):
    """Plausible-looking account a decoy service accepts (FR-C1)."""

    model_config = ConfigDict(extra="forbid")

    service: Literal["ssh", "http", "mysql"] | None = None
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)


class TrapLoggingSettings(BaseModel):
    """What the Agent records from attacker interaction (FR-C1)."""

    model_config = ConfigDict(extra="forbid")

    capture_credentials: bool = True
    capture_commands: bool = True
    capture_http_bodies: bool = True
    max_payload_bytes: int = Field(default=4096, ge=0, le=1_048_576)


class TrapMaskingSettings(BaseModel):
    """Channel camouflage parameters delivered to the Agent (FR-C1, MASK)."""

    model_config = ConfigDict(extra="forbid")

    beacon_interval_seconds: int | None = Field(default=None, ge=1, le=86_400)
    beacon_jitter_seconds: int | None = Field(default=None, ge=0, le=86_400)
    user_agent: str | None = Field(default=None, max_length=256)


class TrapProfileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    interaction_level: Literal["low", "medium"]
    services: list[TrapServiceDefinition] = Field(min_length=1)
    decoy_credentials: list[DecoyCredential] = Field(default_factory=list)
    logging: TrapLoggingSettings = Field(default_factory=TrapLoggingSettings)
    masking: TrapMaskingSettings = Field(default_factory=TrapMaskingSettings)


class TrapProfileRead(TrapProfileCreate):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    version: int
    is_archived: bool
    created_at: datetime
    updated_at: datetime


class TrapProfileUpdate(TrapProfileCreate):
    pass

