from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class TrapEmulatorSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    shell: Literal["fixed"] | None = None
    max_attempts: int | None = Field(default=None, ge=1, le=100)
    response_delay_ms: int | None = Field(default=None, ge=0, le=10_000)
    response_jitter_ms: int | None = Field(
        default=None,
        ge=0,
        le=10_000,
        description=(
            "Random spread added to every response so reply timings never "
            "repeat with machine precision (MASK-6)."
        ),
    )


class TrapServiceDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: Literal["ssh", "http", "mysql", "udp"]
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
    max_payload_bytes: int = Field(
        default=4096, ge=0, le=1_048_576,
        description="Byte limit per captured field (UTF-8 for text); zero redacts data. Wire limits still apply.",
    )


class TrapMaskingSettings(BaseModel):
    """Channel camouflage parameters delivered to the Agent (FR-C1, MASK)."""

    model_config = ConfigDict(extra="forbid")

    beacon_interval_seconds: int | None = Field(default=None, ge=1, le=86_400)
    beacon_jitter_seconds: int | None = Field(default=None, ge=0, le=86_400)
    user_agent: str | None = Field(default=None, max_length=256)


class TrapProfileDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    interaction_level: Literal["low", "medium"]
    services: list[TrapServiceDefinition] = Field(min_length=1)
    decoy_credentials: list[DecoyCredential] = Field(default_factory=list)
    logging: TrapLoggingSettings = Field(default_factory=TrapLoggingSettings)
    masking: TrapMaskingSettings = Field(default_factory=TrapMaskingSettings)


class TrapProfileCreate(TrapProfileDefinition):
    @model_validator(mode="after")
    def supported_services(self) -> "TrapProfileCreate":
        if self.interaction_level == "medium" and any(
            service.protocol == "udp" for service in self.services
        ):
            raise ValueError("Для уровня Medium доступны SSH, HTTP и MySQL. UDP поддерживается только на уровне Low")
        for service in self.services:
            banner = service.banner
            if banner is not None and (not banner.strip() or any(ord(char) < 32 or ord(char) == 127 for char in banner)):
                raise ValueError("Баннер должен быть непустой строкой без управляющих символов")
        ports = [("udp" if service.protocol == "udp" else "tcp", service.internal_port) for service in self.services]
        if len(ports) != len(set(ports)):
            raise ValueError("Сервисы одного транспорта должны использовать разные порты")
        return self


class TrapProfileRead(TrapProfileDefinition):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    version: int
    is_archived: bool
    created_at: datetime
    updated_at: datetime


class TrapProfileUpdate(TrapProfileCreate):
    pass

