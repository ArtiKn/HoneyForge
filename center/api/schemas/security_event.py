from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
    model_validator,
)


class ConnectionOpenedPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    banner: str = Field(min_length=1, max_length=1024)


class ConnectionClosedPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bytes_sent: int = Field(ge=0)


class SecurityEventSchema(BaseModel):
    """Wire contract shared by agents and the telemetry endpoint."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    schema_version: Literal[1] = 1
    trap_id: UUID
    attack_session_id: UUID
    event_type: Literal[
        "connection_opened",
        "authentication_attempt",
        "command_entered",
        "http_request",
        "connection_closed",
    ]
    observed_at: datetime
    source_ip: IPvAnyAddress
    source_port: int | None = Field(default=None, ge=0, le=65535)
    target_service: str | None = None
    target_port: int = Field(ge=0, le=65535)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_typed_payload(self) -> "SecurityEventSchema":
        payload_types = {
            "connection_opened": ConnectionOpenedPayload,
            "connection_closed": ConnectionClosedPayload,
        }
        payload_type = payload_types.get(self.event_type)
        if payload_type is not None:
            if self.source_port is None or self.target_service is None:
                raise ValueError(
                    "connection events require source_port and target_service"
                )
            self.payload = payload_type.model_validate(self.payload).model_dump()
        return self


class SecurityEventRead(SecurityEventSchema):
    model_config = ConfigDict(from_attributes=True)

    received_at: datetime


class SecurityEventPage(BaseModel):
    items: list[SecurityEventRead]
    next_cursor: str | None

