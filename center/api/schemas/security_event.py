import base64
import binascii
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
    session_expired: bool = False


class HttpRequestPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: str = Field(min_length=1, max_length=16)
    path: str = Field(min_length=1, max_length=2048)
    http_version: Literal["HTTP/1.0", "HTTP/1.1"]
    bytes_received: int = Field(ge=0)


class AuthenticationAttemptPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=256)
    password: str = Field(max_length=1024)
    accepted: bool


class CommandEnteredPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str = Field(max_length=4096)


class CommandEnteredV2Payload(CommandEnteredPayload):
    cwd: str = Field(max_length=1024)


class CapturedPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["tcp", "udp", "http_body"]
    encoding: Literal["base64"]
    data: str = Field(max_length=87384)
    bytes_received: int = Field(ge=0)
    bytes_captured: int = Field(ge=0, le=65536)
    truncated: bool
    redacted: bool
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def consistent_bytes(self) -> "CapturedPayload":
        try:
            decoded = base64.b64decode(self.data, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("data must be base64") from exc
        if len(decoded) != self.bytes_captured or self.bytes_captured > self.bytes_received:
            raise ValueError("inconsistent capture length")
        if self.truncated != (self.bytes_captured < self.bytes_received):
            raise ValueError("inconsistent truncation flag")
        if self.redacted and (self.data or self.sha256 is not None):
            raise ValueError("redacted payload cannot contain data or digest")
        return self


class DatabaseQueryPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(max_length=4096)
    database: str = Field(max_length=128)
    succeeded: bool


class DatabaseAuthenticationPayload(AuthenticationAttemptPayload):
    auth_scheme: Literal["mysql_native_password"]
    auth_response: str = Field(max_length=128)
    auth_challenge: str = Field(max_length=128)


class SecurityEventSchema(BaseModel):
    """Wire contract shared by agents and the telemetry endpoint."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    schema_version: Literal[1, 2] = 1
    trap_id: UUID
    attack_session_id: UUID
    event_type: Literal[
        "connection_opened",
        "authentication_attempt",
        "command_entered",
        "http_request",
        "connection_closed",
        "payload_received",
        "database_query",
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
            "authentication_attempt": AuthenticationAttemptPayload,
            "command_entered": CommandEnteredPayload,
            "http_request": HttpRequestPayload,
            "connection_closed": ConnectionClosedPayload,
        }
        if self.schema_version == 2:
            payload_types.update(
                payload_received=CapturedPayload, database_query=DatabaseQueryPayload,
                command_entered=CommandEnteredV2Payload,
            )
            if self.event_type == "authentication_attempt" and self.target_service == "mysql":
                payload_types["authentication_attempt"] = DatabaseAuthenticationPayload
        if self.event_type not in payload_types:
            raise ValueError("event_type requires schema_version 2")
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

