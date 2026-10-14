from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SecurityEventSchema(BaseModel):
    """Wire contract shared by agents and the telemetry endpoint."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    schema_version: int = Field(default=1, ge=1)
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
    source_ip: str
    source_port: int | None = Field(default=None, ge=0, le=65535)
    target_service: str | None = None
    target_port: int = Field(ge=0, le=65535)
    payload: dict[str, Any] = Field(default_factory=dict)

