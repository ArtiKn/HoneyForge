from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class EventSchema(BaseModel):
    """Wire contract shared by agents and the telemetry endpoint."""

    model_config = ConfigDict(extra="forbid")

    ts: datetime
    # Agents may use a deployment name (for example ``h1``); the collector
    # resolves it to the database UUID when persistence is implemented.
    honeypot_id: str = Field(min_length=1)
    src_ip: str
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    proto: str
    action: str
    creds: dict[str, Any] | None = None
    cmd: str | None = None
    raw: Any = None

