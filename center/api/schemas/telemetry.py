from pydantic import BaseModel, ConfigDict

from center.api.schemas.security_event import SecurityEventSchema


class TelemetryBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[SecurityEventSchema]

