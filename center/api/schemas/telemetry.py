from pydantic import BaseModel, ConfigDict

from center.api.schemas.event import EventSchema


class TelemetryBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[EventSchema]

