from typing import Any

from center.api.schemas.event import EventSchema


def normalize(event: EventSchema | dict[str, Any]) -> dict[str, Any]:
    """Convert an event to a stable dictionary for later enrichment."""

    if isinstance(event, EventSchema):
        return event.model_dump(mode="json")
    return EventSchema.model_validate(event).model_dump(mode="json")

