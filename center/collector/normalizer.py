from typing import Any
from datetime import UTC, datetime

from center.api.schemas.security_event import SecurityEventSchema


def normalize(event: SecurityEventSchema | dict[str, Any]) -> dict[str, Any]:
    """Convert an event to a stable dictionary for later enrichment."""

    if isinstance(event, SecurityEventSchema):
        normalized = event.model_dump(mode="json")
    else:
        normalized = SecurityEventSchema.model_validate(event).model_dump(mode="json")
    normalized["received_at"] = datetime.now(UTC).isoformat()
    return normalized

