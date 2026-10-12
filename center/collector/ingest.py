from collections.abc import Sequence
from typing import Any

from center.api.schemas.event import EventSchema
from center.collector.normalizer import normalize


def ingest(batch: Sequence[EventSchema | dict[str, Any]]) -> int:
    """Validate and normalize a batch; persistence is the next collector stage."""

    for event in batch:
        normalize(event)
    return len(batch)

