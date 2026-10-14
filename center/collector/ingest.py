"""Telemetry collector stub (task 6.1).

Placeholder process for the center stack; ingest and normalization are
implemented by the backend role.
"""
from collections.abc import Sequence
from typing import Any

from center.api.schemas.security_event import SecurityEventSchema
from center.collector.normalizer import normalize


def ingest(batch: Sequence[SecurityEventSchema | dict[str, Any]]) -> int:
    """Validate and normalize a batch; persistence is the next collector stage."""

    for event in batch:
        normalize(event)
    return len(batch)
