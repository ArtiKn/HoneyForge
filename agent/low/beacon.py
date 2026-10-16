"""Beacon cadence shaping for the masked Agent channel (MASK-5).

The Control Center delivers the Trap Profile masking settings; the Agent turns
them into a cadence that never looks metronomic: intervals drift around the
configured value and each request carries a different batch size. Without an
explicit jitter the schedule still varies by a third of the interval, because a
perfectly regular beacon is exactly what a scanner fingerprints.
"""

from __future__ import annotations

import random
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

MINIMUM_DELAY_SECONDS = 0.05
DEFAULT_JITTER_FRACTION = 0.3
MINIMUM_BATCH_RATIO = 0.4


def _number(value: Any, *, minimum: float) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number >= minimum else None


@dataclass(frozen=True)
class BeaconSettings:
    """Cadence of one Trap's beacon, as configured by the Trap Profile."""

    interval_seconds: float
    jitter_seconds: float = 0.0

    @classmethod
    def from_masking(
        cls,
        masking: Mapping[str, Any] | None,
        *,
        fallback_interval: float,
    ) -> "BeaconSettings":
        settings = masking or {}
        interval = _number(settings.get("beacon_interval_seconds"), minimum=MINIMUM_DELAY_SECONDS)
        if interval is None:
            interval = max(float(fallback_interval), MINIMUM_DELAY_SECONDS)
        jitter = _number(settings.get("beacon_jitter_seconds"), minimum=0.0)
        if jitter is None:
            jitter = interval * DEFAULT_JITTER_FRACTION
        return cls(
            interval_seconds=interval,
            jitter_seconds=min(jitter, interval),
        )


class BeaconSchedule:
    """Produce the next beacon delay and batch size for an Agent loop."""

    def __init__(
        self,
        settings: BeaconSettings,
        *,
        rng: random.Random | None = None,
    ) -> None:
        self._settings = settings
        self._rng = rng if rng is not None else random.SystemRandom()

    @property
    def settings(self) -> BeaconSettings:
        return self._settings

    def update(self, settings: BeaconSettings) -> None:
        """Adopt the cadence of a freshly fetched Trap Profile."""

        self._settings = settings

    def jittered(self, base_seconds: float) -> float:
        """Spread `base_seconds` by the configured jitter, never below the floor."""

        base = max(float(base_seconds), MINIMUM_DELAY_SECONDS)
        spread = max(self._settings.jitter_seconds, 0.0)
        if spread <= 0:
            return base
        return max(base + self._rng.uniform(-spread, spread), MINIMUM_DELAY_SECONDS)

    def next_delay(self) -> float:
        return self.jittered(self._settings.interval_seconds)

    def next_batch_limit(self, maximum: int) -> int:
        """Vary request sizes so consecutive beacons differ in weight (MASK-5)."""

        ceiling = max(int(maximum), 1)
        floor = max(1, int(ceiling * MINIMUM_BATCH_RATIO))
        if floor >= ceiling:
            return ceiling
        return self._rng.randint(floor, ceiling)