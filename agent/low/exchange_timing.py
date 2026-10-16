"""Human-like pacing of emulated service responses (MASK-6).

Every attacker-visible exchange gets its own delay: the Trap Profile's
configured `response_delay_ms` plus a random slice of `response_jitter_ms`.
Replies therefore never come at a machine-perfect cadence, and a service never
answers faster than the operator asked for.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Mapping
from typing import Any


def _milliseconds(value: Any) -> float:
    if isinstance(value, bool) or value is None:
        return 0.0
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(number, 0.0) / 1000.0


class ExchangeTiming:
    """Base response delay and the jitter spread drawn around it."""

    def __init__(
        self,
        delay_seconds: float = 0.0,
        jitter_seconds: float = 0.0,
        *,
        rng: random.Random | None = None,
    ) -> None:
        self.delay_seconds = max(float(delay_seconds), 0.0)
        self.jitter_seconds = max(float(jitter_seconds), 0.0)
        self._rng = rng if rng is not None else random.SystemRandom()

    @classmethod
    def from_emulator(
        cls,
        settings: Mapping[str, Any] | None,
        *,
        rng: random.Random | None = None,
    ) -> "ExchangeTiming":
        emulator = settings or {}
        return cls(
            _milliseconds(emulator.get("response_delay_ms")),
            _milliseconds(emulator.get("response_jitter_ms")),
            rng=rng,
        )

    def next_delay(self) -> float:
        """Delay before the next reply: the configured minimum plus jitter."""

        if self.jitter_seconds <= 0:
            return self.delay_seconds
        return self.delay_seconds + self._rng.uniform(0.0, self.jitter_seconds)

    async def wait(self) -> float:
        """Pace this reply; returns the delay that was applied."""

        delay = self.next_delay()
        if delay > 0:
            await asyncio.sleep(delay)
        return delay