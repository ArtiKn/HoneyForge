"""Beacon cadence and exchange randomization (MASK-5, MASK-6).

The Trap Profile masking settings were already stored and delivered to the
Agent; these tests pin the part that was missing — the Agent now shapes its
beacon (variable interval, jitter, variable batch size), announces itself with
the configured User-Agent, and paces every attacker-visible reply with a random
spread so the decoy never answers with machine precision.
"""

import random

import pytest

from agent.low.beacon import (
    DEFAULT_JITTER_FRACTION,
    MINIMUM_DELAY_SECONDS,
    BeaconSchedule,
    BeaconSettings,
)
from agent.low.exchange_timing import ExchangeTiming
from agent.low.honeyforge_low import AgentClient


def test_masking_settings_drive_the_beacon_interval() -> None:
    settings = BeaconSettings.from_masking(
        {"beacon_interval_seconds": 45, "beacon_jitter_seconds": 7},
        fallback_interval=1,
    )
    assert settings.interval_seconds == 45
    assert settings.jitter_seconds == 7


def test_missing_masking_falls_back_to_the_environment_interval() -> None:
    for masking in (None, {}, {"beacon_interval_seconds": None}, {"beacon_interval_seconds": 0}):
        settings = BeaconSettings.from_masking(masking, fallback_interval=2)
        assert settings.interval_seconds == 2
        assert settings.jitter_seconds == pytest.approx(2 * DEFAULT_JITTER_FRACTION)


def test_jitter_is_capped_by_the_interval_and_ignores_junk() -> None:
    settings = BeaconSettings.from_masking(
        {"beacon_interval_seconds": 30, "beacon_jitter_seconds": "soon"},
        fallback_interval=1,
    )
    assert settings.jitter_seconds == pytest.approx(30 * DEFAULT_JITTER_FRACTION)

    oversized = BeaconSettings.from_masking(
        {"beacon_interval_seconds": 10, "beacon_jitter_seconds": 900}, fallback_interval=1
    )
    assert oversized.jitter_seconds == 10


def test_beacon_delays_stay_inside_the_configured_window() -> None:
    schedule = BeaconSchedule(
        BeaconSettings(interval_seconds=30, jitter_seconds=6),
        rng=random.Random(7),
    )
    delays = [schedule.next_delay() for _ in range(200)]
    assert all(24 <= delay <= 36 for delay in delays)
    assert len(set(delays)) > 1
    # The health and profile timers ride on the same jitter.
    assert all(19 <= schedule.jittered(25) <= 31 for _ in range(50))


def test_beacon_delays_never_drop_below_the_floor() -> None:
    schedule = BeaconSchedule(
        BeaconSettings(interval_seconds=0.5, jitter_seconds=5),
        rng=random.Random(3),
    )
    assert all(
        schedule.next_delay() >= MINIMUM_DELAY_SECONDS for _ in range(200)
    )


def test_beacon_without_jitter_stays_regular() -> None:
    schedule = BeaconSchedule(BeaconSettings(interval_seconds=12, jitter_seconds=0))
    assert [schedule.next_delay() for _ in range(5)] == [12.0] * 5


def test_beacon_batch_sizes_vary_between_requests() -> None:
    schedule = BeaconSchedule(
        BeaconSettings(interval_seconds=30, jitter_seconds=1), rng=random.Random(11)
    )
    limits = [schedule.next_batch_limit(500) for _ in range(50)]
    assert all(200 <= limit <= 500 for limit in limits)
    assert len(set(limits)) > 5
    # A tiny ceiling still delivers at least one event.
    assert schedule.next_batch_limit(1) == 1


def test_schedule_adopts_a_new_trap_profile_cadence() -> None:
    schedule = BeaconSchedule(BeaconSettings(interval_seconds=5, jitter_seconds=1))
    schedule.update(BeaconSettings(interval_seconds=300, jitter_seconds=30))
    assert schedule.settings.interval_seconds == 300
    assert all(270 <= schedule.next_delay() <= 330 for _ in range(50))


def test_exchange_timing_adds_a_random_spread_to_every_reply() -> None:
    timing = ExchangeTiming.from_emulator(
        {"response_delay_ms": 150, "response_jitter_ms": 350}, rng=random.Random(5)
    )
    delays = [timing.next_delay() for _ in range(200)]
    assert all(0.15 <= delay <= 0.5 for delay in delays)
    assert len(set(delays)) > 50


def test_exchange_timing_without_jitter_answers_exactly_when_configured() -> None:
    timing = ExchangeTiming.from_emulator({"response_delay_ms": 120})
    assert [timing.next_delay() for _ in range(5)] == [0.12] * 5
    assert ExchangeTiming.from_emulator(None).next_delay() == 0.0
    assert ExchangeTiming.from_emulator({"response_jitter_ms": -5}).next_delay() == 0.0


def test_configured_user_agent_replaces_the_transport_default() -> None:
    client = AgentClient("https://assets.cdn-static.example", "secret")
    assert client.apply_masking({"user_agent": "curl/8.5.0"}) == "curl/8.5.0"
    assert client._headers({"Authorization": "Bearer secret"}) == {
        "Authorization": "Bearer secret",
        "User-Agent": "curl/8.5.0",
    }
    client.apply_masking({"user_agent": None})
    assert client.user_agent is None
    assert "User-Agent" not in client._headers()


@pytest.mark.parametrize(
    "user_agent",
    ["", "   ", "bad\r\nInjected: 1", "x" * 257],
)
def test_unusable_user_agents_are_ignored(user_agent: str) -> None:
    client = AgentClient("https://assets.cdn-static.example", "secret")
    assert client.apply_masking({"user_agent": user_agent}) is None
    assert client.user_agent is None
    assert client.apply_masking(None) is None