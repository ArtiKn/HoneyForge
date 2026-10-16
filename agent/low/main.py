"""Low-interaction SSH Trap Agent."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from uuid import UUID

from honeyforge_low import (
    AgentClient,
    EventQueue,
    JsonLogFormatter,
    LowHttpAgent,
    LowHttpAttackSessionRegistry,
    LowMySqlAgent,
    LowSshAgent,
    LowUdpAgent,
)
from agent.low.beacon import BeaconSchedule, BeaconSettings
from process_masking import apply_process_masking, resolve_process_name
from profile_runtime import ProfileRuntime, TrapService, report_runtime_health

log_handler = logging.StreamHandler()
log_handler.setFormatter(JsonLogFormatter())
logging.basicConfig(level=logging.INFO, handlers=[log_handler])
log = logging.getLogger(resolve_process_name())

DELIVERY_BATCH_LIMIT = 500


async def _fetch_configuration(client: AgentClient) -> dict[str, Any]:
    """Wait for the Control Center to return this Trap's configuration.

    A freshly started stack may not be reachable yet, and an Agent that lost
    its Trap secret must not crash-loop; it keeps retrying with backoff so an
    operator can restore the Trap and the Agent recovers on its own.
    """

    delay = 2.0
    while True:
        try:
            return await client.fetch_configuration()
        except (OSError, URLError, ValueError) as exc:
            reload_on_auth_error(client, exc)
            log.exception("Trap configuration fetch failed; retrying in %.0fs", delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 15.0)


def reload_on_auth_error(client: AgentClient, exc: BaseException) -> None:
    """Reload the on-disk Trap secret when the center rejects our credentials."""

    if isinstance(exc, HTTPError) and exc.code == 401:
        client.reload_secret()


async def run() -> None:
    """Apply the assigned Low SSH profile and continuously deliver events."""

    log.info("started as %s", apply_process_masking())
    secret_file = Path(os.environ["TRAP_SECRET_FILE"])
    trap_secret = secret_file.read_text(encoding="utf-8").strip()
    ca_file = os.getenv("CENTER_CA_FILE")
    client = AgentClient(
        os.environ["CENTER_URL"],
        trap_secret,
        ca_file=Path(ca_file) if ca_file else None,
        secret_file=secret_file,
    )
    configuration = await _fetch_configuration(client)
    if configuration["interaction_level"] != "low":
        raise RuntimeError("Low Trap Agent requires a low-interaction Trap Profile")
    queue = EventQueue(
        Path(os.environ["EVENT_QUEUE_PATH"]),
        max_events=int(os.getenv("EVENT_QUEUE_MAX_EVENTS", "100000")),
        max_bytes=int(os.getenv("EVENT_QUEUE_MAX_BYTES", str(256 * 1024 * 1024))),
    )
    http_sessions = LowHttpAttackSessionRegistry()

    def configured_services(config: dict[str, Any]) -> list[TrapService]:
        if config["interaction_level"] != "low":
            raise RuntimeError(
                "Low Trap Agent requires a low-interaction Trap Profile"
            )
        result: list[TrapService] = []
        logging_settings = config.get("logging") or {}
        common = {
            "trap_id": UUID(config["trap_id"]),
            "host": os.getenv("LISTEN_HOST", "0.0.0.0"),
            "queue": queue,
            "max_payload_bytes": int(logging_settings.get("max_payload_bytes", 4096)),
            "capture_credentials": bool(logging_settings.get("capture_credentials", True)),
            "capture_http_bodies": bool(logging_settings.get("capture_http_bodies", True)),
        }
        for definition in config["services"]:
            protocol = definition["protocol"]
            emulator = definition.get("emulator_settings", {})
            settings = {
                **common,
                "port": int(definition["internal_port"]),
                "banner": definition.get("banner"),
                "response_delay_ms": int(emulator.get("response_delay_ms") or 0),
                "response_jitter_ms": int(emulator.get("response_jitter_ms") or 0),
            }
            if protocol == "ssh":
                service: TrapService = LowSshAgent(
                    **{
                        **settings,
                        "banner": definition.get("banner")
                        or "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
                    }
                )
            elif protocol == "http":
                service = LowHttpAgent(**settings, session_registry=http_sessions)
            elif protocol == "udp":
                service = LowUdpAgent(**settings)
            elif protocol == "mysql":
                service = LowMySqlAgent(**settings)
            else:
                raise RuntimeError(f"Unsupported Low service protocol: {protocol}")
            result.append(service)
        return result

    runtime = ProfileRuntime(configured_services)
    health_interval = float(os.getenv("HEALTH_INTERVAL_SECONDS", "30"))
    profile_interval = float(os.getenv("PROFILE_CHECK_INTERVAL_SECONDS", "30"))
    delivery_interval = float(os.getenv("DELIVERY_INTERVAL_SECONDS", "1"))
    schedule = BeaconSchedule(
        BeaconSettings.from_masking(
            configuration.get("masking"), fallback_interval=delivery_interval
        )
    )
    client.apply_masking(configuration.get("masking"))

    async def refreshed_configuration() -> dict[str, Any]:
        """Fetch the Trap Profile and adopt its camouflage settings (MASK-5)."""

        config = await client.fetch_configuration()
        schedule.update(
            BeaconSettings.from_masking(
                config.get("masking"), fallback_interval=delivery_interval
            )
        )
        client.apply_masking(config.get("masking"))
        return config

    next_health_at = 0.0
    next_profile_at = asyncio.get_running_loop().time() + profile_interval
    try:
        await runtime.start(configuration)
        while True:
            try:
                await client.deliver_pending(
                    queue, limit=schedule.next_batch_limit(DELIVERY_BATCH_LIMIT)
                )
            except (OSError, URLError, ValueError) as exc:
                reload_on_auth_error(client, exc)
                log.exception("Security Event delivery failed; events remain queued")
            now = asyncio.get_running_loop().time()
            if now >= next_profile_at:
                try:
                    if await runtime.refresh(refreshed_configuration):
                        log.info(
                            "Applied Trap Profile change (enabled=%s, version=%s)",
                            runtime.enabled,
                            runtime.active_profile_version,
                        )
                except (OSError, URLError, RuntimeError, ValueError) as exc:
                    reload_on_auth_error(client, exc)
                    log.exception("Trap Profile check or apply failed")
                next_profile_at = now + schedule.jittered(profile_interval)
            if now >= next_health_at:
                try:
                    await report_runtime_health(
                        client,
                        queue,
                        agent_version=os.getenv("AGENT_VERSION", "0.1.0"),
                        runtime=runtime,
                    )
                except (OSError, URLError, ValueError) as exc:
                    reload_on_auth_error(client, exc)
                    log.exception("Agent Health Report delivery failed")
                else:
                    next_health_at = now + schedule.jittered(health_interval)
            await asyncio.sleep(schedule.next_delay())
    finally:
        await runtime.stop()
        queue.close()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
