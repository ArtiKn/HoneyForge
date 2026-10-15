"""Low-interaction SSH Trap Agent."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any
from urllib.error import URLError
from uuid import UUID

from honeyforge_low import (
    AgentClient,
    EventQueue,
    JsonLogFormatter,
    LowHttpAgent,
    LowHttpAttackSessionRegistry,
    LowMySqlAgent,
    LowSshAgent,
)
from process_masking import apply_process_masking, resolve_process_name
from profile_runtime import ProfileRuntime, TrapService, report_runtime_health

log_handler = logging.StreamHandler()
log_handler.setFormatter(JsonLogFormatter())
logging.basicConfig(level=logging.INFO, handlers=[log_handler])
log = logging.getLogger(resolve_process_name())


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
    )
    configuration = await client.fetch_configuration()
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
        common = {
            "trap_id": UUID(config["trap_id"]),
            "host": os.getenv("LISTEN_HOST", "0.0.0.0"),
            "queue": queue,
        }
        for definition in config["services"]:
            protocol = definition["protocol"]
            emulator = definition.get("emulator_settings", {})
            settings = {
                **common,
                "port": int(definition["internal_port"]),
                "banner": definition.get("banner"),
                "response_delay_ms": int(emulator.get("response_delay_ms") or 0),
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
    next_health_at = 0.0
    next_profile_at = asyncio.get_running_loop().time() + profile_interval
    try:
        await runtime.start(configuration)
        while True:
            try:
                await client.deliver_pending(queue)
            except (OSError, URLError, ValueError):
                log.exception("Security Event delivery failed; events remain queued")
            now = asyncio.get_running_loop().time()
            if now >= next_profile_at:
                try:
                    if await runtime.refresh(client.fetch_configuration):
                        log.info(
                            "Applied Trap Profile change (enabled=%s, version=%s)",
                            runtime.enabled,
                            runtime.active_profile_version,
                        )
                except (OSError, URLError, RuntimeError, ValueError):
                    log.exception("Trap Profile check or apply failed")
                next_profile_at = now + profile_interval
            if now >= next_health_at:
                try:
                    await report_runtime_health(
                        client,
                        queue,
                        agent_version=os.getenv("AGENT_VERSION", "0.1.0"),
                        runtime=runtime,
                    )
                except (OSError, URLError, ValueError):
                    log.exception("Agent Health Report delivery failed")
                else:
                    next_health_at = now + health_interval
            await asyncio.sleep(delivery_interval)
    finally:
        await runtime.stop()
        queue.close()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
