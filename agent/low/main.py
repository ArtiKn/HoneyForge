"""Low-interaction SSH Trap Agent."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from urllib.error import URLError
from uuid import UUID

from honeyforge_low import AgentClient, EventQueue, JsonLogFormatter, LowSshAgent

log_handler = logging.StreamHandler()
log_handler.setFormatter(JsonLogFormatter())
logging.basicConfig(level=logging.INFO, handlers=[log_handler])
log = logging.getLogger(os.getenv("PROCESS_NAME", "agent"))


async def run() -> None:
    """Apply the assigned Low SSH profile and continuously deliver events."""

    secret_file = Path(os.environ["TRAP_SECRET_FILE"])
    trap_secret = secret_file.read_text(encoding="utf-8").strip()
    client = AgentClient(
        os.environ["CENTER_URL"],
        trap_secret,
        ca_file=Path(os.environ["CENTER_CA_FILE"]),
    )
    configuration = await client.fetch_configuration()
    if configuration["interaction_level"] != "low":
        raise RuntimeError("Low SSH Agent requires a low-interaction Trap Profile")
    ssh_service = next(
        service
        for service in configuration["services"]
        if service["protocol"] == "ssh"
    )
    banner = ssh_service.get("banner") or "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
    queue = EventQueue(
        Path(os.environ["EVENT_QUEUE_PATH"]),
        max_events=int(os.getenv("EVENT_QUEUE_MAX_EVENTS", "100000")),
        max_bytes=int(os.getenv("EVENT_QUEUE_MAX_BYTES", str(256 * 1024 * 1024))),
    )
    agent = LowSshAgent(
        trap_id=UUID(configuration["trap_id"]),
        host=os.getenv("LISTEN_HOST", "0.0.0.0"),
        port=int(ssh_service["internal_port"]),
        banner=banner,
        queue=queue,
    )
    await agent.start()
    log.info("Low SSH Trap started on port %s", agent.port)
    health_interval = float(os.getenv("HEALTH_INTERVAL_SECONDS", "30"))
    delivery_interval = float(os.getenv("DELIVERY_INTERVAL_SECONDS", "1"))
    next_health_at = 0.0
    try:
        while True:
            try:
                await client.deliver_pending(queue)
            except (OSError, URLError, ValueError):
                log.exception("Security Event delivery failed; events remain queued")
            now = asyncio.get_running_loop().time()
            if now >= next_health_at:
                try:
                    await client.report_health(
                        queue,
                        agent_version=os.getenv("AGENT_VERSION", "0.1.0"),
                        active_profile_version=configuration["profile_version"],
                        configuration_errors=[],
                    )
                except (OSError, URLError, ValueError):
                    log.exception("Agent Health Report delivery failed")
                else:
                    next_health_at = now + health_interval
            await asyncio.sleep(delivery_interval)
    finally:
        await agent.stop()
        queue.close()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
