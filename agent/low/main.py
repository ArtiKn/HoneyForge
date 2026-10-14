"""Low-interaction SSH Trap Agent."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from urllib.error import URLError
from uuid import UUID

from honeyforge_low import AgentClient, EventQueue, LowSshAgent

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
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
    queue = EventQueue(Path(os.environ["EVENT_QUEUE_PATH"]))
    agent = LowSshAgent(
        trap_id=UUID(configuration["trap_id"]),
        host=os.getenv("LISTEN_HOST", "0.0.0.0"),
        port=int(ssh_service["internal_port"]),
        banner=banner,
        queue=queue,
    )
    await agent.start()
    log.info("Low SSH Trap started on port %s", agent.port)
    try:
        while True:
            try:
                await client.deliver_pending(queue)
            except (OSError, URLError, ValueError):
                log.exception("Security Event delivery failed; events remain queued")
            await asyncio.sleep(1)
    finally:
        await agent.stop()
        queue.close()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
