"""Medium-interaction honeypot agent stub (tasks 3.2, 3.3, 3.4, 6.2).

Placeholder process for the honeypot fleet skeleton. Fake SSH/HTTP emulators,
the fake shell and the masked telemetry channel are implemented by the
security role (role 1).
"""

from __future__ import annotations

import asyncio
import logging
import os

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(os.getenv("PROCESS_NAME", "agent"))


async def run() -> None:
    """Run the medium honeypot placeholder loop."""
    log.info(
        "medium agent started: id=%s center=%s",
        os.getenv("HONEYPOT_ID", "unknown"),
        os.getenv("CENTER_URL", ""),
    )
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
