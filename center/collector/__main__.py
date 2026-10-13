"""Collector process entrypoint (tasks 2.1, 6.1).

Keeps the collector container alive as a separate service of the center stack.
Real batch draining and persistence are implemented by the backend role.
"""

from __future__ import annotations

import asyncio
import logging
import signal

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("collector")


async def run() -> None:
    """Run the collector loop and stop cleanly on SIGTERM/SIGINT."""

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    log.info("collector started")
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=30)
        except asyncio.TimeoutError:
            log.info("collector heartbeat")
    log.info("collector stopped")


if __name__ == "__main__":
    asyncio.run(run())
