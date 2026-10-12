"""Telemetry collector stub (task 6.1).

Placeholder process for the center stack; ingest and normalization are
implemented by the backend role (role 2, Collector).
"""

from __future__ import annotations

import asyncio
import logging
import signal

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("collector")


async def run() -> None:
    """Run the collector placeholder loop."""
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    log.info("collector started")
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=30)
        except asyncio.TimeoutError:
            pass
    log.info("collector stopped")


if __name__ == "__main__":
    asyncio.run(run())
