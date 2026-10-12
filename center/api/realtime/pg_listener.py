import asyncio
import json
from collections.abc import Awaitable, Callable

import asyncpg

from center.api.config import get_settings


def _asyncpg_dsn() -> str:
    return get_settings().database_url.replace("postgresql+asyncpg://", "postgresql://", 1)


async def listen(
    publish: Callable[[dict[str, object]], Awaitable[None]],
    stop: asyncio.Event | None = None,
) -> None:
    """Forward ``events_new`` PostgreSQL notifications to a publisher."""

    connection = await asyncpg.connect(_asyncpg_dsn())

    def on_notification(
        _connection: asyncpg.Connection, _pid: int, _channel: str, payload: str
    ) -> None:
        asyncio.create_task(publish(json.loads(payload)))

    await connection.add_listener("events_new", on_notification)
    try:
        if stop is None:
            await asyncio.Future()
        else:
            await stop.wait()
    finally:
        await connection.remove_listener("events_new", on_notification)
        await connection.close()

