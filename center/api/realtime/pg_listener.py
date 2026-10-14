import asyncio
import logging
from uuid import UUID

import asyncpg
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from center.api.models import SecurityEvent
from center.api.realtime.ws_manager import ConnectionManager
from center.api.schemas.security_event import SecurityEventRead


CHANNEL = "security_events"
APPLICATION_NAME = "honeyforge-security-event-listener"
logger = logging.getLogger(__name__)


def asyncpg_dsn(database_url: str) -> str:
    return database_url.replace("postgresql+asyncpg://", "postgresql://", 1)


class SecurityEventRelay:
    """Turn durable event IDs into process-local WebSocket broadcasts."""

    def __init__(
        self,
        database_url: str,
        connections: ConnectionManager,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        self._database_url = database_url
        self._connections = connections
        self._engine: AsyncEngine | None = None
        if session_factory is None:
            self._engine = create_async_engine(database_url, pool_pre_ping=True)
            session_factory = async_sessionmaker(
                self._engine, expire_on_commit=False, class_=AsyncSession
            )
        self._session_factory = session_factory
        self._connection: asyncpg.Connection | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._runner: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._ready: asyncio.Future[None] | None = None

    async def start(self) -> None:
        if self._runner is not None:
            return
        self._stop.clear()
        self._ready = asyncio.get_running_loop().create_future()
        self._runner = asyncio.create_task(self._listen_forever())
        await self._ready

    async def stop(self) -> None:
        await self._connections.listener_stopped()
        self._stop.set()
        runner, self._runner = self._runner, None
        if runner is not None:
            await runner
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)
        if self._engine is not None:
            await self._engine.dispose()

    async def _listen_forever(self) -> None:
        retry_delay = 0.25
        while not self._stop.is_set():
            terminated = asyncio.Event()
            connection: asyncpg.Connection | None = None
            try:
                connection = await asyncpg.connect(
                    asyncpg_dsn(self._database_url),
                    server_settings={"application_name": APPLICATION_NAME},
                )
                connection.add_termination_listener(lambda _connection: terminated.set())
                await connection.add_listener(CHANNEL, self._on_notification)
                self._connection = connection
                await self._connections.listener_started()
                if self._ready is not None and not self._ready.done():
                    self._ready.set_result(None)
                retry_delay = 0.25
                stop_waiter = asyncio.create_task(self._stop.wait())
                termination_waiter = asyncio.create_task(terminated.wait())
                done, pending = await asyncio.wait(
                    (stop_waiter, termination_waiter),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for waiter in pending:
                    waiter.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                if termination_waiter in done and not self._stop.is_set():
                    logger.warning("PostgreSQL Security Event listener disconnected")
                    await self._connections.listener_stopped()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if self._ready is not None and not self._ready.done():
                    self._ready.set_exception(exc)
                    return
                logger.exception("PostgreSQL Security Event listener failed")
                await self._connections.listener_stopped()
            finally:
                if self._connection is connection:
                    self._connection = None
                if connection is not None and not connection.is_closed():
                    await connection.remove_listener(CHANNEL, self._on_notification)
                    await connection.close()
            if self._stop.is_set():
                break
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=retry_delay)
            except TimeoutError:
                retry_delay = min(retry_delay * 2, 10)

    def _on_notification(
        self,
        _connection: asyncpg.Connection,
        _pid: int,
        _channel: str,
        payload: str,
    ) -> None:
        task = asyncio.create_task(self._load_and_broadcast(payload))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _load_and_broadcast(self, payload: str) -> None:
        try:
            event_id = UUID(payload)
        except ValueError:
            logger.warning("Ignoring malformed Security Event notification")
            return
        try:
            async with self._session_factory() as session:
                event = await session.get(SecurityEvent, event_id)
                if event is None:
                    return
                message = SecurityEventRead.model_validate(event).model_dump(mode="json")
            await self._connections.broadcast(message)
        except Exception:
            logger.exception("Could not relay committed Security Event %s", event_id)

