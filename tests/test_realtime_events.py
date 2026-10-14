import asyncio
import os
import subprocess
import sys
from datetime import UTC, datetime
from uuid import UUID, uuid4

import asyncpg
import pytest

from center.api.realtime.pg_listener import SecurityEventRelay
from center.api.realtime.ws_manager import ConnectionManager


pytestmark = pytest.mark.asyncio
CHANNEL = "security_events"


def _asyncpg_url(database_url: str) -> str:
    return database_url.replace("postgresql+asyncpg://", "postgresql://", 1)


@pytest.fixture
async def realtime_database_url() -> str:
    database_url = os.getenv("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("set TEST_DATABASE_URL to run realtime integration tests")
    environment = os.environ | {"DATABASE_URL": database_url}
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
    )
    yield database_url
    subprocess.run(
        [sys.executable, "-m", "alembic", "downgrade", "base"],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
    )


async def _seed_event_parents(connection: asyncpg.Connection) -> tuple[UUID, UUID]:
    profile_id = uuid4()
    trap_id = uuid4()
    attack_session_id = uuid4()
    await connection.execute(
        """
        INSERT INTO trap_profiles
            (id, name, interaction_level, services, banners, config, version,
             is_archived)
        VALUES ($1, $2, 'low', '[]', '{}', '{}', 1, false)
        """,
        profile_id,
        f"Realtime {profile_id}",
    )
    await connection.execute(
        """
        INSERT INTO traps
            (id, name, trap_profile_id, status, is_archived, agent_meta)
        VALUES ($1, $2, $3, 'online', false, '{}')
        """,
        trap_id,
        f"realtime-{trap_id}",
        profile_id,
    )
    await connection.execute(
        """
        INSERT INTO attack_sessions
            (id, trap_id, source_ip, started_at, protocol, metadata)
        VALUES ($1, $2, '192.0.2.20', $3, 'ssh', '{}')
        """,
        attack_session_id,
        trap_id,
        datetime.now(UTC),
    )
    return trap_id, attack_session_id


async def _insert_event(
    connection: asyncpg.Connection, trap_id: UUID, attack_session_id: UUID
) -> UUID:
    event_id = uuid4()
    now = datetime.now(UTC)
    await connection.execute(
        """
        INSERT INTO security_events
            (id, schema_version, trap_id, attack_session_id, event_type,
             observed_at, received_at, source_ip, source_port, target_service,
             target_port, payload)
        VALUES ($1, 1, $2, $3, 'connection_opened', $4, $4,
                '192.0.2.20', 49152, 'ssh', 22, '{"banner": "SSH-test"}')
        """,
        event_id,
        trap_id,
        attack_session_id,
        now,
    )
    return event_id


async def test_postgres_notifies_only_after_security_event_commit(
    realtime_database_url: str,
) -> None:
    listener = await asyncpg.connect(_asyncpg_url(realtime_database_url))
    writer = await asyncpg.connect(_asyncpg_url(realtime_database_url))
    notifications: asyncio.Queue[str] = asyncio.Queue()

    def receive(
        _connection: asyncpg.Connection, _pid: int, _channel: str, payload: str
    ) -> None:
        notifications.put_nowait(payload)

    await listener.add_listener(CHANNEL, receive)
    try:
        trap_id, attack_session_id = await _seed_event_parents(writer)
        committed_id = await _insert_event(writer, trap_id, attack_session_id)

        assert await asyncio.wait_for(notifications.get(), timeout=1) == str(
            committed_id
        )

        transaction = writer.transaction()
        await transaction.start()
        rolled_back_id = await _insert_event(writer, trap_id, attack_session_id)
        await transaction.rollback()

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(notifications.get(), timeout=0.1)
        assert rolled_back_id != committed_id
    finally:
        await listener.close()
        await writer.close()


class RecordingWebSocket:
    def __init__(self) -> None:
        self.messages: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        self.accepted = False
        self.closed = asyncio.Event()
        self.close_code: int | None = None

    async def accept(self) -> None:
        self.accepted = True

    async def send_json(self, message: dict[str, object]) -> None:
        self.messages.put_nowait(message)

    async def close(self, code: int) -> None:
        self.close_code = code
        self.closed.set()


async def test_each_api_process_loads_and_broadcasts_the_durable_event(
    realtime_database_url: str,
) -> None:
    first_manager = ConnectionManager()
    second_manager = ConnectionManager()
    first_socket = RecordingWebSocket()
    second_socket = RecordingWebSocket()
    first_relay = SecurityEventRelay(realtime_database_url, first_manager)
    second_relay = SecurityEventRelay(realtime_database_url, second_manager)

    await first_relay.start()
    await second_relay.start()
    await first_manager.connect(first_socket)  # type: ignore[arg-type]
    await second_manager.connect(second_socket)  # type: ignore[arg-type]
    writer = await asyncpg.connect(_asyncpg_url(realtime_database_url))
    try:
        trap_id, attack_session_id = await _seed_event_parents(writer)
        event_id = await _insert_event(writer, trap_id, attack_session_id)

        first = await asyncio.wait_for(first_socket.messages.get(), timeout=1)
        second = await asyncio.wait_for(second_socket.messages.get(), timeout=1)

        assert first == second
        assert first["id"] == str(event_id)
        assert first["event_type"] == "connection_opened"
        assert first["payload"] == {"banner": "SSH-test"}
    finally:
        await writer.close()
        await first_relay.stop()
        await second_relay.stop()


async def test_listener_disconnects_clients_and_resumes_after_postgres_drop(
    realtime_database_url: str,
) -> None:
    manager = ConnectionManager()
    disconnected_socket = RecordingWebSocket()
    relay = SecurityEventRelay(realtime_database_url, manager)
    await relay.start()
    await manager.connect(disconnected_socket)  # type: ignore[arg-type]
    writer = await asyncpg.connect(_asyncpg_url(realtime_database_url))
    try:
        terminated = await writer.fetchval(
            """
            SELECT pg_terminate_backend(pid)
            FROM pg_stat_activity
            WHERE application_name = 'honeyforge-security-event-listener'
              AND pid <> pg_backend_pid()
            LIMIT 1
            """
        )
        assert terminated is True
        await asyncio.wait_for(disconnected_socket.closed.wait(), timeout=1)
        assert disconnected_socket.close_code == 1012

        unavailable_socket = RecordingWebSocket()
        connected_during_outage = await manager.connect(  # type: ignore[arg-type]
            unavailable_socket
        )
        assert connected_during_outage is False
        assert unavailable_socket.close_code == 1013

        recovered_socket: RecordingWebSocket | None = None
        for _ in range(100):
            candidate = RecordingWebSocket()
            if await manager.connect(candidate):  # type: ignore[arg-type]
                recovered_socket = candidate
                break
            await asyncio.sleep(0.02)
        if recovered_socket is None:
            raise AssertionError("Security Event listener did not reconnect")

        trap_id, attack_session_id = await _seed_event_parents(writer)
        event_id = await _insert_event(writer, trap_id, attack_session_id)
        recovered = await asyncio.wait_for(recovered_socket.messages.get(), timeout=1)
        assert recovered["id"] == str(event_id)
    finally:
        await writer.close()
        await relay.stop()
