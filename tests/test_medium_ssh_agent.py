import asyncio
from pathlib import Path
from uuid import uuid4

import pytest
import asyncssh

from agent.low.honeyforge_low import EventQueue
from agent.medium.main import MediumSshService

pytestmark = pytest.mark.asyncio


async def test_medium_ssh_accepts_credentials_and_runs_bounded_fake_shell(tmp_path: Path) -> None:
    queue = EventQueue(tmp_path / "medium.sqlite3")
    service = MediumSshService(trap_id=uuid4(), host="127.0.0.1", port=0, queue=queue)
    await service.start()
    try:
        async with asyncssh.connect(
            "127.0.0.1", port=service.port, username="root", password="hunter2",
            known_hosts=None,
        ) as connection:
            process = await connection.create_process()
            assert "Welcome" in await process.stdout.readuntil("$ ")
            process.stdin.write("pwd\n")
            assert "/home/root" in await process.stdout.readuntil("$ ")
            marker = tmp_path / "honeyforge-should-not-exist"
            process.stdin.write(f"touch {marker}\n")
            assert await process.stdout.readuntil("$ ") == "command not found\r\n$ "
            assert not marker.exists()
            process.stdin.write("exit\n")
            assert "logout" in await process.stdout.read()
        await _wait_for_events(queue, 6)
    finally:
        await service.stop()

    events = queue.pending(limit=20)
    assert [event["event_type"] for event in events] == [
        "connection_opened", "authentication_attempt", "command_entered",
        "command_entered", "command_entered", "connection_closed",
    ]
    assert events[1]["payload"] == {
        "username": "root", "password": "hunter2", "accepted": True
    }
    assert [event["payload"]["command"] for event in events[2:5]] == [
        "pwd", f"touch {tmp_path / 'honeyforge-should-not-exist'}", "exit"
    ]
    assert len({event["attack_session_id"] for event in events}) == 1


async def _wait_for_events(queue: EventQueue, count: int) -> None:
    for _ in range(100):
        if queue.pending_count() >= count:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"expected at least {count} events")


async def test_medium_ssh_honours_decoy_credentials(tmp_path: Path) -> None:
    queue = EventQueue(tmp_path / "medium-decoy.sqlite3")
    service = MediumSshService(
        trap_id=uuid4(),
        host="127.0.0.1",
        port=0,
        queue=queue,
        decoy_credentials=[
            {"username": "root", "password": "s3cret", "service": "ssh"}
        ],
    )
    await service.start()
    try:
        with pytest.raises(asyncssh.PermissionDenied):
            async with asyncssh.connect(
                "127.0.0.1",
                port=service.port,
                username="root",
                password="wrong",
                known_hosts=None,
            ):
                pass
        async with asyncssh.connect(
            "127.0.0.1",
            port=service.port,
            username="root",
            password="s3cret",
            known_hosts=None,
        ) as connection:
            process = await connection.create_process()
            assert "Welcome" in await process.stdout.readuntil("$ ")
            process.stdin.write("exit\n")
            assert "logout" in await process.stdout.read()
        await _wait_for_events(queue, 4)
    finally:
        await service.stop()

    attempts = [
        event["payload"]
        for event in queue.pending(limit=20)
        if event["event_type"] == "authentication_attempt"
    ]
    assert [attempt["accepted"] for attempt in attempts] == [False, True]


async def test_medium_ssh_applies_logging_settings(tmp_path: Path) -> None:
    queue = EventQueue(tmp_path / "medium-logging.sqlite3")
    service = MediumSshService(
        trap_id=uuid4(),
        host="127.0.0.1",
        port=0,
        queue=queue,
        capture_credentials=False,
        capture_commands=False,
    )
    await service.start()
    try:
        async with asyncssh.connect(
            "127.0.0.1",
            port=service.port,
            username="root",
            password="hunter2",
            known_hosts=None,
        ) as connection:
            process = await connection.create_process()
            await process.stdout.readuntil("$ ")
            process.stdin.write("whoami\n")
            await process.stdout.readuntil("$ ")
        await _wait_for_events(queue, 3)
    finally:
        await service.stop()

    events = queue.pending(limit=20)
    attempt = next(
        event for event in events if event["event_type"] == "authentication_attempt"
    )
    command = next(
        event for event in events if event["event_type"] == "command_entered"
    )
    assert attempt["payload"]["password"] == "<redacted>"
    assert attempt["payload"]["accepted"] is True
    assert command["payload"]["command"] == "<redacted>"


async def test_medium_ssh_applies_response_delay(tmp_path: Path) -> None:
    queue = EventQueue(tmp_path / "medium-delay.sqlite3")
    service = MediumSshService(
        trap_id=uuid4(),
        host="127.0.0.1",
        port=0,
        queue=queue,
        response_delay_ms=400,
    )
    await service.start()
    try:
        loop = asyncio.get_running_loop()
        async with asyncssh.connect(
            "127.0.0.1",
            port=service.port,
            username="root",
            password="hunter2",
            known_hosts=None,
        ) as connection:
            started = loop.time()
            process = await connection.create_process()
            assert "Welcome" in await process.stdout.readuntil("$ ")
            elapsed = loop.time() - started
    finally:
        await service.stop()
    assert elapsed >= 0.3, elapsed


async def test_medium_ssh_rejects_connections_above_limit(tmp_path: Path) -> None:
    queue = EventQueue(tmp_path / "medium-limit.sqlite3")
    service = MediumSshService(
        trap_id=uuid4(), host="127.0.0.1", port=0, queue=queue,
        connection_limit=1, idle_timeout_seconds=5,
    )
    await service.start()
    try:
        first_reader, first_writer = await asyncio.open_connection("127.0.0.1", service.port)
        second_reader, second_writer = await asyncio.open_connection("127.0.0.1", service.port)
        assert await second_reader.read() == b""
        second_writer.close()
        await second_writer.wait_closed()
        first_writer.close()
        await first_writer.wait_closed()
    finally:
        await service.stop()
    assert first_reader is not None
