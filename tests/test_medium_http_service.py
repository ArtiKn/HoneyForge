import asyncio
from pathlib import Path
from uuid import uuid4

import pytest

from agent.low.honeyforge_low import EventQueue
from agent.medium.http_service import HttpAttackSessionRegistry, MediumHttpService

pytestmark = pytest.mark.asyncio


async def test_medium_http_exposes_fake_login_and_admin_flow(tmp_path: Path) -> None:
    queue = EventQueue(tmp_path / "medium-http.sqlite3")
    service = MediumHttpService(
        trap_id=uuid4(), host="127.0.0.1", port=0, queue=queue
    )
    await service.start()
    marker = tmp_path / "must-not-exist"
    try:
        login = await _request(service.port, b"GET /login HTTP/1.1\r\nHost: trap\r\n\r\n")
        assert login.startswith(b"HTTP/1.1 200 OK")
        assert b"Operations Console" in login

        body = f"username=root&password=touch+{marker}".encode()
        authenticated = await _request(
            service.port,
            b"POST /login HTTP/1.1\r\nHost: trap\r\nContent-Type: application/x-www-form-urlencoded\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body,
        )
        assert authenticated.startswith(b"HTTP/1.1 302 Found")
        cookie = next(
            line for line in authenticated.split(b"\r\n")
            if line.startswith(b"Set-Cookie: hf_admin=")
        ).split(b";", 1)[0].removeprefix(b"Set-Cookie: ")

        admin = await _request(
            service.port,
            b"GET /admin HTTP/1.1\r\nHost: trap\r\nCookie: " + cookie + b"\r\n\r\n",
        )
        assert b"System Overview" in admin
        assert b"3 nodes online" in admin
        assert not marker.exists()
        await _wait_for_events(queue, 10)
    finally:
        await service.stop()

    events = queue.pending(limit=20)
    assert [event["event_type"] for event in events].count("http_request") == 3
    authentication = next(
        event for event in events if event["event_type"] == "authentication_attempt"
    )
    assert authentication["payload"] == {
        "username": "root",
        "password": f"touch {marker}",
        "accepted": True,
    }
    assert len({event["attack_session_id"] for event in events}) == 1
    assert {event["target_service"] for event in events} == {"http"}


async def test_medium_http_admin_requires_session_bound_cookie(tmp_path: Path) -> None:
    queue = EventQueue(tmp_path / "medium-http-cookie.sqlite3")
    service = MediumHttpService(
        trap_id=uuid4(), host="127.0.0.1", port=0, queue=queue
    )
    await service.start()
    try:
        response = await _request(
            service.port,
            b"GET /admin HTTP/1.1\r\nHost: trap\r\n"
            b"Cookie: not_hf_admin=fake-session\r\n\r\n",
        )
    finally:
        await service.stop()
    assert response.startswith(b"HTTP/1.1 302 Found")
    assert b"Location: /login" in response


async def test_medium_http_enforces_request_and_connection_limits(tmp_path: Path) -> None:
    queue = EventQueue(tmp_path / "medium-http-limits.sqlite3")
    service = MediumHttpService(
        trap_id=uuid4(),
        host="127.0.0.1",
        port=0,
        queue=queue,
        connection_limit=1,
        idle_timeout_seconds=0.1,
        max_input_bytes=64,
    )
    await service.start()
    try:
        first_reader, first_writer = await asyncio.open_connection(
            "127.0.0.1", service.port
        )
        second_reader, second_writer = await asyncio.open_connection(
            "127.0.0.1", service.port
        )
        assert await second_reader.read() == b""
        second_writer.close()
        await second_writer.wait_closed()
        first_writer.write(b"GET /login HTTP/1.1\r\nX-Large: " + b"x" * 80 + b"\r\n\r\n")
        await first_writer.drain()
        assert await first_reader.read() == b""
        first_writer.close()
        await first_writer.wait_closed()
        await _wait_for_events(queue, 2)
    finally:
        await service.stop()

    assert [event["event_type"] for event in queue.pending(limit=10)] == [
        "connection_opened",
        "connection_closed",
    ]


async def test_medium_http_closes_attack_session_after_inactivity(tmp_path: Path) -> None:
    queue = EventQueue(tmp_path / "medium-http-session.sqlite3")
    service = MediumHttpService(
        trap_id=uuid4(), host="127.0.0.1", port=0, queue=queue,
        session_timeout_seconds=0.05,
    )
    await service.start()
    try:
        await _request(service.port, b"GET /login HTTP/1.1\r\nHost: trap\r\n\r\n")
        await asyncio.sleep(0.08)
        await _request(service.port, b"GET /login HTTP/1.1\r\nHost: trap\r\n\r\n")
        await _wait_for_events(queue, 7)
    finally:
        await service.stop()

    events = queue.pending(limit=20)
    opened = [event for event in events if event["event_type"] == "connection_opened"]
    assert opened[0]["attack_session_id"] != opened[1]["attack_session_id"]
    expired = [event for event in events if event["payload"].get("session_expired")]
    assert len(expired) == 1
    assert expired[0]["attack_session_id"] == opened[0]["attack_session_id"]


async def test_medium_http_registry_keeps_session_across_service_replacement(
    tmp_path: Path,
) -> None:
    queue = EventQueue(tmp_path / "medium-http-reload.sqlite3")
    registry = HttpAttackSessionRegistry(timeout_seconds=60)
    first = MediumHttpService(
        trap_id=uuid4(), host="127.0.0.1", port=0, queue=queue,
        session_registry=registry,
    )
    await first.start()
    try:
        await _request(first.port, b"GET /login HTTP/1.1\r\nHost: trap\r\n\r\n")
    finally:
        await first.stop()

    replacement = MediumHttpService(
        trap_id=first.trap_id, host="127.0.0.1", port=0, queue=queue,
        session_registry=registry,
    )
    await replacement.start()
    try:
        await _request(
            replacement.port, b"GET /login HTTP/1.1\r\nHost: trap\r\n\r\n"
        )
    finally:
        await replacement.stop()

    events = queue.pending(limit=20)
    assert len({event["attack_session_id"] for event in events}) == 1
    queue.close()


async def _request(port: int, request: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(request)
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    return response


async def _wait_for_events(queue: EventQueue, count: int) -> None:
    for _ in range(100):
        if queue.pending_count() >= count:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"expected at least {count} events")
