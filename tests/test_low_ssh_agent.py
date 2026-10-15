import asyncio
import json
import logging
import ssl
import threading
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from uuid import uuid4

import pytest

from agent.low.honeyforge_low import (
    AgentClient,
    EventQueue,
    JsonLogFormatter,
    LowHttpAgent,
    LowHttpAttackSessionRegistry,
    LowMySqlAgent,
    LowSshAgent,
)
from tests.support import create_test_certificate


pytestmark = pytest.mark.asyncio


async def test_tcp_connection_is_queued_as_one_ssh_attack_session(
    tmp_path: Path,
) -> None:
    queue = EventQueue(tmp_path / "events.sqlite3")
    trap_id = uuid4()
    banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
    agent = LowSshAgent(
        trap_id=trap_id,
        host="127.0.0.1",
        port=0,
        banner=banner,
        queue=queue,
    )

    await agent.start()
    bound_port = agent.port
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", bound_port)
        assert (await reader.readline()).decode().rstrip() == banner
        writer.close()
        await writer.wait_closed()
        await _wait_for_events(queue, count=2)
    finally:
        await agent.stop()

    events = queue.pending(limit=10)
    assert queue.journal_mode == "wal"
    assert [event["event_type"] for event in events] == [
        "connection_opened",
        "connection_closed",
    ]
    assert {event["attack_session_id"] for event in events} == {
        events[0]["attack_session_id"]
    }
    assert {event["trap_id"] for event in events} == {str(trap_id)}
    assert all(event["schema_version"] == 1 for event in events)
    assert all(event["observed_at"].endswith("+00:00") for event in events)
    assert events[0]["source_ip"] == "127.0.0.1"
    assert events[0]["target_service"] == "ssh"
    assert events[0]["target_port"] == bound_port


async def test_http_service_returns_static_response_and_normalizes_request(
    tmp_path: Path,
) -> None:
    queue = EventQueue(tmp_path / "http.sqlite3")
    agent = LowHttpAgent(
        trap_id=uuid4(), host="127.0.0.1", port=0, queue=queue, max_input_bytes=1024
    )
    await agent.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", agent.port)
        writer.write(b"GET /admin?probe=1 HTTP/1.1\r\n")
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(b"Host: trap\r\n\r\n")
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        await _wait_for_events(queue, count=3)
    finally:
        await agent.stop()

    assert response.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"HoneyForge" in response
    events = queue.pending(limit=10)
    assert [event["event_type"] for event in events] == [
        "connection_opened",
        "http_request",
        "connection_closed",
    ]
    assert events[1]["payload"] == {
        "method": "GET",
        "path": "/admin?probe=1",
        "http_version": "HTTP/1.1",
        "bytes_received": 43,
    }
    assert events[0]["target_service"] == "http"
    assert {event["attack_session_id"] for event in events} == {
        events[0]["attack_session_id"]
    }


async def test_low_http_applies_response_delay(tmp_path: Path) -> None:
    queue = EventQueue(tmp_path / "http-delay.sqlite3")
    agent = LowHttpAgent(
        trap_id=uuid4(),
        host="127.0.0.1",
        port=0,
        queue=queue,
        response_delay_ms=300,
    )
    await agent.start()
    try:
        loop = asyncio.get_running_loop()
        started = loop.time()
        reader, writer = await asyncio.open_connection("127.0.0.1", agent.port)
        writer.write(b"GET / HTTP/1.1\r\nHost: trap\r\n\r\n")
        await writer.drain()
        response = await reader.read()
        elapsed = loop.time() - started
        writer.close()
        await writer.wait_closed()
        await _wait_for_events(queue, count=3)
    finally:
        await agent.stop()

    assert response.startswith(b"HTTP/1.1 200 OK\r\n")
    assert elapsed >= 0.2, elapsed


async def test_mysql_service_returns_handshake_and_enforces_input_limit(
    tmp_path: Path,
) -> None:
    queue = EventQueue(tmp_path / "mysql.sqlite3")
    agent = LowMySqlAgent(
        trap_id=uuid4(), host="127.0.0.1", port=0, queue=queue, max_input_bytes=8
    )
    await agent.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", agent.port)
        handshake = await reader.readexactly(4)
        packet_length = int.from_bytes(handshake[:3], "little")
        payload = await reader.readexactly(packet_length)
        writer.write(b"x" * 9)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await _wait_for_events(queue, count=2)
    finally:
        await agent.stop()

    assert payload[0] == 10
    assert b"8.0.36-HoneyForge" in payload
    assert b"mysql_native_password\x00" in payload
    events = queue.pending(limit=10)
    assert [event["event_type"] for event in events] == [
        "connection_opened",
        "connection_closed",
    ]
    assert events[0]["target_service"] == "mysql"


async def test_http_service_rejects_connections_above_configured_limit(
    tmp_path: Path,
) -> None:
    queue = EventQueue(tmp_path / "http-limit.sqlite3")
    agent = LowHttpAgent(
        trap_id=uuid4(),
        host="127.0.0.1",
        port=0,
        queue=queue,
        connection_limit=1,
        idle_timeout_seconds=5,
    )
    await agent.start()
    try:
        first_reader, first_writer = await asyncio.open_connection(
            "127.0.0.1", agent.port
        )
        second_reader, second_writer = await asyncio.open_connection(
            "127.0.0.1", agent.port
        )
        assert await second_reader.read() == b""
        second_writer.close()
        await second_writer.wait_closed()
        first_writer.close()
        await first_writer.wait_closed()
        await _wait_for_events(queue, count=2)
    finally:
        await agent.stop()

    assert queue.pending_count() == 2
    assert first_reader is not None


async def test_http_source_reuses_attack_session_for_fifteen_minutes(
    tmp_path: Path,
) -> None:
    queue = EventQueue(tmp_path / "http-session.sqlite3")
    agent = LowHttpAgent(trap_id=uuid4(), host="127.0.0.1", port=0, queue=queue)
    await agent.start()
    try:
        for _ in range(2):
            reader, writer = await asyncio.open_connection("127.0.0.1", agent.port)
            writer.write(b"GET / HTTP/1.1\r\nHost: trap\r\n\r\n")
            await writer.drain()
            await reader.read()
            writer.close()
            await writer.wait_closed()
        await _wait_for_events(queue, count=6)
    finally:
        await agent.stop()

    events = queue.pending(limit=10)
    opened = [event for event in events if event["event_type"] == "connection_opened"]
    assert len(opened) == 2
    assert opened[0]["attack_session_id"] == opened[1]["attack_session_id"]


async def test_http_session_survives_ports_and_service_replacement(
    tmp_path: Path,
) -> None:
    queue = EventQueue(tmp_path / "http-shared-session.sqlite3")
    trap_id = uuid4()
    registry = LowHttpAttackSessionRegistry()
    first = LowHttpAgent(
        trap_id=trap_id,
        host="127.0.0.1",
        port=0,
        queue=queue,
        session_registry=registry,
    )
    second = LowHttpAgent(
        trap_id=trap_id,
        host="127.0.0.1",
        port=0,
        queue=queue,
        session_registry=registry,
    )
    await first.start()
    await second.start()
    try:
        for port in (first.port, second.port):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: trap\r\n\r\n")
            await writer.drain()
            await reader.read()
            writer.close()
            await writer.wait_closed()
    finally:
        await first.stop()
        await second.stop()

    replacement = LowHttpAgent(
        trap_id=trap_id,
        host="127.0.0.1",
        port=0,
        queue=queue,
        session_registry=registry,
    )
    await replacement.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", replacement.port)
        writer.write(b"GET / HTTP/1.1\r\nHost: trap\r\n\r\n")
        await writer.drain()
        await reader.read()
        writer.close()
        await writer.wait_closed()
        await _wait_for_events(queue, count=9)
    finally:
        await replacement.stop()

    opened = [
        event
        for event in queue.pending(limit=20)
        if event["event_type"] == "connection_opened"
    ]
    assert len(opened) == 3
    assert len({event["attack_session_id"] for event in opened}) == 1


async def test_http_session_closes_at_inactivity_boundary_without_next_request(
    tmp_path: Path,
) -> None:
    queue = EventQueue(tmp_path / "http-session-expiry.sqlite3")
    agent = LowHttpAgent(
        trap_id=uuid4(),
        host="127.0.0.1",
        port=0,
        queue=queue,
        session_registry=LowHttpAttackSessionRegistry(
            timeout=timedelta(milliseconds=20)
        ),
    )
    await agent.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", agent.port)
        writer.write(b"GET / HTTP/1.1\r\nHost: trap\r\n\r\n")
        await writer.drain()
        await reader.read()
        writer.close()
        await writer.wait_closed()
        await _wait_for_events(queue, count=4)
    finally:
        await agent.stop()

    expired = [
        event
        for event in queue.pending(limit=10)
        if event["payload"].get("session_expired")
    ]
    assert len(expired) == 1


async def _wait_for_events(queue: EventQueue, *, count: int) -> None:
    for _ in range(100):
        if queue.pending_count() == count:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"expected {count} queued events")


async def test_delivery_requires_trusted_tls_and_acknowledges_queue(
    tmp_path: Path,
) -> None:
    certificate, private_key = create_test_certificate(tmp_path, name="center")
    captured: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers["Content-Length"])
            payload = json.loads(self.rfile.read(length))
            captured.append(
                {
                    "path": self.path,
                    "authorization": self.headers["Authorization"],
                    "content_type": self.headers["Content-Type"],
                    "payload": payload,
                }
            )
            body = json.dumps(
                {"accepted": [event["id"] for event in payload["events"]]}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificate, private_key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    queue = EventQueue(tmp_path / "delivery.sqlite3")
    event_id = str(uuid4())
    queue.enqueue({"id": event_id})
    base_url = f"https://127.0.0.1:{server.server_port}"
    try:
        with pytest.raises(URLError):
            await AgentClient(base_url, "trap-secret").deliver_pending(queue)
        assert queue.pending_count() == 1

        delivered = await AgentClient(
            base_url, "trap-secret", ca_file=certificate
        ).deliver_pending(queue)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert delivered == 1
    assert queue.pending_count() == 0
    assert captured == [
        {
            "path": "/assets/v2/init",
            "authorization": "Bearer trap-secret",
            "content_type": "application/javascript",
            "payload": {"events": [{"id": event_id}]},
        }
    ]


async def test_stop_drains_an_open_connection_before_queue_closes(
    tmp_path: Path,
) -> None:
    queue = EventQueue(tmp_path / "shutdown.sqlite3")
    agent = LowSshAgent(
        trap_id=uuid4(),
        host="127.0.0.1",
        port=0,
        banner="SSH-2.0-test",
        queue=queue,
        idle_timeout_seconds=60,
    )
    await agent.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", agent.port)
    assert (await reader.readline()).startswith(b"SSH-2.0-")

    await agent.stop()
    queue.close()
    writer.close()
    await writer.wait_closed()

    verification = EventQueue(tmp_path / "shutdown.sqlite3")
    try:
        assert [event["event_type"] for event in verification.pending(limit=10)] == [
            "connection_opened",
            "connection_closed",
        ]
    finally:
        verification.close()


async def test_fifo_limits_evict_oldest_and_persist_buffer_loss(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "bounded.sqlite3"
    caplog.set_level(logging.WARNING)
    queue = EventQueue(path, max_events=2, max_bytes=1024)

    queue.enqueue({"id": "first", "value": "a"})
    queue.enqueue({"id": "second", "value": "bb"})
    queue.enqueue({"id": "third", "value": "ccc"})

    assert [event["id"] for event in queue.pending(limit=10)] == ["second", "third"]
    loss = queue.buffer_loss_report()
    assert loss is not None
    assert loss["dropped_events"] == 1
    assert loss["dropped_bytes"] == len(b'{"id":"first","value":"a"}')
    assert datetime.fromisoformat(loss["first_dropped_at"]).tzinfo is not None
    assert loss["last_dropped_at"] == loss["first_dropped_at"]
    assert "Security Event buffer overflow" in caplog.text
    queue.close()

    reopened = EventQueue(path, max_events=2, max_bytes=1024)
    try:
        assert reopened.buffer_loss_report()["dropped_events"] == 1
        reopened.acknowledge_buffer_loss()
        assert reopened.buffer_loss_report() is None
    finally:
        reopened.close()


async def test_pending_batch_caps_count_and_quarantines_an_oversized_record(
    tmp_path: Path,
) -> None:
    queue = EventQueue(tmp_path / "request-limits.sqlite3")
    for index in range(501):
        queue.enqueue({"id": f"small-{index}"})

    assert len(queue.pending_batch(max_events=500)) == 500

    oversized = "oversized"
    queue.acknowledge([f"small-{index}" for index in range(501)])
    queue.enqueue({"id": oversized, "payload": "x" * (1024 * 1024)})
    queue.enqueue({"id": "sendable"})

    assert queue.pending_batch() == [{"id": "sendable"}]
    assert queue.quarantined()[0]["event"]["id"] == oversized


async def test_quarantine_removes_only_the_rejected_record(tmp_path: Path) -> None:
    queue = EventQueue(tmp_path / "quarantine.sqlite3")
    queue.enqueue({"id": "valid"})
    queue.enqueue({"id": "invalid"})

    queue.quarantine("invalid", "schema validation failed")

    assert queue.pending(limit=10) == [{"id": "valid"}]
    assert queue.quarantined() == [
        {
            "event": {"id": "invalid"},
            "reason": "schema validation failed",
        }
    ]


async def test_delivery_bounds_request_and_removes_only_sent_acknowledged_ids(
    tmp_path: Path,
) -> None:
    certificate, private_key = create_test_certificate(tmp_path)
    captured: list[dict] = []
    future_id = str(uuid4())

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            payload = json.loads(raw)
            captured.append({"size": len(raw), "payload": payload})
            body = json.dumps(
                {
                    "accepted": [payload["events"][0]["id"], future_id],
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server, thread = _start_tls_server(Handler, certificate, private_key)
    queue = EventQueue(tmp_path / "bounded-delivery.sqlite3")
    event_ids = [str(uuid4()) for _ in range(502)]
    for event_id in event_ids:
        queue.enqueue({"id": event_id, "payload": "x" * 2200})
    queue.enqueue({"id": future_id, "payload": "future"})
    client = AgentClient(
        f"https://127.0.0.1:{server.server_port}",
        "trap-secret",
        ca_file=certificate,
    )
    try:
        delivered = await client.deliver_pending(queue)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert delivered == 1
    assert len(captured) == 1
    assert len(captured[0]["payload"]["events"]) < 500
    assert captured[0]["size"] <= 1024 * 1024
    assert [event["id"] for event in queue.pending(limit=1)] == [event_ids[1]]
    assert future_id in {event["id"] for event in queue.pending(limit=1000)}


async def test_permanently_invalid_record_is_quarantined_without_blocking_fifo(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    certificate, private_key = create_test_certificate(tmp_path)
    accepted: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            events = payload["events"]
            if any(event.get("invalid") for event in events):
                body = json.dumps(
                    {"detail": "schema validation failed: attacker-secret"}
                ).encode()
                self.send_response(422)
            else:
                accepted.extend(event["id"] for event in events)
                body = json.dumps({"accepted": accepted[-len(events) :]}).encode()
                self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server, thread = _start_tls_server(Handler, certificate, private_key)
    queue = EventQueue(tmp_path / "invalid-delivery.sqlite3")
    valid_before = str(uuid4())
    invalid = str(uuid4())
    valid_after = str(uuid4())
    queue.enqueue({"id": valid_before})
    queue.enqueue({"id": invalid, "invalid": True})
    queue.enqueue({"id": valid_after})
    client = AgentClient(
        f"https://127.0.0.1:{server.server_port}",
        "trap-secret",
        ca_file=certificate,
    )
    try:
        delivered = await client.deliver_pending(queue)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert delivered == 2
    assert accepted == [valid_before, valid_after]
    assert queue.pending_count() == 0
    assert queue.quarantined() == [
        {
            "event": {"id": invalid, "invalid": True},
            "reason": "schema validation failed: attacker-secret",
        }
    ]
    assert "attacker-secret" not in caplog.text


async def test_agent_json_logs_keep_operational_fields_structured() -> None:
    record = logging.LogRecord(
        "agent",
        logging.WARNING,
        __file__,
        1,
        "Security Event buffer overflow",
        (),
        None,
    )
    record.event_id = "event-1"
    record.event_bytes = 42

    rendered = json.loads(JsonLogFormatter().format(record))

    assert rendered == {
        "level": "WARNING",
        "logger": "agent",
        "message": "Security Event buffer overflow",
        "event_id": "event-1",
        "event_bytes": 42,
    }


async def test_buffer_loss_is_cleared_only_after_health_acknowledgement(
    tmp_path: Path,
) -> None:
    certificate, private_key = create_test_certificate(tmp_path)
    captured: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            captured.append(
                json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            )
            self.send_response(204)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    server, thread = _start_tls_server(Handler, certificate, private_key)
    queue = EventQueue(tmp_path / "loss-health.sqlite3", max_events=1)
    queue.enqueue({"id": "dropped"})
    queue.enqueue({"id": "retained"})
    client = AgentClient(
        f"https://127.0.0.1:{server.server_port}",
        "trap-secret",
        ca_file=certificate,
    )
    try:
        await client.report_health(
            queue,
            agent_version="0.1.0",
            active_profile_version=3,
            enabled=True,
            configuration_errors=[],
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert captured[0]["agent_version"] == "0.1.0"
    assert captured[0]["active_profile_version"] == 3
    assert captured[0]["enabled"] is True
    assert captured[0]["buffer_depth"] == 1
    assert captured[0]["buffer_loss"]["dropped_events"] == 1
    assert captured[0]["buffer_loss"]["dropped_bytes"] == len(b'{"id":"dropped"}')
    assert queue.buffer_loss_report() is None


def _start_tls_server(
    handler: type[BaseHTTPRequestHandler], certificate: Path, private_key: Path
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificate, private_key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
