import asyncio
import json
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from uuid import uuid4

import pytest

from agent.low.honeyforge_low import AgentClient, EventQueue, LowSshAgent


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


async def _wait_for_events(queue: EventQueue, *, count: int) -> None:
    for _ in range(100):
        if queue.pending_count() == count:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"expected {count} queued events")


async def test_delivery_requires_trusted_tls_and_acknowledges_queue(
    tmp_path: Path,
) -> None:
    certificate = tmp_path / "center.crt"
    private_key = tmp_path / "center.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
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
