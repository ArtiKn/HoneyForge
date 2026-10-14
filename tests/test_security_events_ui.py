import json
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


def test_security_events_ui_renders_persisted_ssh_interaction() -> None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if chrome is None:
        pytest.skip("Chrome or Chromium is required for the Security Events UI test")
    web_root = Path(__file__).parent.parent / "center" / "web"
    events = [
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "schema_version": 1,
            "trap_id": "22222222-2222-2222-2222-222222222222",
            "attack_session_id": "33333333-3333-3333-3333-333333333333",
            "event_type": "connection_opened",
            "observed_at": "2026-10-14T12:00:00Z",
            "received_at": "2026-10-14T12:00:01Z",
            "source_ip": "192.0.2.44",
            "source_port": 54321,
            "target_service": "ssh",
            "target_port": 2222,
            "payload": {"banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"},
        }
    ]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/api/v1/security-events":
                page = {"items": events, "next_cursor": None}
                self._send("application/json", json.dumps(page).encode())
                return
            filename = self.path.lstrip("/") or "events.html"
            file_path = web_root / filename
            if not file_path.is_file():
                self.send_error(404)
                return
            body = file_path.read_bytes()
            content_type = {
                ".html": "text/html",
                ".css": "text/css",
                ".js": "text/javascript",
            }.get(file_path.suffix, "application/octet-stream")
            self._send(content_type, body)

        def _send(self, content_type: str, body: bytes) -> None:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [
                chrome,
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--virtual-time-budget=2000",
                "--dump-dom",
                f"http://127.0.0.1:{server.server_port}/events.html",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert "Connection opened" in result.stdout
    assert "192.0.2.44:54321" in result.stdout
    assert "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10" in result.stdout
