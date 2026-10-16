import json
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

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

    assert "Соединение открыто" in result.stdout
    assert "192.0.2.44:54321" in result.stdout
    assert "ID ловушки: 22222222-2222-2222-2222-222222222222" in result.stdout
    assert "ID сессии атаки: 33333333-3333-3333-3333-333333333333" in result.stdout
    assert "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10" in result.stdout


def test_security_events_ui_recovers_a_gap_and_deduplicates_realtime_events() -> None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if chrome is None:
        pytest.skip("Chrome or Chromium is required for the Security Events UI test")
    web_root = Path(__file__).parent.parent / "center" / "web"

    def event(number: int) -> dict[str, object]:
        return {
            "id": f"00000000-0000-0000-0000-{number:012d}",
            "schema_version": 1,
            "trap_id": "22222222-2222-2222-2222-222222222222",
            "attack_session_id": "33333333-3333-3333-3333-333333333333",
            "event_type": "connection_opened",
            "observed_at": f"2026-10-14T12:00:0{number}Z",
            "received_at": f"2026-10-14T12:00:0{number}Z",
            "source_ip": "192.0.2.44",
            "source_port": 54320 + number,
            "target_service": "ssh",
            "target_port": 22,
            "payload": {"banner": f"SSH-event-{number}"},
        }

    first, missed, live = event(1), event(2), event(3)
    requested_pages: list[str] = []
    snapshot_requests = 0
    fake_websocket = f"""
      class FakeWebSocket {{
        static attempts = 0;
        constructor() {{
          const attempt = ++FakeWebSocket.attempts;
          setTimeout(() => {{
            this.onopen?.();
            if (attempt === 1) {{
                  setTimeout(() => this.onmessage?.({{data: {json.dumps(json.dumps(live))}}}), 20);
              setTimeout(() => this.onclose?.(), 60);
            }} else {{
              setTimeout(() => this.onmessage?.({{data: {json.dumps(json.dumps(live))}}}), 20);
            }}
          }}, 0);
        }}
        close() {{}}
      }}
      window.WebSocket = FakeWebSocket;
    """

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            nonlocal snapshot_requests
            parsed = urlparse(self.path)
            if parsed.path == "/api/v1/security-events":
                requested_pages.append(self.path)
                cursor = parse_qs(parsed.query).get("cursor", [])
                if cursor:
                    page = {
                        "items": [],
                        "next_cursor": None,
                    }
                else:
                    snapshot_requests += 1
                    page = {
                        "items": (
                            [first]
                            if snapshot_requests < 3
                            else [live, missed, first]
                        ),
                            "next_cursor": "page-2",
                    }
                self._send("application/json", json.dumps(page).encode())
                return
            if parsed.path == "/fake-websocket.js":
                self._send("text/javascript", fake_websocket.encode())
                return
            file_path = web_root / (parsed.path.lstrip("/") or "events.html")
            if not file_path.is_file():
                self.send_error(404)
                return
            body = file_path.read_bytes()
            if file_path.name == "events.html":
                body = body.replace(
                    b'<script src="/events.js" defer></script>',
                    b'<script src="/fake-websocket.js"></script>'
                    b'<script src="/events.js" defer></script>',
                )
            self._send(
                {".html": "text/html", ".css": "text/css", ".js": "text/javascript"}.get(
                    file_path.suffix, "application/octet-stream"
                ),
                body,
            )

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
    page_filters = {
        "trap_id": str(first["trap_id"]),
        "attack_session_id": str(first["attack_session_id"]),
        "event_type": "connection_opened",
        "source_ip": "192.0.2.44",
        "received_from": "2026-10-14T12:00:00Z",
        "received_to": "2026-10-14T12:00:09Z",
    }
    try:
        result = subprocess.run(
            [
                chrome,
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--virtual-time-budget=2500",
                "--dump-dom",
                f"http://127.0.0.1:{server.server_port}/events.html?{urlencode(page_filters)}",
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

    assert any("cursor=page-2" in path for path in requested_pages)
    first_request = parse_qs(urlparse(requested_pages[0]).query)
    assert first_request == {key: [value] for key, value in page_filters.items()}
    assert result.stdout.count('class="security-event reveal"') == 3
    for number in (1, 2, 3):
        assert result.stdout.count(f"SSH-event-{number}") == 1
    assert result.stdout.count('class="event-time-label">Зафиксировано</span>') == 3
    assert result.stdout.count('class="event-time-label">Получено</span>') == 3


def test_security_events_export_button_sends_the_active_filters() -> None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if chrome is None:
        pytest.skip("Chrome or Chromium is required for the Security Events UI test")
    web_root = Path(__file__).parent.parent / "center" / "web"
    probe = b"""
<script>
  (async () => {
    for (let attempt = 0; attempt < 100 && typeof collectFilters !== 'function'; attempt += 1) {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    const form = document.getElementById('event-filters');
    form.elements.namedItem('event_type').value = 'authentication_attempt';
    form.elements.namedItem('source_ip').value = '192.0.2.44';
    form.elements.namedItem('received_from_date').value = '2026-10-14';
    form.elements.namedItem('received_from_time').value = '10:30:00';
    let captured = '';
    const native = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () {
      if (this.href.includes('export.csv')) { captured = this.href; return; }
      return native.call(this);
    };
    document.getElementById('export-csv').click();
    HTMLAnchorElement.prototype.click = native;
    const marker = document.createElement('div');
    marker.id = 'export-probe';
    marker.textContent = captured;
    document.body.append(marker);
  })();
</script>
"""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/api/v1/security-events":
                self._send("application/json", json.dumps({"items": [], "next_cursor": None}).encode())
                return
            file_path = web_root / (parsed.path.lstrip("/") or "events.html")
            if not file_path.is_file():
                self.send_error(404)
                return
            body = file_path.read_bytes()
            if file_path.name == "events.html":
                body = body.replace(b"</body>", probe + b"</body>")
            self._send(
                {".html": "text/html", ".css": "text/css", ".js": "text/javascript"}.get(
                    file_path.suffix, "application/octet-stream"
                ),
                body,
            )

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
                "--virtual-time-budget=3000",
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

    assert "Экспорт IoC (CSV)" in result.stdout
    probe_markup = result.stdout.split('id="export-probe"')[1]
    exported = probe_markup.split(">")[1].split("<")[0].replace("&amp;", "&")
    assert exported.startswith(f"http://127.0.0.1:{server.server_port}/api/v1/security-events/export.csv?")
    assert "event_type=authentication_attempt" in exported
    assert "source_ip=192.0.2.44" in exported
    assert "received_from=" in exported
