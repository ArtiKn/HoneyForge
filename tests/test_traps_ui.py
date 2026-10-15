import json
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


PROFILE_ID = "11111111-1111-1111-1111-111111111111"
TRAP_A = "22222222-2222-2222-2222-222222222222"
TRAP_B = "33333333-3333-3333-3333-333333333333"


def test_traps_ui_exposes_the_management_workflow() -> None:
    web_root = Path(__file__).parent.parent / "center" / "web"
    markup = (web_root / "traps.html").read_text(encoding="utf-8")
    behavior = (web_root / "traps.js").read_text(encoding="utf-8")

    assert 'id="trap-form"' in markup
    assert 'id="trap-list"' in markup
    assert 'id="enrollment-token"' in markup
    assert "trap-start" in behavior
    assert "trap-stop" in behavior
    assert "trap-revoke" in behavior
    assert "trap-archive" in behavior
    assert "/start" in behavior
    assert "/stop" in behavior


def test_traps_ui_starts_stops_and_registers_traps_through_the_api() -> None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if chrome is None:
        pytest.skip("Chrome or Chromium is required for the Traps UI test")

    web_root = Path(__file__).parent.parent / "center" / "web"
    captured: list[dict[str, object]] = []
    profile: dict[str, object] = {
        "id": PROFILE_ID,
        "name": "Medium SSH",
        "interaction_level": "medium",
        "services": [{"protocol": "ssh", "internal_port": 22}],
        "version": 1,
        "is_archived": False,
        "created_at": "2026-10-14T12:00:00Z",
        "updated_at": "2026-10-14T12:00:00Z",
    }
    traps: list[dict[str, object]] = [
        {
            "id": TRAP_A,
            "name": "edge-01",
            "trap_profile_id": PROFILE_ID,
            "ip_address": "192.0.2.10",
            "hostname": "edge-01.lab",
            "region": "dmz",
            "agent_meta": {},
            "status": "online",
            "display_status": "online",
            "enabled": True,
            "is_archived": False,
            "agent_version": "1.0.0",
            "last_seen_at": "2026-10-14T12:05:00Z",
            "created_at": "2026-10-14T12:00:00Z",
        },
        {
            "id": TRAP_B,
            "name": "edge-02",
            "trap_profile_id": PROFILE_ID,
            "ip_address": None,
            "hostname": None,
            "region": "dmz",
            "agent_meta": {},
            "status": "offline",
            "display_status": "stopped",
            "enabled": False,
            "is_archived": False,
            "agent_version": None,
            "last_seen_at": None,
            "created_at": "2026-10-14T12:00:00Z",
        },
    ]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/api/v1/dashboard":
                self._send("application/json", json.dumps({"operator": "vera"}).encode())
                return
            if path == "/api/v1/trap-profiles":
                self._send("application/json", json.dumps([profile]).encode())
                return
            if path == "/api/v1/traps":
                self._send("application/json", json.dumps(traps).encode())
                return
            filename = "traps.html" if path == "/traps.html" else path.lstrip("/")
            file_path = web_root / filename
            if not file_path.is_file():
                self.send_error(404)
                return
            body = file_path.read_bytes()
            if filename == "traps.html":
                body = body.replace(b"</body>", _SCENARIO + b"</body>")
            content_type = {
                ".html": "text/html",
                ".css": "text/css",
                ".js": "text/javascript",
            }.get(file_path.suffix, "application/octet-stream")
            self._send(content_type, body)

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            payload = self._payload()
            captured.append({"path": path, "payload": payload})
            if path == "/api/v1/traps":
                created = {
                    "id": f"44444444-4444-4444-4444-{len(traps):012d}",
                    "name": payload["name"],
                    "trap_profile_id": payload["trap_profile_id"],
                    "ip_address": None,
                    "hostname": payload.get("hostname"),
                    "region": payload.get("region"),
                    "agent_meta": {},
                    "status": "provisioning",
                    "display_status": "provisioning",
                    "enabled": True,
                    "is_archived": False,
                    "agent_version": None,
                    "last_seen_at": None,
                    "created_at": "2026-10-14T12:00:00Z",
                    "enrollment_token": "new-enrollment-token",
                }
                traps.append(created)
                self._send(
                    "application/json", json.dumps(created).encode(), status_code=201
                )
                return
            if path.endswith("/stop"):
                current = self._current(path)
                current["enabled"] = False
                current["display_status"] = "stopped"
                self._send("application/json", json.dumps(current).encode())
                return
            if path.endswith("/start"):
                current = self._current(path)
                current["enabled"] = True
                current["display_status"] = "online"
                self._send("application/json", json.dumps(current).encode())
                return
            self.send_error(404)

        def log_message(self, format: str, *args: object) -> None:
            pass

        def _send(
            self, content_type: str, body: bytes, status_code: int = 200
        ) -> None:
            self.send_response(status_code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _payload(self) -> dict[str, object]:
            length = int(self.headers.get("Content-Length", "0"))
            if not length:
                return {}
            return json.loads(self.rfile.read(length))

        def _current(self, path: str) -> dict[str, object]:
            trap_id = path.split("/api/v1/traps/", 1)[1].split("/", 1)[0]
            return next(item for item in traps if item["id"] == trap_id)

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
                "--virtual-time-budget=5000",
                "--dump-dom",
                f"http://127.0.0.1:{server.server_port}/traps.html",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=25,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert 'data-test-result="passed"' in result.stdout, result.stdout
    assert [request["path"] for request in captured] == [
        f"/api/v1/traps/{TRAP_A}/stop",
        f"/api/v1/traps/{TRAP_A}/start",
        "/api/v1/traps",
    ]


_SCENARIO = """
<script type="module">
window.confirm = () => true;
const waitFor = predicate => new Promise(resolve => {
  const check = () => {
    if (!predicate()) return false;
    observer.disconnect();
    resolve();
    return true;
  };
  const observer = new MutationObserver(check);
  observer.observe(document.body, { childList: true, subtree: true, attributes: true });
  check();
});

await import('/traps.js');
await waitFor(() => document.querySelector('.trap-row'));
const rowFor = name => [...document.querySelectorAll('.trap-row')]
  .find(row => row.querySelector('td').textContent === name);
const statusOf = name => rowFor(name).querySelector('.trap-status').dataset.status;

rowFor('edge-01').querySelector('.trap-stop').click();
await waitFor(() => statusOf('edge-01') === 'stopped');
rowFor('edge-01').querySelector('.trap-start').click();
await waitFor(() => statusOf('edge-01') === 'online');

document.querySelector('[name="name"]').value = 'edge-03';
document.querySelector('#trap-form').requestSubmit();
await waitFor(() => document.querySelector('#enrollment-token').textContent.includes('Токен регистрации'));
await waitFor(() => [...document.querySelectorAll('.trap-row td:first-child')]
  .some(cell => cell.textContent === 'edge-03'));
document.body.dataset.testResult = 'passed';
</script>
""".encode("utf-8")
