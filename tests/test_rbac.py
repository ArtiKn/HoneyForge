"""Role-based access control for the Control Center (FR-C5).

The authenticated Operator surface is split into an ``admin`` role with full
access and a read-only ``viewer`` role. These tests exercise the enforcement on
every mutating endpoint, the audit trail left by a denied attempt, and the UI
that hides mutation controls from a viewer.
"""

import json
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select

from center.api.models import AuditEntry

pytestmark = pytest.mark.asyncio

TRAP_PROFILE_PAYLOAD = {
    "name": "RBAC profile",
    "interaction_level": "low",
    "services": [{"protocol": "http", "internal_port": 80}],
}


@pytest.fixture
async def rbac_app(postgres_application):
    """PostgreSQL-backed Control API shared with the role clients."""

    yield postgres_application


async def test_viewer_can_read_every_operator_surface(viewer_client) -> None:
    for path in (
        "/api/v1/auth/me",
        "/api/v1/dashboard",
        "/api/v1/traps",
        "/api/v1/trap-profiles",
        "/api/v1/security-events",
    ):
        response = await viewer_client.get(path)
        assert response.status_code == 200, path

    identity = await viewer_client.get("/api/v1/auth/me")
    assert identity.json() == {"username": "viewer", "role": "viewer"}


async def test_viewer_mutations_are_forbidden_and_audited(
    rbac_app, viewer_client
) -> None:
    profile_id = uuid4()
    trap_id = uuid4()
    attempts = [
        ("post", "/api/v1/trap-profiles", TRAP_PROFILE_PAYLOAD),
        (
            "put",
            f"/api/v1/trap-profiles/{profile_id}",
            TRAP_PROFILE_PAYLOAD,
        ),
        ("delete", f"/api/v1/trap-profiles/{profile_id}", None),
        ("post", "/api/v1/traps", {"name": "edge", "trap_profile_id": str(uuid4())}),
        ("patch", f"/api/v1/traps/{trap_id}", {"name": "edge-renamed"}),
        ("post", f"/api/v1/traps/{trap_id}/start", None),
        ("post", f"/api/v1/traps/{trap_id}/stop", None),
        ("post", f"/api/v1/traps/{trap_id}/archive", None),
        ("post", f"/api/v1/traps/{trap_id}/revoke", None),
        ("post", f"/api/v1/traps/{trap_id}/restore", None),
        ("post", f"/api/v1/traps/{trap_id}/enrollment-token", None),
        ("delete", f"/api/v1/traps/{trap_id}", None),
    ]

    for method, path, payload in attempts:
        headers = {"Origin": "https://test"}
        if method == "delete":
            headers["If-Match"] = '"1"'
        options = {"headers": headers}
        if payload is not None:
            options["json"] = payload
        response = await getattr(viewer_client, method)(path, **options)
        assert response.status_code == 403, (method, path)
        assert response.json() == {
            "detail": "Operator role cannot perform this action"
        }

    async with rbac_app.state.database.session_factory() as session:
        denied = list(
            await session.scalars(
                select(AuditEntry)
                .where(AuditEntry.action == "operator.access.denied")
                .order_by(AuditEntry.id)
            )
        )
    assert len(denied) == len(attempts)
    assert [
        (entry.details["method"], entry.details["path"]) for entry in denied
    ] == [(method.upper(), path) for method, path, _ in attempts]
    assert all(entry.entity == "operator" for entry in denied)


async def test_admin_keeps_full_access(rbac_app, operator_client) -> None:
    profile = await operator_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json=TRAP_PROFILE_PAYLOAD,
    )
    assert profile.status_code == 201
    trap = await operator_client.post(
        "/api/v1/traps",
        headers={"Origin": "https://test"},
        json={"name": "edge", "trap_profile_id": profile.json()["id"]},
    )
    assert trap.status_code == 201
    trap_id = trap.json()["id"]

    stopped = await operator_client.post(
        f"/api/v1/traps/{trap_id}/stop", headers={"Origin": "https://test"}
    )
    assert stopped.status_code == 200
    assert stopped.json()["enabled"] is False

    async with rbac_app.state.database.session_factory() as session:
        denied = list(
            await session.scalars(
                select(AuditEntry).where(AuditEntry.action == "operator.access.denied")
            )
        )
    assert denied == []


async def test_viewer_can_log_out(viewer_client) -> None:
    logout = await viewer_client.post(
        "/api/v1/auth/logout", headers={"Origin": "https://test"}
    )

    assert logout.status_code == 204
    assert (await viewer_client.get("/api/v1/dashboard")).status_code == 401


def test_ui_views_delegate_role_gating_to_the_shared_helper() -> None:
    web_root = Path(__file__).parent.parent / "center" / "web"
    helper = (web_root / "operator.js").read_text(encoding="utf-8")
    traps = (web_root / "traps.js").read_text(encoding="utf-8")
    profiles = (web_root / "profiles.js").read_text(encoding="utf-8")

    assert "/api/v1/auth/me" in helper
    assert "role === 'admin'" in helper
    assert "from './operator.js'" in traps
    assert "from './operator.js'" in profiles
    assert "canManage" in traps
    assert "canManage" in profiles
    assert "Только просмотр" in traps
    assert "Доступ только для просмотра" in profiles


def test_viewer_ui_hides_mutation_controls() -> None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if chrome is None:
        pytest.skip("Chrome or Chromium is required for the RBAC UI test")

    web_root = Path(__file__).parent.parent / "center" / "web"
    profile_id = "11111111-1111-1111-1111-111111111111"
    traps = [
        {
            "id": "22222222-2222-2222-2222-222222222222",
            "name": "edge-01",
            "trap_profile_id": profile_id,
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
        }
    ]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/api/v1/auth/me":
                self._send(
                    "application/json",
                    json.dumps({"username": "viewer", "role": "viewer"}).encode(),
                )
                return
            if path == "/api/v1/trap-profiles":
                self._send("application/json", b"[]")
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
                body = body.replace(b"</body>", _VIEWER_SCENARIO + b"</body>")
            content_type = {
                ".html": "text/html",
                ".css": "text/css",
                ".js": "text/javascript",
            }.get(file_path.suffix, "application/octet-stream")
            self._send(content_type, body)

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
            timeout=90,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert 'data-test-result="passed"' in result.stdout, result.stdout


_VIEWER_SCENARIO = """
<script type="module">
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
const row = document.querySelector('.trap-row');
const actions = row.querySelector('.trap-actions').textContent;
const hidden =
  document.querySelector('.trap-start') === null &&
  document.querySelector('.trap-stop') === null &&
  document.querySelector('.trap-revoke') === null &&
  document.querySelector('.trap-archive') === null &&
  actions.includes('Только просмотр') &&
  document.querySelector('#trap-form [type="submit"]').disabled === true;
document.body.dataset.testResult = hidden ? 'passed' : 'failed';
</script>
""".encode()
