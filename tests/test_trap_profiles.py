import os
import json
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from center.api.config import Settings
from center.api.main import create_app
from center.api.models import AuditEntry, Trap


pytestmark = pytest.mark.asyncio


@pytest.fixture
async def profile_app():
    database_url = os.getenv("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("set TEST_DATABASE_URL to run Trap Profile API tests")

    environment = os.environ | {"DATABASE_URL": database_url}
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
    )
    application = create_app(
        Settings(
            database_url=database_url,
            jwt_secret="test-secret-that-is-long-enough",
            operator_username="operator",
            operator_password="correct horse battery staple",
            cors_origins=["https://test"],
        )
    )
    async with application.router.lifespan_context(application):
        yield application
    subprocess.run(
        [sys.executable, "-m", "alembic", "downgrade", "base"],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
    )


@pytest.fixture
async def profile_client(profile_app):
    transport = httpx.ASGITransport(app=profile_app)
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        login = await client.post(
            "/api/v1/auth/login",
            headers={"Origin": "https://test"},
            json={
                "username": "operator",
                "password": "correct horse battery staple",
            },
        )
        assert login.status_code == 204
        yield client


async def test_trap_profile_api_requires_an_operator(profile_app) -> None:
    transport = httpx.ASGITransport(app=profile_app)
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        response = await client.post(
            "/api/v1/trap-profiles",
            headers={"Origin": "https://test"},
            json={
                "name": "Anonymous",
                "interaction_level": "low",
                "services": [{"protocol": "http", "internal_port": 80}],
            },
        )
    assert response.status_code == 401


async def test_operator_creates_a_trap_profile(profile_client) -> None:
    response = await profile_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": "Quiet SSH",
            "interaction_level": "low",
            "services": [
                {
                    "protocol": "ssh",
                    "internal_port": 22,
                    "banner": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
                    "emulator_settings": {"max_attempts": 3},
                }
            ],
        },
    )

    assert response.status_code == 201
    assert response.headers["etag"] == '"1"'
    assert response.json() == {
        "id": response.json()["id"],
        "name": "Quiet SSH",
        "interaction_level": "low",
        "services": [
            {
                "protocol": "ssh",
                "internal_port": 22,
                "banner": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
                "emulator_settings": {"max_attempts": 3},
            }
        ],
        "version": 1,
        "is_archived": False,
        "created_at": response.json()["created_at"],
        "updated_at": response.json()["updated_at"],
    }


async def test_trap_profile_rejects_deployment_and_credential_fields(
    profile_client,
) -> None:
    response = await profile_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": "Unsafe SSH",
            "interaction_level": "low",
            "services": [
                {
                    "protocol": "ssh",
                    "internal_port": 22,
                    "host": "203.0.113.4",
                    "password": "do-not-store",
                }
            ],
        },
    )

    assert response.status_code == 422

    nested = await profile_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": "Nested secret",
            "interaction_level": "medium",
            "services": [
                {
                    "protocol": "ssh",
                    "internal_port": 22,
                    "emulator_settings": {"password": "do-not-store"},
                }
            ],
        },
    )
    assert nested.status_code == 422


async def test_operator_lists_and_reads_trap_profiles(profile_client) -> None:
    created = await create_profile(profile_client, "HTTP storefront")

    listing = await profile_client.get("/api/v1/trap-profiles")
    detail = await profile_client.get(
        f"/api/v1/trap-profiles/{created['id']}"
    )

    assert listing.status_code == 200
    assert [item["name"] for item in listing.json()] == ["HTTP storefront"]
    assert detail.status_code == 200
    assert detail.headers["etag"] == '"1"'
    assert detail.json() == created


async def test_update_advances_version_and_rejects_a_stale_edit(profile_client) -> None:
    created = await create_profile(profile_client, "Quiet SSH")
    path = f"/api/v1/trap-profiles/{created['id']}"
    update = {
        "name": "Conversational SSH",
        "interaction_level": "medium",
        "services": [
            {
                "protocol": "ssh",
                "internal_port": 22,
                "emulator_settings": {"shell": "fixed"},
            }
        ],
    }

    changed = await profile_client.put(
        path,
        headers={"Origin": "https://test", "If-Match": '"1"'},
        json=update,
    )
    stale = await profile_client.put(
        path,
        headers={"Origin": "https://test", "If-Match": '"1"'},
        json=update | {"name": "Lost concurrent edit"},
    )

    assert changed.status_code == 200
    assert changed.headers["etag"] == '"2"'
    assert changed.json()["version"] == 2
    assert changed.json()["name"] == "Conversational SSH"
    assert stale.status_code == 409
    assert stale.json() == {
        "detail": "Trap Profile changed; reload it before editing"
    }

    missing_precondition = await profile_client.put(
        path,
        headers={"Origin": "https://test"},
        json=update,
    )
    malformed_precondition = await profile_client.put(
        path,
        headers={"Origin": "https://test", "If-Match": "latest"},
        json=update,
    )
    assert missing_precondition.status_code == 428
    assert malformed_precondition.status_code == 400


async def test_unused_trap_profile_is_deleted(profile_client) -> None:
    created = await create_profile(profile_client, "Unused HTTP")
    path = f"/api/v1/trap-profiles/{created['id']}"

    deleted = await profile_client.delete(
        path,
        headers={"Origin": "https://test", "If-Match": '"1"'},
    )

    assert deleted.status_code == 204
    assert (await profile_client.get(path)).status_code == 404


async def test_assigned_trap_profile_is_archived_and_mutations_are_audited(
    profile_app, profile_client
) -> None:
    created = await create_profile(profile_client, "Assigned SSH")
    profile_id = created["id"]
    async with profile_app.state.database.session_factory() as session:
        session.add(
            Trap(
                name="edge-ssh",
                trap_profile_id=profile_id,
                status="provisioning",
                is_archived=False,
                agent_meta={},
            )
        )
        await session.commit()

    archived = await profile_client.delete(
        f"/api/v1/trap-profiles/{profile_id}",
        headers={"Origin": "https://test", "If-Match": '"1"'},
    )
    detail = await profile_client.get(f"/api/v1/trap-profiles/{profile_id}")

    assert archived.status_code == 204
    assert detail.status_code == 200
    assert detail.json()["is_archived"] is True
    assert detail.json()["version"] == 2
    assert detail.headers["etag"] == '"2"'

    async with profile_app.state.database.session_factory() as session:
        actions = list(
            await session.scalars(
                select(AuditEntry.action)
                .where(AuditEntry.entity == "trap_profile")
                .order_by(AuditEntry.id)
            )
        )
    assert actions == ["trap_profile.created", "trap_profile.archived"]

    repeat_archive = await profile_client.delete(
        f"/api/v1/trap-profiles/{profile_id}",
        headers={"Origin": "https://test", "If-Match": '"2"'},
    )
    update_archived = await profile_client.put(
        f"/api/v1/trap-profiles/{profile_id}",
        headers={"Origin": "https://test", "If-Match": '"2"'},
        json={
            "name": "Rewritten history",
            "interaction_level": "low",
            "services": [{"protocol": "http", "internal_port": 80}],
        },
    )
    assert repeat_archive.status_code == 409
    assert update_archived.status_code == 409


async def create_profile(client: httpx.AsyncClient, name: str) -> dict:
    response = await client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": name,
            "interaction_level": "low",
            "services": [{"protocol": "http", "internal_port": 8080}],
        },
    )
    assert response.status_code == 201
    return response.json()


async def test_trap_profile_ui_exposes_management_workflow() -> None:
    web_root = Path(__file__).parent.parent / "center" / "web"
    markup = (web_root / "profiles.html").read_text(encoding="utf-8")
    behavior = (web_root / "profiles.js").read_text(encoding="utf-8")

    assert 'id="profile-form"' in markup
    assert 'id="add-service"' in markup
    assert 'id="remove-profile"' in markup
    assert 'name="emulator_settings"' in markup
    assert "'If-Match'" in behavior
    assert "selected ? 'PUT' : 'POST'" in behavior
    assert "method: 'DELETE'" in behavior
    assert "status === 409" in behavior


async def test_trap_profile_ui_preserves_settings_and_shows_conflicts() -> None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if chrome is None:
        pytest.skip("Chrome or Chromium is required for the Trap Profile UI test")

    web_root = Path(__file__).parent.parent / "center" / "web"
    captured: list[dict[str, object]] = []
    profile: dict[str, object] = {
        "id": "11111111-1111-1111-1111-111111111111",
        "name": "Medium SSH",
        "interaction_level": "medium",
        "services": [
            {
                "protocol": "ssh",
                "internal_port": 22,
                "emulator_settings": {"shell": "fixed"},
            }
        ],
        "version": 3,
        "is_archived": False,
        "created_at": "2026-10-14T12:00:00Z",
        "updated_at": "2026-10-14T12:00:00Z",
    }
    profiles = [profile]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/api/v1/trap-profiles":
                self._send("application/json", json.dumps(profiles).encode())
                return
            path = self.path.split("?", 1)[0]
            filename = "profiles.html" if path == "/profiles.html" else path.lstrip("/")
            file_path = web_root / filename
            if not file_path.is_file():
                self.send_error(404)
                return
            body = file_path.read_bytes()
            if filename == "profiles.html":
                scenario = b"""
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

await import('/profiles.js');
await waitFor(() => document.querySelector('.profile-row'));
document.querySelector('.profile-row').click();
{
  const settings = document.querySelector('[name="emulator_settings"]');
  const loaded = JSON.parse(settings.value).shell === 'fixed';
  document.querySelector('[name="name"]').value = 'Updated SSH';
  document.querySelector('#profile-form').requestSubmit();
  await waitFor(() => document.querySelector('#version-label').textContent === 'Version 4');
  document.querySelector('#remove-profile').click();
  await waitFor(() => document.querySelector('#notice').textContent === 'Trap Profile archived.');

  document.querySelector('#new-profile').click();
  document.querySelector('[name="name"]').value = 'Unused HTTP';
  document.querySelector('#profile-form').requestSubmit();
  await waitFor(() => [...document.querySelectorAll('.profile-row strong')].some(node => node.textContent === 'Unused HTTP'));
  document.querySelector('#remove-profile').click();
  await waitFor(() => document.querySelector('#notice').textContent === 'Unused Trap Profile deleted.');

  document.querySelector('[name="name"]').value = 'Conflict base';
  document.querySelector('#profile-form').requestSubmit();
  await waitFor(() => [...document.querySelectorAll('.profile-row strong')].some(node => node.textContent === 'Conflict base'));
  document.querySelector('[name="name"]').value = 'Conflict edit';
  document.querySelector('#profile-form').requestSubmit();
  await waitFor(() => document.querySelector('#notice').textContent.includes('changed elsewhere'));
  document.body.dataset.testResult = loaded ? 'passed' : 'failed';
}
</script>
"""
                body = body.replace(b"</body>", scenario + b"</body>")
            content_type = {
                ".html": "text/html",
                ".css": "text/css",
                ".js": "text/javascript",
            }.get(file_path.suffix, "application/octet-stream")
            self._send(content_type, body)

        def do_PUT(self) -> None:
            payload = self._payload()
            captured.append(
                {"method": "PUT", "payload": payload, "if_match": self.headers.get("If-Match")}
            )
            if payload["name"] == "Conflict edit":
                self.send_response(409)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"detail":"stale"}')
                return
            current = self._current()
            current.update(payload)
            current["version"] = int(current["version"]) + 1
            self._send("application/json", json.dumps(current).encode())

        def do_POST(self) -> None:
            payload = self._payload()
            created = {
                **payload,
                "id": f"22222222-2222-2222-2222-{len(profiles):012d}",
                "version": 1,
                "is_archived": False,
                "created_at": "2026-10-14T12:00:00Z",
                "updated_at": "2026-10-14T12:00:00Z",
            }
            profiles.append(created)
            captured.append({"method": "POST", "payload": payload})
            self._send("application/json", json.dumps(created).encode(), status_code=201)

        def do_DELETE(self) -> None:
            current = self._current()
            captured.append(
                {"method": "DELETE", "if_match": self.headers.get("If-Match")}
            )
            if current["id"] == profile["id"]:
                current["is_archived"] = True
                current["version"] = int(current["version"]) + 1
            else:
                profiles.remove(current)
            self.send_response(204)
            self.end_headers()

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
            return json.loads(self.rfile.read(length))

        def _current(self) -> dict[str, object]:
            profile_id = self.path.rsplit("/", 1)[-1]
            return next(item for item in profiles if item["id"] == profile_id)

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
                "--virtual-time-budget=4000",
                "--dump-dom",
                f"http://127.0.0.1:{server.server_port}/profiles.html",
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

    assert 'data-test-result="passed"' in result.stdout, result.stdout
    assert [request["method"] for request in captured] == [
        "PUT",
        "DELETE",
        "POST",
        "DELETE",
        "POST",
        "PUT",
    ]
    assert captured[0]["if_match"] == '"3"'
    assert captured[0]["payload"]["services"][0]["emulator_settings"] == {
        "shell": "fixed"
    }
