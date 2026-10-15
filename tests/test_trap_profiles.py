import json
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from center.api.models import AuditEntry, Trap


pytestmark = pytest.mark.asyncio


@pytest.fixture
async def profile_app(postgres_application):
    """PostgreSQL-backed Control API shared with the authenticated client."""

    yield postgres_application


@pytest.fixture
async def profile_client(operator_client):
    """Authenticated API client sharing the PostgreSQL-backed application."""

    yield operator_client


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
        "decoy_credentials": [],
        "logging": {
            "capture_credentials": True,
            "capture_commands": True,
            "capture_http_bodies": True,
            "max_payload_bytes": 4096,
        },
        "masking": {},
        "version": 1,
        "is_archived": False,
        "created_at": response.json()["created_at"],
        "updated_at": response.json()["updated_at"],
    }


async def test_low_profile_configures_http_and_mysql_independently(profile_client) -> None:
    response = await profile_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": "Web and MySQL decoy",
            "interaction_level": "low",
            "services": [
                {"protocol": "http", "internal_port": 80},
                {"protocol": "mysql", "internal_port": 3306},
            ],
        },
    )

    assert response.status_code == 201
    assert response.json()["services"] == [
        {"protocol": "http", "internal_port": 80, "emulator_settings": {}},
        {"protocol": "mysql", "internal_port": 3306, "emulator_settings": {}},
    ]


async def test_medium_profile_configures_fixed_fake_ssh(profile_client) -> None:
    response = await profile_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": "Interactive fake SSH",
            "interaction_level": "medium",
            "services": [
                {
                    "protocol": "ssh",
                    "internal_port": 22,
                    "emulator_settings": {"shell": "fixed", "max_attempts": 5},
                }
            ],
        },
    )

    assert response.status_code == 201
    assert response.json()["interaction_level"] == "medium"
    assert response.json()["services"][0]["emulator_settings"] == {
        "shell": "fixed",
        "max_attempts": 5,
    }


async def test_medium_profile_configures_fake_http(profile_client) -> None:
    response = await profile_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": "Interactive fake admin",
            "interaction_level": "medium",
            "services": [{"protocol": "http", "internal_port": 80}],
        },
    )

    assert response.status_code == 201
    assert response.json()["services"] == [
        {"protocol": "http", "internal_port": 80, "emulator_settings": {}}
    ]


async def test_profile_carries_decoy_logging_and_masking_settings(profile_client) -> None:
    response = await profile_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": "Realistic SSH",
            "interaction_level": "medium",
            "services": [{"protocol": "ssh", "internal_port": 22}],
            "decoy_credentials": [
                {"username": "root", "password": "hunter2", "service": "ssh"},
                {"username": "admin", "password": "Summer2026!"},
            ],
            "logging": {
                "capture_credentials": True,
                "capture_commands": False,
                "capture_http_bodies": True,
                "max_payload_bytes": 2048,
            },
            "masking": {
                "beacon_interval_seconds": 300,
                "beacon_jitter_seconds": 60,
                "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
            },
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["decoy_credentials"] == [
        {"username": "root", "password": "hunter2", "service": "ssh"},
        {"username": "admin", "password": "Summer2026!"},
    ]
    assert body["logging"] == {
        "capture_credentials": True,
        "capture_commands": False,
        "capture_http_bodies": True,
        "max_payload_bytes": 2048,
    }
    assert body["masking"] == {
        "beacon_interval_seconds": 300,
        "beacon_jitter_seconds": 60,
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
    }


async def test_profile_rejects_invalid_decoy_logging_and_masking_values(
    profile_client,
) -> None:
    base = {
        "name": "Invalid settings",
        "interaction_level": "low",
        "services": [{"protocol": "http", "internal_port": 80}],
    }
    empty_decoy = await profile_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json=base | {"decoy_credentials": [{"username": "", "password": "x"}]},
    )
    bad_payload = await profile_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json=base | {"logging": {"max_payload_bytes": 10_000_000}},
    )
    unknown_masking = await profile_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json=base | {"masking": {"interval": 10}},
    )

    assert empty_decoy.status_code == 422
    assert bad_payload.status_code == 422
    assert unknown_masking.status_code == 422


async def test_update_persists_decoy_logging_and_masking_settings(profile_client) -> None:
    created = await create_profile(profile_client, "Editable settings")
    path = f"/api/v1/trap-profiles/{created['id']}"

    changed = await profile_client.put(
        path,
        headers={"Origin": "https://test", "If-Match": '"1"'},
        json={
            "name": "Editable settings",
            "interaction_level": "medium",
            "services": [{"protocol": "ssh", "internal_port": 22}],
            "decoy_credentials": [{"username": "svc", "password": "decoy"}],
            "logging": {"capture_commands": False},
            "masking": {"beacon_interval_seconds": 120},
        },
    )

    assert changed.status_code == 200
    assert changed.json()["version"] == 2
    assert changed.json()["decoy_credentials"] == [
        {"username": "svc", "password": "decoy"}
    ]
    assert changed.json()["logging"]["capture_commands"] is False
    assert changed.json()["logging"]["capture_credentials"] is True
    assert changed.json()["masking"] == {"beacon_interval_seconds": 120}

    detail = await profile_client.get(path)
    assert detail.json() == changed.json()


async def test_trap_profile_rejects_unmodeled_service_fields(
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


async def test_assigned_profile_requires_reassignment_before_permanent_deletion(
    profile_app, profile_client
) -> None:
    created = await create_profile(profile_client, "Assigned SSH")
    profile_id = created["id"]
    async with profile_app.state.database.session_factory() as session:
        trap = Trap(name="edge-ssh", trap_profile_id=profile_id,
                    status="provisioning", is_archived=False, agent_meta={})
        session.add(trap)
        await session.commit()
        trap_id = trap.id
    headers = {"Origin": "https://test", "If-Match": '"1"'}
    blocked = await profile_client.delete(f"/api/v1/trap-profiles/{profile_id}", headers=headers)
    assert blocked.status_code == 409
    assert (await profile_client.get(f"/api/v1/trap-profiles/{profile_id}")).json()["is_archived"] is False
    assert (await profile_client.delete(f"/api/v1/traps/{trap_id}", headers=headers)).status_code == 204
    assert (await profile_client.delete(f"/api/v1/trap-profiles/{profile_id}", headers=headers)).status_code == 204
    assert (await profile_client.get(f"/api/v1/trap-profiles/{profile_id}")).status_code == 404
    async with profile_app.state.database.session_factory() as session:
        assert not list(await session.scalars(select(AuditEntry).where(AuditEntry.entity_id == profile_id)))


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
    assert 'id="add-credential"' in markup
    assert 'name="credential_username"' in markup
    assert 'name="capture_credentials"' in markup
    assert 'name="beacon_interval_seconds"' in markup
    assert "'If-Match'" in behavior
    assert "selected ? 'PUT' : 'POST'" in behavior
    assert "method: 'DELETE'" in behavior
    assert "status === 409" in behavior
    assert 'decoy_credentials' in behavior
    assert 'beacon_interval_seconds' in behavior


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
        "decoy_credentials": [
            {"username": "root", "password": "hunter2", "service": "ssh"}
        ],
        "logging": {
            "capture_credentials": True,
            "capture_commands": True,
            "capture_http_bodies": True,
            "max_payload_bytes": 2048,
        },
        "masking": {"beacon_interval_seconds": 120},
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
                scenario = """
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
  const credentialLoaded =
    document.querySelector('[name="credential_username"]').value === 'root' &&
    document.querySelector('[name="credential_password"]').value === 'hunter2' &&
    document.querySelector('[name="credential_service"]').value === 'ssh' &&
    document.querySelector('[name="beacon_interval_seconds"]').value === '120' &&
    document.querySelector('[name="max_payload_bytes"]').value === '2048';
  document.querySelector('[name="capture_credentials"]').checked = false;
  document.querySelector('[name="name"]').value = 'Updated SSH';
  document.querySelector('#profile-form').requestSubmit();
  await waitFor(() => document.querySelector('#version-label').textContent === 'Версия 4');
  document.querySelector('#remove-profile').click();
  await waitFor(() => document.querySelector('#notice').textContent === 'Профиль ловушки удалён.');

  document.querySelector('#new-profile').click();
  document.querySelector('[name="name"]').value = 'Unused HTTP';
  document.querySelector('#profile-form').requestSubmit();
  await waitFor(() => [...document.querySelectorAll('.profile-row strong')].some(node => node.textContent === 'Unused HTTP'));
  document.querySelector('#remove-profile').click();
  await waitFor(() => document.querySelector('#notice').textContent === 'Профиль ловушки удалён.');

  document.querySelector('[name="name"]').value = 'Conflict base';
  document.querySelector('#profile-form').requestSubmit();
  await waitFor(() => [...document.querySelectorAll('.profile-row strong')].some(node => node.textContent === 'Conflict base'));
  document.querySelector('[name="name"]').value = 'Conflict edit';
  document.querySelector('#profile-form').requestSubmit();
  await waitFor(() => document.querySelector('#notice').textContent.includes('изменён в другом окне'));
  document.body.dataset.testResult = loaded && credentialLoaded ? 'passed' : 'failed';
}
</script>
""".encode("utf-8")
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
    assert captured[0]["payload"]["decoy_credentials"] == [
        {"username": "root", "password": "hunter2", "service": "ssh"}
    ]
    assert captured[0]["payload"]["logging"]["capture_credentials"] is False
    assert captured[0]["payload"]["logging"]["max_payload_bytes"] == 2048
    assert captured[0]["payload"]["masking"] == {"beacon_interval_seconds": 120}


@pytest.mark.parametrize("services,level", [
    ([{"protocol": "udp", "internal_port": 9999}], "medium"),
    ([{"protocol": "ssh", "internal_port": 22}, {"protocol": "http", "internal_port": 22}], "low"),
    ([{"protocol": "http", "internal_port": 80, "banner": "\r\n"}], "low"),
])
async def test_invalid_service_combinations_never_change_saved_profiles(
    profile_client, services, level,
):
    headers = {"Origin": "https://test", "If-Match": '"1"'}
    invalid = {"name": "Unsupported", "interaction_level": level, "services": services}
    created = await profile_client.post("/api/v1/trap-profiles", headers=headers, json=invalid)
    assert created.status_code == 422
    valid = await create_profile(profile_client, "Keep working profile")
    path = f"/api/v1/trap-profiles/{valid['id']}"
    updated = await profile_client.put(path, headers=headers, json=invalid)
    assert updated.status_code == 422
    current = await profile_client.get(path)
    assert current.json() == valid


async def test_legacy_unsupported_profile_remains_readable_and_repairable(profile_app, profile_client):
    from center.api.models import TrapProfile
    created = await create_profile(profile_client, "Legacy Medium")
    async with profile_app.state.database.session_factory() as session:
        profile = await session.get(TrapProfile, created["id"])
        profile.interaction_level = "medium"
        profile.services = [{"protocol": "mysql", "internal_port": 3306}]
        await session.commit()
    path = f"/api/v1/trap-profiles/{created['id']}"
    assert (await profile_client.get(path)).status_code == 200
    assert (await profile_client.get("/api/v1/trap-profiles")).status_code == 200
    repaired = await profile_client.put(path,
        headers={"Origin": "https://test", "If-Match": '"1"'},
        json={"name": "Repaired", "interaction_level": "medium",
              "services": [{"protocol": "ssh", "internal_port": 22}]})
    assert repaired.status_code == 200
    assert repaired.json()["version"] == 2
