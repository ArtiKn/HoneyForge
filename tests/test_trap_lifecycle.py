import asyncio
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from uuid import uuid4

import httpx
import pytest
import uvicorn
import asyncssh
from sqlalchemy import func, select

from agent.low.honeyforge_low import (
    AgentClient,
    EventQueue,
    LowHttpAgent,
    LowMySqlAgent,
    LowSshAgent,
)
from agent.medium.main import MediumSshService
from agent.medium.http_service import MediumHttpService
from center.api.config import Settings
from center.api.main import create_app
from center.api.models import AttackSession, AuditEntry, SecurityEvent, Trap
from tests.support import create_test_certificate


pytestmark = pytest.mark.asyncio


@pytest.fixture
async def lifecycle_app():
    database_url = os.getenv("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("set TEST_DATABASE_URL to run Trap lifecycle tests")
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
            health_timeout_seconds=90,
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
async def lifecycle_client(lifecycle_app):
    transport = httpx.ASGITransport(app=lifecycle_app)
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


async def create_profile(
    client: httpx.AsyncClient, name: str = "Lifecycle profile"
) -> str:
    response = await client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": name,
            "interaction_level": "medium",
            "services": [{"protocol": "ssh", "internal_port": 22}],
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


async def precreate_trap(
    client: httpx.AsyncClient, *, name: str = "edge-01", profile_name: str = "Lifecycle profile"
) -> dict:
    profile_id = await create_profile(client, profile_name)
    response = await client.post(
        "/api/v1/traps",
        headers={"Origin": "https://test"},
        json={"name": name, "trap_profile_id": profile_id, "region": "dmz"},
    )
    assert response.status_code == 201
    return response.json()


async def enroll_trap(client: httpx.AsyncClient, created: dict) -> str:
    response = await client.post(
        "/assets/v2/enroll", json={"enrollment_token": created["enrollment_token"]}
    )
    assert response.status_code == 200
    return response.json()["trap_secret"]


def authorization(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


def health_report(*, errors: list[str] | None = None) -> dict:
    return {
        "agent_version": "1.4.0",
        "active_profile_version": 3,
        "buffer_depth": 7,
        "configuration_errors": errors or [],
    }


async def test_operator_precreates_and_agent_enrolls_once(
    lifecycle_app, lifecycle_client
) -> None:
    created = await precreate_trap(lifecycle_client)
    assert created["status"] == "provisioning"
    assert created["enrollment_token"].startswith(f"{created['id']}.")

    enrolled = await lifecycle_client.post(
        "/assets/v2/enroll", json={"enrollment_token": created["enrollment_token"]}
    )
    replay = await lifecycle_client.post(
        "/assets/v2/enroll", json={"enrollment_token": created["enrollment_token"]}
    )

    assert enrolled.status_code == 200
    assert enrolled.json()["trap_id"] == created["id"]
    assert enrolled.json()["trap_secret"].startswith(f"{created['id']}.")
    assert replay.status_code == 401

    async with lifecycle_app.state.database.session_factory() as session:
        trap = await session.get(Trap, created["id"])
        actions = list(
            await session.scalars(
                select(AuditEntry.action)
                .where(AuditEntry.entity_id == trap.id)
                .order_by(AuditEntry.id)
            )
        )
    assert trap.status == "online"
    assert trap.enrollment_token_hash != created["enrollment_token"]
    assert trap.current_secret_hash != enrolled.json()["trap_secret"]
    assert trap.enrollment_token_used_at is not None
    assert actions == ["trap.created", "trap.enrolled"]


async def test_expired_enrollment_token_is_rejected(
    lifecycle_app, lifecycle_client
) -> None:
    created = await precreate_trap(lifecycle_client)
    async with lifecycle_app.state.database.session_factory() as session:
        trap = await session.get(Trap, created["id"])
        trap.enrollment_token_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    response = await lifecycle_client.post(
        "/assets/v2/enroll", json={"enrollment_token": created["enrollment_token"]}
    )

    assert response.status_code == 401


async def test_health_reports_change_operational_state_without_security_events(
    lifecycle_app, lifecycle_client
) -> None:
    created = await precreate_trap(lifecycle_client)
    secret = await enroll_trap(lifecycle_client, created)

    degraded = await lifecycle_client.post(
        "/assets/v2/health",
        headers=authorization(secret),
        json=health_report(errors=["profile rejected"]),
    )
    assert degraded.status_code == 204
    online = await lifecycle_client.post(
        "/assets/v2/health",
        headers=authorization(secret),
        json=health_report(),
    )
    assert online.status_code == 204

    async with lifecycle_app.state.database.session_factory() as session:
        trap = await session.get(Trap, created["id"])
        event_count = await session.scalar(
            select(func.count()).select_from(SecurityEvent)
        )
    assert trap.status == "online"
    assert trap.agent_version == "1.4.0"
    assert trap.agent_meta == {
        "active_profile_version": 3,
        "buffer_depth": 7,
        "configuration_errors": [],
    }
    assert event_count == 0


async def test_control_center_retains_the_latest_buffer_loss_report(
    lifecycle_app, lifecycle_client
) -> None:
    created = await precreate_trap(lifecycle_client)
    secret = await enroll_trap(lifecycle_client, created)
    loss = {
        "dropped_events": 12,
        "dropped_bytes": 4096,
        "first_dropped_at": "2026-10-14T12:00:00Z",
        "last_dropped_at": "2026-10-14T12:01:00Z",
    }

    reported = await lifecycle_client.post(
        "/assets/v2/health",
        headers=authorization(secret),
        json=health_report() | {"buffer_loss": loss},
    )
    next_health = await lifecycle_client.post(
        "/assets/v2/health",
        headers=authorization(secret),
        json=health_report(),
    )

    assert reported.status_code == 204
    assert next_health.status_code == 204
    async with lifecycle_app.state.database.session_factory() as session:
        trap = await session.get(Trap, created["id"])
    assert trap.agent_meta["buffer_loss"] == loss


async def test_rotation_has_five_minute_overlap_then_expires_old_secret(
    lifecycle_app, lifecycle_client
) -> None:
    created = await precreate_trap(lifecycle_client)
    old_secret = await enroll_trap(lifecycle_client, created)

    rotated = await lifecycle_client.post(
        "/assets/v2/rotate", headers=authorization(old_secret)
    )
    assert rotated.status_code == 200
    new_secret = rotated.json()["trap_secret"]
    assert new_secret != old_secret
    assert (
        await lifecycle_client.post(
            "/assets/v2/rotate", headers=authorization(new_secret)
        )
    ).status_code == 409
    assert (
        await lifecycle_client.post(
            "/assets/v2/health",
            headers=authorization(old_secret),
            json=health_report(),
        )
    ).status_code == 204

    async with lifecycle_app.state.database.session_factory() as session:
        trap = await session.get(Trap, created["id"])
        assert timedelta(minutes=4, seconds=55) < (
            trap.previous_secret_valid_until - datetime.now(UTC)
        ) <= timedelta(minutes=5)
        trap.previous_secret_valid_until = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    assert (
        await lifecycle_client.post(
            "/assets/v2/health",
            headers=authorization(old_secret),
            json=health_report(),
        )
    ).status_code == 401
    assert (
        await lifecycle_client.post(
            "/assets/v2/health",
            headers=authorization(new_secret),
            json=health_report(),
        )
    ).status_code == 204


async def test_revocation_immediately_rejects_current_and_overlapping_secrets(
    lifecycle_app, lifecycle_client
) -> None:
    created = await precreate_trap(lifecycle_client)
    old_secret = await enroll_trap(lifecycle_client, created)
    rotated = await lifecycle_client.post(
        "/assets/v2/rotate", headers=authorization(old_secret)
    )
    new_secret = rotated.json()["trap_secret"]

    revoked = await lifecycle_client.post(
        f"/api/v1/traps/{created['id']}/revoke", headers={"Origin": "https://test"}
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    for secret in (old_secret, new_secret):
        assert (
            await lifecycle_client.post(
                "/assets/v2/health",
                headers=authorization(secret),
                json=health_report(),
            )
        ).status_code == 401

    async with lifecycle_app.state.database.session_factory() as session:
        trap = await session.get(Trap, created["id"])
        audit_entries = list(
            await session.scalars(
                select(AuditEntry)
                .where(AuditEntry.entity_id == trap.id)
                .order_by(AuditEntry.id)
            )
        )
    assert trap.current_secret_hash is None
    assert trap.previous_secret_hash is None
    assert [entry.action for entry in audit_entries] == [
        "trap.created",
        "trap.enrolled",
        "trap.secret.rotated",
        "trap.revoked",
    ]
    assert all(entry.details == {} for entry in audit_entries)


async def test_missing_health_transitions_trap_offline_after_configured_timeout(
    lifecycle_app, lifecycle_client
) -> None:
    created = await precreate_trap(lifecycle_client)
    await enroll_trap(lifecycle_client, created)
    async with lifecycle_app.state.database.session_factory() as session:
        trap = await session.get(Trap, created["id"])
        trap.last_seen_at = datetime.now(UTC) - timedelta(seconds=91)
        await session.commit()

    listed = await lifecycle_client.get("/api/v1/traps")

    assert listed.status_code == 200
    assert listed.json()[0]["status"] == "offline"


async def test_dashboard_exposes_every_trap_status() -> None:
    dashboard = Path("center/web/index.html").read_text()

    assert "fetch('/api/v1/traps'" in dashboard
    for status_name in ("provisioning", "online", "degraded", "offline", "revoked"):
        assert f'data-status="{status_name}"' in dashboard


async def test_masked_agent_channel_exposes_lifecycle_endpoints() -> None:
    nginx = Path("deploy/nginx/conf.d/honeypot_masking.conf").read_text()

    assert "location /assets/v2/" in nginx
    assert "proxy_pass http://api:8000/assets/v2/;" in nginx


async def test_authenticated_agent_persists_and_deduplicates_ssh_interaction(
    lifecycle_app, lifecycle_client
) -> None:
    created = await precreate_trap(lifecycle_client)
    secret = await enroll_trap(lifecycle_client, created)
    attack_session_id = str(uuid4())
    opened_id = str(uuid4())
    closed_id = str(uuid4())
    events = [
        {
            "id": opened_id,
            "schema_version": 1,
            "trap_id": created["id"],
            "attack_session_id": attack_session_id,
            "event_type": "connection_opened",
            "observed_at": "2026-10-14T12:00:00Z",
            "source_ip": "192.0.2.44",
            "source_port": 54321,
            "target_service": "ssh",
            "target_port": 2222,
            "payload": {"banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"},
        },
        {
            "id": closed_id,
            "schema_version": 1,
            "trap_id": created["id"],
            "attack_session_id": attack_session_id,
            "event_type": "connection_closed",
            "observed_at": "2026-10-14T12:00:01Z",
            "source_ip": "192.0.2.44",
            "source_port": 54321,
            "target_service": "ssh",
            "target_port": 2222,
            "payload": {"bytes_sent": 42},
        },
    ]

    first = await lifecycle_client.post(
        "/assets/v2/init",
        headers={**authorization(secret), "Content-Type": "application/javascript"},
        json={"events": events},
    )
    duplicate = await lifecycle_client.post(
        "/assets/v2/init",
        headers={**authorization(secret), "Content-Type": "application/javascript"},
        json={"events": events},
    )
    first_page = await lifecycle_client.get(
        f"/api/v1/security-events?trap_id={created['id']}&limit=1"
    )
    second_page = await lifecycle_client.get(
        "/api/v1/security-events",
        params={
            "trap_id": created["id"],
            "limit": 1,
            "cursor": first_page.json()["next_cursor"],
        },
    )
    listed_events = first_page.json()["items"] + second_page.json()["items"]

    assert first.status_code == 200
    assert first.json() == {"accepted": [opened_id, closed_id]}
    assert duplicate.status_code == 200
    assert duplicate.json() == {"accepted": [opened_id, closed_id]}
    assert first_page.status_code == 200
    assert second_page.status_code == 200
    assert second_page.json()["next_cursor"] is None
    assert {event["event_type"] for event in listed_events} == {
        "connection_opened",
        "connection_closed",
    }
    assert {event["attack_session_id"] for event in listed_events} == {
        attack_session_id
    }

    async with lifecycle_app.state.database.session_factory() as session:
        event_count = await session.scalar(
            select(func.count()).select_from(SecurityEvent)
        )
        session_count = await session.scalar(
            select(func.count()).select_from(AttackSession)
        )
    assert event_count == 2
    assert session_count == 1


async def test_enrolled_agent_reads_its_assigned_trap_profile(
    lifecycle_client,
) -> None:
    created = await precreate_trap(lifecycle_client)
    secret = await enroll_trap(lifecycle_client, created)

    response = await lifecycle_client.get(
        "/assets/v2/config", headers=authorization(secret)
    )

    assert response.status_code == 200
    assert response.json() == {
        "trap_id": created["id"],
        "profile_version": 1,
        "interaction_level": "medium",
        "services": [
            {
                "protocol": "ssh",
                "internal_port": 22,
                "banner": None,
                "emulator_settings": {
                    "shell": None,
                    "max_attempts": None,
                    "response_delay_ms": None,
                },
            }
        ],
    }


async def test_agent_cannot_attach_events_to_another_traps_attack_session(
    lifecycle_client,
) -> None:
    first = await precreate_trap(lifecycle_client)
    first_secret = await enroll_trap(lifecycle_client, first)
    second = await precreate_trap(
        lifecycle_client, name="edge-02", profile_name="Second lifecycle profile"
    )
    second_secret = await enroll_trap(lifecycle_client, second)
    attack_session_id = str(uuid4())

    def event(trap_id: str, event_id: str) -> dict:
        return {
            "id": event_id,
            "schema_version": 1,
            "trap_id": trap_id,
            "attack_session_id": attack_session_id,
            "event_type": "connection_opened",
            "observed_at": "2026-10-14T12:00:00Z",
            "source_ip": "192.0.2.44",
            "source_port": 54321,
            "target_service": "ssh",
            "target_port": 22,
            "payload": {"banner": "SSH-2.0-test"},
        }

    accepted = await lifecycle_client.post(
        "/assets/v2/init",
        headers=authorization(first_secret),
        json={"events": [event(first["id"], str(uuid4()))]},
    )
    rejected = await lifecycle_client.post(
        "/assets/v2/init",
        headers=authorization(second_secret),
        json={"events": [event(second["id"], str(uuid4()))]},
    )

    assert accepted.status_code == 200
    assert rejected.status_code == 422


async def test_duplicate_event_uuid_cannot_mutate_or_create_an_attack_session(
    lifecycle_app, lifecycle_client
) -> None:
    created = await precreate_trap(lifecycle_client)
    secret = await enroll_trap(lifecycle_client, created)
    event_id = str(uuid4())
    original_session_id = str(uuid4())
    conflicting_session_id = str(uuid4())

    def event(session_id: str, observed_at: str) -> dict:
        return {
            "id": event_id,
            "schema_version": 1,
            "trap_id": created["id"],
            "attack_session_id": session_id,
            "event_type": "connection_closed",
            "observed_at": observed_at,
            "source_ip": "192.0.2.44",
            "source_port": 54321,
            "target_service": "ssh",
            "target_port": 22,
            "payload": {"bytes_sent": 4},
        }

    first = await lifecycle_client.post(
        "/assets/v2/init",
        headers=authorization(secret),
        json={"events": [event(original_session_id, "2026-10-14T12:00:00Z")]},
    )
    collision = await lifecycle_client.post(
        "/assets/v2/init",
        headers=authorization(secret),
        json={"events": [event(conflicting_session_id, "2026-10-14T13:00:00Z")]},
    )

    assert first.status_code == 200
    assert collision.status_code == 422
    async with lifecycle_app.state.database.session_factory() as session:
        sessions = list(await session.scalars(select(AttackSession)))
    assert len(sessions) == 1
    assert str(sessions[0].id) == original_session_id
    assert sessions[0].ended_at.isoformat() == "2026-10-14T12:00:00+00:00"


async def test_reversed_concurrent_batches_are_ingested_without_deadlock(
    lifecycle_app, lifecycle_client
) -> None:
    created = await precreate_trap(lifecycle_client)
    secret = await enroll_trap(lifecycle_client, created)

    def event(event_id: str, session_id: str, source_port: int) -> dict:
        return {
            "id": event_id,
            "schema_version": 1,
            "trap_id": created["id"],
            "attack_session_id": session_id,
            "event_type": "connection_opened",
            "observed_at": "2026-10-14T12:00:00Z",
            "source_ip": "192.0.2.44",
            "source_port": source_port,
            "target_service": "ssh",
            "target_port": 22,
            "payload": {"banner": "SSH-2.0-test"},
        }

    events = [
        event(str(uuid4()), str(uuid4()), 54321),
        event(str(uuid4()), str(uuid4()), 54322),
    ]
    responses = await asyncio.wait_for(
        asyncio.gather(
            lifecycle_client.post(
                "/assets/v2/init",
                headers=authorization(secret),
                json={"events": events},
            ),
            lifecycle_client.post(
                "/assets/v2/init",
                headers=authorization(secret),
                json={"events": list(reversed(events))},
            ),
        ),
        timeout=5,
    )

    assert [response.status_code for response in responses] == [200, 200]
    async with lifecycle_app.state.database.session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(SecurityEvent)) == 2
        assert await session.scalar(select(func.count()).select_from(AttackSession)) == 2


async def test_black_box_low_ssh_interaction_reaches_operator_api(
    lifecycle_app, lifecycle_client, tmp_path: Path
) -> None:
    ssh_port = _free_port()
    profile = await lifecycle_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": "Black-box Low SSH",
            "interaction_level": "low",
            "services": [
                {
                    "protocol": "ssh",
                    "internal_port": ssh_port,
                    "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
                }
            ],
        },
    )
    created_response = await lifecycle_client.post(
        "/api/v1/traps",
        headers={"Origin": "https://test"},
        json={"name": "black-box-ssh", "trap_profile_id": profile.json()["id"]},
    )
    created = created_response.json()
    secret = await enroll_trap(lifecycle_client, created)

    older_events = [
        {
            "id": str(uuid4()),
            "schema_version": 1,
            "trap_id": created["id"],
            "attack_session_id": str(uuid4()),
            "event_type": "connection_opened",
            "observed_at": "2026-10-14T10:00:00Z",
            "source_ip": "192.0.2.10",
            "source_port": 40000 + index,
            "target_service": "ssh",
            "target_port": ssh_port,
            "payload": {"banner": "SSH-2.0-older"},
        }
        for index in range(100)
    ]
    seeded = await lifecycle_client.post(
        "/assets/v2/init",
        headers=authorization(secret),
        json={"events": older_events},
    )
    assert seeded.status_code == 200

    certificate, private_key = create_test_certificate(tmp_path, name="center")
    api_port = _free_port()
    configuration_response = await lifecycle_client.get(
        "/assets/v2/config", headers=authorization(secret)
    )
    configuration = configuration_response.json()
    service = configuration["services"][0]
    queue = EventQueue(tmp_path / "black-box.sqlite3")
    client = AgentClient(
        f"https://127.0.0.1:{api_port}", secret, ca_file=certificate
    )
    agent = LowSshAgent(
        trap_id=configuration["trap_id"],
        host="127.0.0.1",
        port=service["internal_port"],
        banner=service["banner"],
        queue=queue,
        idle_timeout_seconds=1,
    )
    await agent.start()
    server = uvicorn.Server(
        uvicorn.Config(
            lifecycle_app,
            host="127.0.0.1",
            port=api_port,
            ssl_certfile=str(certificate),
            ssl_keyfile=str(private_key),
            lifespan="off",
            log_level="error",
        )
    )
    server_task: asyncio.Task | None = None
    try:
        ssh = await asyncio.create_subprocess_exec(
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=2",
            "-p",
            str(ssh_port),
            "nobody@127.0.0.1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(ssh.communicate(), timeout=5)
        assert ssh.returncode != 0
        for _ in range(100):
            if queue.pending_count() == 2:
                break
            await asyncio.sleep(0.01)

        with pytest.raises(URLError):
            await client.deliver_pending(queue)
        assert queue.pending_count() == 2

        server_task = asyncio.create_task(server.serve())
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("test API did not restart")

        replayed_events = queue.pending(limit=10)
        trusted_tls = ssl.create_default_context(cafile=certificate)
        async with httpx.AsyncClient(
            base_url=f"https://127.0.0.1:{api_port}", verify=trusted_tls
        ) as network_client:
            stored_without_local_ack = await network_client.post(
                "/assets/v2/init",
                headers={
                    **authorization(secret),
                    "Content-Type": "application/javascript",
                },
                json={"events": replayed_events},
            )
        assert stored_without_local_ack.status_code == 200
        assert queue.pending_count() == 2
        assert await client.deliver_pending(queue) == 2
        assert queue.pending_count() == 0
    finally:
        await agent.stop()
        queue.close()
        if server_task is not None:
            server.should_exit = True
            await server_task

    response = await lifecycle_client.get(
        f"/api/v1/security-events?trap_id={created['id']}"
    )
    assert response.status_code == 200
    visible_events = [
        event
        for event in response.json()["items"]
        if event["payload"].get("banner") != "SSH-2.0-older"
    ]
    assert {event["event_type"] for event in visible_events} == {
        "connection_opened",
        "connection_closed",
    }
    assert len({event["attack_session_id"] for event in visible_events}) == 1
    async with lifecycle_app.state.database.session_factory() as session:
        event_count = await session.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.trap_id == created["id"])
        )
    assert event_count == 102
    _assert_events_visible_in_browser(response.json()["items"])


async def test_black_box_low_http_and_mysql_reach_operator_api(
    lifecycle_app, lifecycle_client, tmp_path: Path
) -> None:
    http_port = _free_port()
    mysql_port = _free_port()
    profile = await lifecycle_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": "Black-box Low HTTP and MySQL",
            "interaction_level": "low",
            "services": [
                {"protocol": "http", "internal_port": http_port},
                {"protocol": "mysql", "internal_port": mysql_port},
            ],
        },
    )
    assert profile.status_code == 201
    created_response = await lifecycle_client.post(
        "/api/v1/traps",
        headers={"Origin": "https://test"},
        json={"name": "black-box-http-mysql", "trap_profile_id": profile.json()["id"]},
    )
    assert created_response.status_code == 201
    created = created_response.json()
    secret = await enroll_trap(lifecycle_client, created)

    certificate, private_key = create_test_certificate(tmp_path, name="center-http-mysql")
    api_port = _free_port()
    configuration = (
        await lifecycle_client.get("/assets/v2/config", headers=authorization(secret))
    ).json()
    services = {service["protocol"]: service for service in configuration["services"]}
    queue = EventQueue(tmp_path / "black-box-http-mysql.sqlite3")
    http_agent = LowHttpAgent(
        trap_id=configuration["trap_id"],
        host="127.0.0.1",
        port=services["http"]["internal_port"],
        banner=services["http"]["banner"],
        queue=queue,
        idle_timeout_seconds=1,
    )
    mysql_agent = LowMySqlAgent(
        trap_id=configuration["trap_id"],
        host="127.0.0.1",
        port=services["mysql"]["internal_port"],
        banner=services["mysql"]["banner"],
        queue=queue,
        idle_timeout_seconds=1,
    )
    await http_agent.start()
    await mysql_agent.start()
    server = uvicorn.Server(
        uvicorn.Config(
            lifecycle_app,
            host="127.0.0.1",
            port=api_port,
            ssl_certfile=str(certificate),
            ssl_keyfile=str(private_key),
            lifespan="off",
            log_level="error",
        )
    )
    server_task = asyncio.create_task(server.serve())
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("test API did not start")

        http_reader, http_writer = await asyncio.open_connection(
            "127.0.0.1", http_agent.port
        )
        http_writer.write(b"GET /admin HTTP/1.1\r\n")
        await http_writer.drain()
        await asyncio.sleep(0.02)
        http_writer.write(b"Host: trap\r\n\r\n")
        await http_writer.drain()
        assert (await http_reader.read()).startswith(b"HTTP/1.1 200 OK")
        http_writer.close()
        await http_writer.wait_closed()

        mysql_reader, mysql_writer = await asyncio.open_connection(
            "127.0.0.1", mysql_agent.port
        )
        header = await mysql_reader.readexactly(4)
        await mysql_reader.readexactly(int.from_bytes(header[:3], "little"))
        mysql_writer.close()
        await mysql_writer.wait_closed()

        for _ in range(100):
            if queue.pending_count() == 5:
                break
            await asyncio.sleep(0.01)
        assert queue.pending_count() == 5
        client = AgentClient(
            f"https://127.0.0.1:{api_port}", secret, ca_file=certificate
        )
        assert await client.deliver_pending(queue) == 5
        assert queue.pending_count() == 0
    finally:
        await http_agent.stop()
        await mysql_agent.stop()
        queue.close()
        server.should_exit = True
        await server_task

    response = await lifecycle_client.get(
        f"/api/v1/security-events?trap_id={created['id']}"
    )
    assert response.status_code == 200
    events = response.json()["items"]
    assert {event["target_service"] for event in events} == {"http", "mysql"}
    assert {event["event_type"] for event in events} == {
        "connection_opened",
        "http_request",
        "connection_closed",
    }
    assert len({event["attack_session_id"] for event in events}) == 2
    async with lifecycle_app.state.database.session_factory() as session:
        http_session_id = next(
            event["attack_session_id"]
            for event in events
            if event["target_service"] == "http"
        )
        http_session = await session.get(AttackSession, http_session_id)
        assert http_session is not None
        assert http_session.ended_at is None
    _assert_events_visible_in_browser(events)


async def test_black_box_medium_fake_ssh_reaches_operator_api(
    lifecycle_app, lifecycle_client, tmp_path: Path
) -> None:
    ssh_port = _free_port()
    profile = await lifecycle_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": "Black-box Medium SSH",
            "interaction_level": "medium",
            "services": [
                {
                    "protocol": "ssh",
                    "internal_port": ssh_port,
                    "emulator_settings": {"shell": "fixed"},
                }
            ],
        },
    )
    assert profile.status_code == 201
    created_response = await lifecycle_client.post(
        "/api/v1/traps",
        headers={"Origin": "https://test"},
        json={"name": "black-box-medium-ssh", "trap_profile_id": profile.json()["id"]},
    )
    created = created_response.json()
    secret = await enroll_trap(lifecycle_client, created)
    certificate, private_key = create_test_certificate(tmp_path, name="center-medium")
    api_port = _free_port()
    configuration = (
        await lifecycle_client.get("/assets/v2/config", headers=authorization(secret))
    ).json()
    queue = EventQueue(tmp_path / "black-box-medium.sqlite3")
    service = MediumSshService(
        trap_id=configuration["trap_id"], host="127.0.0.1",
        port=configuration["services"][0]["internal_port"], queue=queue,
        idle_timeout_seconds=1,
    )
    await service.start()
    server = uvicorn.Server(uvicorn.Config(
        lifecycle_app, host="127.0.0.1", port=api_port,
        ssl_certfile=str(certificate), ssl_keyfile=str(private_key),
        lifespan="off", log_level="error",
    ))
    server_task = asyncio.create_task(server.serve())
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.01)
        async with asyncssh.connect(
            "127.0.0.1", port=service.port, username="root", password="secret",
            known_hosts=None,
        ) as connection:
            process = await connection.create_process()
            await process.stdout.readuntil("$ ")
            process.stdin.write("whoami\nexit\n")
            await process.stdout.read()
        for _ in range(100):
            if queue.pending_count() == 5:
                break
            await asyncio.sleep(0.01)
        client = AgentClient(f"https://127.0.0.1:{api_port}", secret, ca_file=certificate)
        assert await client.deliver_pending(queue) == 5
    finally:
        await service.stop()
        queue.close()
        server.should_exit = True
        await server_task

    response = await lifecycle_client.get(f"/api/v1/security-events?trap_id={created['id']}")
    assert response.status_code == 200
    events = response.json()["items"]
    assert {event["event_type"] for event in events} == {
        "connection_opened", "authentication_attempt", "command_entered", "connection_closed"
    }
    assert any(event["payload"].get("username") == "root" for event in events)
    assert any(event["payload"].get("command") == "whoami" for event in events)
    _assert_events_visible_in_browser(events)


async def test_black_box_medium_fake_http_reaches_operator_api(
    lifecycle_app, lifecycle_client, tmp_path: Path
) -> None:
    http_port = _free_port()
    profile = await lifecycle_client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": "Black-box Medium HTTP",
            "interaction_level": "medium",
            "services": [{"protocol": "http", "internal_port": http_port}],
        },
    )
    assert profile.status_code == 201
    created_response = await lifecycle_client.post(
        "/api/v1/traps",
        headers={"Origin": "https://test"},
        json={"name": "black-box-medium-http", "trap_profile_id": profile.json()["id"]},
    )
    created = created_response.json()
    secret = await enroll_trap(lifecycle_client, created)
    certificate, private_key = create_test_certificate(tmp_path, name="center-medium-http")
    api_port = _free_port()
    configuration = (
        await lifecycle_client.get("/assets/v2/config", headers=authorization(secret))
    ).json()
    queue = EventQueue(tmp_path / "black-box-medium-http.sqlite3")
    service = MediumHttpService(
        trap_id=configuration["trap_id"], host="127.0.0.1",
        port=configuration["services"][0]["internal_port"], queue=queue,
        idle_timeout_seconds=1,
    )
    await service.start()
    server = uvicorn.Server(uvicorn.Config(
        lifecycle_app, host="127.0.0.1", port=api_port,
        ssl_certfile=str(certificate), ssl_keyfile=str(private_key),
        lifespan="off", log_level="error",
    ))
    server_task = asyncio.create_task(server.serve())
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.01)
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{service.port}", follow_redirects=False
        ) as fake_admin:
            marker = tmp_path / "medium-http-host-marker"
            login = await fake_admin.get("/login")
            assert login.status_code == 200
            authenticated = await fake_admin.post(
                "/login", data={"username": "operator", "password": "probe-secret"}
            )
            assert authenticated.status_code == 302
            admin = await fake_admin.get("/admin")
            assert admin.status_code == 200
            assert "System Overview" in admin.text
            malicious = await fake_admin.post(
                "/login",
                data={
                    "username": "probe",
                    "password": f"file://{marker}; touch {marker}",
                },
            )
            assert malicious.status_code == 302
            assert not marker.exists()
        for _ in range(100):
            if queue.pending_count() == 14:
                break
            await asyncio.sleep(0.01)
        assert queue.pending_count() == 14
        client = AgentClient(f"https://127.0.0.1:{api_port}", secret, ca_file=certificate)
        assert await client.deliver_pending(queue) == 14
    finally:
        await service.stop()
        queue.close()
        server.should_exit = True
        await server_task

    response = await lifecycle_client.get(
        f"/api/v1/security-events?trap_id={created['id']}"
    )
    assert response.status_code == 200
    events = response.json()["items"]
    assert [event["event_type"] for event in events].count("http_request") == 4
    assert any(
        event["event_type"] == "authentication_attempt"
        and event["payload"]["username"] == "operator"
        for event in events
    )
    assert len({event["attack_session_id"] for event in events}) == 1
    _assert_events_visible_in_browser(events)


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _assert_events_visible_in_browser(events: list[dict]) -> None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if chrome is None:
        pytest.skip("Chrome or Chromium is required for the black-box UI check")
    web_root = Path(__file__).parent.parent / "center" / "web"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/api/v1/security-events":
                body = json.dumps({"items": events, "next_cursor": None}).encode()
                content_type = "application/json"
            else:
                file_path = web_root / (self.path.lstrip("/") or "events.html")
                if not file_path.is_file():
                    self.send_error(404)
                    return
                body = file_path.read_bytes()
                content_type = {
                    ".html": "text/html",
                    ".css": "text/css",
                    ".js": "text/javascript",
                }.get(file_path.suffix, "application/octet-stream")
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
        rendered = subprocess.run(
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
    assert "Connection opened" in rendered.stdout
    assert "Connection closed" in rendered.stdout
