import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select

from center.api.config import Settings
from center.api.main import create_app
from center.api.models import AuditEntry, SecurityEvent, Trap


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


async def create_profile(client: httpx.AsyncClient) -> str:
    response = await client.post(
        "/api/v1/trap-profiles",
        headers={"Origin": "https://test"},
        json={
            "name": "Lifecycle profile",
            "interaction_level": "medium",
            "services": [{"protocol": "ssh", "internal_port": 22}],
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


async def precreate_trap(client: httpx.AsyncClient) -> dict:
    profile_id = await create_profile(client)
    response = await client.post(
        "/api/v1/traps",
        headers={"Origin": "https://test"},
        json={"name": "edge-01", "trap_profile_id": profile_id, "region": "dmz"},
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
