from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from center.api.config import Settings
from center.api.main import create_app
from center.api.models import AuditEntry, Operator
from center.api.operator_auth import verify_password
from tests.conftest import (
    TEST_OPERATOR_PASSWORD,
    TEST_OPERATOR_USERNAME,
    build_settings,
)


pytestmark = pytest.mark.asyncio


@pytest.fixture
async def auth_app(postgres_application):
    """PostgreSQL-backed Control API shared with the anonymous client."""

    yield postgres_application


@pytest.fixture
async def auth_client(anonymous_client):
    """Unauthenticated API client sharing the PostgreSQL-backed application."""

    yield anonymous_client


async def test_operator_can_login_reach_dashboard_and_logout(auth_app, auth_client) -> None:
    unauthenticated = await auth_client.get("/api/v1/dashboard")
    assert unauthenticated.status_code == 401

    login = await auth_client.post(
        "/api/v1/auth/login",
        headers={"Origin": "https://test"},
        json={"username": "operator", "password": "correct horse battery staple"},
    )
    assert login.status_code == 204
    cookie = login.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=strict" in cookie
    assert "Max-Age=28800" in cookie
    session_token = auth_client.cookies["honeyforge_session"]

    dashboard = await auth_client.get("/api/v1/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.json() == {"operator": "operator"}

    identity = await auth_client.get("/api/v1/auth/me")
    assert identity.status_code == 200
    assert identity.json() == {"username": "operator", "role": "admin"}

    logout = await auth_client.post(
        "/api/v1/auth/logout", headers={"Origin": "https://test"}
    )
    assert logout.status_code == 204
    assert (await auth_client.get("/api/v1/dashboard")).status_code == 401
    auth_client.cookies.set("honeyforge_session", session_token)
    assert (await auth_client.get("/api/v1/dashboard")).status_code == 401

    async with auth_app.state.database.session_factory() as session:
        operators = await session.scalar(select(func.count()).select_from(Operator))
        operator = await session.scalar(select(Operator))
        audit_actions = list(
            await session.scalars(select(AuditEntry.action).order_by(AuditEntry.id))
        )
    assert operators == 1
    assert operator is not None
    assert operator.role == "admin"
    assert operator.password_hash != "correct horse battery staple"
    assert verify_password("correct horse battery staple", operator.password_hash)
    assert audit_actions == ["operator.login.succeeded", "operator.logout"]


async def test_invalid_login_is_generic_audited_and_does_not_set_cookie(
    auth_app, auth_client
) -> None:
    response = await auth_client.post(
        "/api/v1/auth/login",
        headers={"Origin": "https://test"},
        json={"username": "unknown", "password": "wrong"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}
    assert "set-cookie" not in response.headers

    async with auth_app.state.database.session_factory() as session:
        actions = list(await session.scalars(select(AuditEntry.action)))
        details = list(await session.scalars(select(AuditEntry.details)))
    assert actions == ["operator.login.failed"]
    assert details == [{"username": "unknown"}]


async def test_state_changes_reject_untrusted_origins(auth_client) -> None:
    response = await auth_client.post(
        "/api/v1/auth/login",
        headers={"Origin": "https://evil.example"},
        json={"username": "operator", "password": "correct horse battery staple"},
    )
    assert response.status_code == 403


async def test_identity_endpoint_requires_authentication(auth_client) -> None:
    response = await auth_client.get("/api/v1/auth/me")

    assert response.status_code == 401


async def test_seeded_operator_role_comes_from_settings(
    migrated_database_url,
) -> None:
    application = create_app(
        build_settings(migrated_database_url, operator_role="viewer")
    )
    transport = httpx.ASGITransport(app=application)
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(
            transport=transport, base_url="https://test"
        ) as client:
            login = await client.post(
                "/api/v1/auth/login",
                headers={"Origin": "https://test"},
                json={
                    "username": TEST_OPERATOR_USERNAME,
                    "password": TEST_OPERATOR_PASSWORD,
                },
            )
            identity = await client.get("/api/v1/auth/me")
    assert login.status_code == 204
    assert identity.json() == {
        "username": TEST_OPERATOR_USERNAME,
        "role": "viewer",
    }


async def test_optional_read_only_operator_is_seeded_from_settings(
    migrated_database_url,
) -> None:
    application = create_app(
        build_settings(
            migrated_database_url,
            operator_viewer_username="auditor",
            operator_viewer_password="auditor-password",
        )
    )
    transport = httpx.ASGITransport(app=application)
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(
            transport=transport, base_url="https://test"
        ) as client:
            login = await client.post(
                "/api/v1/auth/login",
                headers={"Origin": "https://test"},
                json={"username": "auditor", "password": "auditor-password"},
            )
            identity = await client.get("/api/v1/auth/me")
            mutation = await client.post(
                "/api/v1/trap-profiles",
                headers={"Origin": "https://test"},
                json={
                    "name": "auditor-should-not-create",
                    "interaction_level": "low",
                    "services": [{"protocol": "ssh", "internal_port": 22}],
                },
            )
    assert login.status_code == 204
    assert identity.json() == {"username": "auditor", "role": "viewer"}
    assert mutation.status_code == 403


async def test_half_configured_viewer_operator_is_refused() -> None:
    from center.api.config import validate_deployment_secrets

    settings = build_settings(
        "postgresql+asyncpg://u:p@localhost/db", operator_viewer_username="auditor"
    )

    with pytest.raises(RuntimeError, match="OPERATOR_VIEWER"):
        validate_deployment_secrets(settings)

    # Leaving both unset keeps the center a single-Operator deployment.
    assert validate_deployment_secrets(
        build_settings("postgresql+asyncpg://u:p@localhost/db")
    ) is None
    assert Settings(operator_viewer_username=None).operator_viewer_username is None


async def test_health_and_readiness_have_distinct_meanings(auth_client) -> None:
    assert (await auth_client.get("/health")).json() == {"status": "ok"}
    assert (await auth_client.get("/ready")).json() == {"status": "ready"}


async def test_readiness_fails_without_hiding_process_liveness(
    auth_app, auth_client, monkeypatch
) -> None:
    async def database_unavailable() -> None:
        raise SQLAlchemyError("database unavailable")

    monkeypatch.setattr(auth_app.state.database, "ready", database_unavailable)
    assert (await auth_client.get("/ready")).status_code == 503
    assert (await auth_client.get("/health")).status_code == 200


async def test_websocket_requires_the_operator_cookie(auth_app, auth_client) -> None:
    assert await websocket_handshake(auth_app) == [
        {"type": "websocket.close", "code": 1008, "reason": ""}
    ]

    login = await auth_client.post(
        "/api/v1/auth/login",
        headers={"Origin": "https://test"},
        json={"username": "operator", "password": "correct horse battery staple"},
    )
    assert login.status_code == 204
    token = auth_client.cookies["honeyforge_session"]
    messages = await websocket_handshake(
        auth_app, cookie=f"honeyforge_session={token}"
    )
    assert messages[0]["type"] == "websocket.accept"


async def websocket_handshake(application, cookie: str | None = None) -> list[dict]:
    incoming: AsyncIterator[dict] = _websocket_messages()
    sent: list[dict] = []
    headers = [] if cookie is None else [(b"cookie", cookie.encode())]
    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "scheme": "wss",
        "path": "/ws",
        "raw_path": b"/ws",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("test", 443),
        "subprotocols": [],
        "state": {},
    }

    async def receive() -> dict:
        return await anext(incoming)

    async def send(message: dict) -> None:
        sent.append(message)

    await application(scope, receive, send)
    return sent


async def _websocket_messages() -> AsyncIterator[dict]:
    yield {"type": "websocket.connect"}
    yield {"type": "websocket.disconnect", "code": 1000, "reason": ""}


async def test_startup_rejects_placeholder_credentials() -> None:
    application = create_app(
        Settings(jwt_secret="change-me", operator_password="change-me-in-production")
    )
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        async with application.router.lifespan_context(application):
            pass
