"""Shared pytest fixtures for the HoneyForge test suite.

PostgreSQL-backed tests run only when ``TEST_DATABASE_URL`` is set. The helpers
here centralize the Alembic migration cycle and the Control API settings that
used to be duplicated across the API test modules.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from center.api.config import Settings
from center.api.main import create_app
from center.api.models import Operator
from center.api.operator_auth import hash_password
from tests.support import run_migrations

TEST_JWT_SECRET = "test-secret-that-is-long-enough"
TEST_OPERATOR_USERNAME = "operator"
TEST_OPERATOR_PASSWORD = "correct horse battery staple"
TEST_OPERATOR_ROLE = "admin"
TEST_VIEWER_USERNAME = "viewer"
TEST_VIEWER_PASSWORD = "read only battery staple"
TEST_ORIGIN = "https://test"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def test_database_url() -> str:
    """Return the dedicated PostgreSQL URL, or skip the PostgreSQL seam."""

    database_url = os.getenv("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("set TEST_DATABASE_URL to run PostgreSQL integration tests")
    return database_url


def build_settings(database_url: str, **overrides: object) -> Settings:
    """Build Control API settings for a PostgreSQL-backed test application."""

    values: dict[str, object] = {
        "database_url": database_url,
        "jwt_secret": TEST_JWT_SECRET,
        "operator_username": TEST_OPERATOR_USERNAME,
        "operator_password": TEST_OPERATOR_PASSWORD,
        "operator_role": TEST_OPERATOR_ROLE,
        "cors_origins": [TEST_ORIGIN],
    }
    values.update(overrides)
    return Settings(**values)


async def create_operator(
    application: FastAPI, username: str, password: str, role: str
) -> None:
    """Insert an additional Operator with an explicit role for RBAC tests."""

    async with application.state.database.session_factory() as session:
        session.add(
            Operator(
                username=username,
                password_hash=hash_password(password),
                role=role,
                is_active=True,
                session_version=0,
            )
        )
        await session.commit()


@pytest.fixture
async def migrated_database_url(test_database_url: str) -> AsyncIterator[str]:
    """Provide a database with the canonical schema applied, then revert it."""

    run_migrations(test_database_url, "upgrade", "head")
    try:
        yield test_database_url
    finally:
        # Teardown discards this test's observations before checking the downgrade.
        # Production downgrade intentionally refuses to invalidate v2 history.
        engine = create_async_engine(test_database_url)
        try:
            async with engine.begin() as connection:
                await connection.execute(text("TRUNCATE security_events"))
        finally:
            await engine.dispose()
        run_migrations(test_database_url, "downgrade", "base")


@pytest.fixture
async def postgres_application(migrated_database_url: str) -> AsyncIterator[FastAPI]:
    """Run the Control API against the migrated PostgreSQL database."""

    application = create_app(build_settings(migrated_database_url))
    async with application.router.lifespan_context(application):
        yield application


@pytest.fixture
async def anonymous_client(postgres_application: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """An API client that shares the PostgreSQL-backed application."""

    transport = httpx.ASGITransport(app=postgres_application)
    async with httpx.AsyncClient(transport=transport, base_url=TEST_ORIGIN) as client:
        yield client


@pytest.fixture
async def operator_client(anonymous_client: httpx.AsyncClient) -> AsyncIterator[httpx.AsyncClient]:
    """An API client already authenticated as the seeded Operator."""

    login = await anonymous_client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={
            "username": TEST_OPERATOR_USERNAME,
            "password": TEST_OPERATOR_PASSWORD,
        },
    )
    assert login.status_code == 204
    yield anonymous_client


@pytest.fixture
async def viewer_client(
    anonymous_client: httpx.AsyncClient, postgres_application: FastAPI
) -> AsyncIterator[httpx.AsyncClient]:
    """An API client authenticated as a read-only Operator."""

    await create_operator(
        postgres_application, TEST_VIEWER_USERNAME, TEST_VIEWER_PASSWORD, "viewer"
    )
    login = await anonymous_client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={
            "username": TEST_VIEWER_USERNAME,
            "password": TEST_VIEWER_PASSWORD,
        },
    )
    assert login.status_code == 204
    yield anonymous_client
