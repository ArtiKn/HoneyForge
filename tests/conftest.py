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

from center.api.config import Settings
from center.api.main import create_app
from tests.support import run_migrations

TEST_JWT_SECRET = "test-secret-that-is-long-enough"
TEST_OPERATOR_USERNAME = "operator"
TEST_OPERATOR_PASSWORD = "correct horse battery staple"
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
        "cors_origins": [TEST_ORIGIN],
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
async def migrated_database_url(test_database_url: str) -> AsyncIterator[str]:
    """Provide a database with the canonical schema applied, then revert it."""

    run_migrations(test_database_url, "upgrade", "head")
    try:
        yield test_database_url
    finally:
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
