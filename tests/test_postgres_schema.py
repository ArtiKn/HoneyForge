import os
import subprocess
import sys

import pytest
from sqlalchemy import inspect
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine


@pytest.mark.asyncio
async def test_canonical_schema_applies_to_real_postgresql() -> None:
    database_url = os.getenv("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("set TEST_DATABASE_URL to run the PostgreSQL integration seam")

    if not (make_url(database_url).database or "").endswith("_test"):
        pytest.fail("TEST_DATABASE_URL must name a dedicated database ending in _test")

    environment = os.environ | {"DATABASE_URL": database_url}
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
    )
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as connection:
            table_names = await connection.run_sync(
                lambda sync_connection: set(inspect(sync_connection).get_table_names())
                - {"alembic_version"}
            )
        assert table_names == {
            "trap_profiles",
            "traps",
            "security_events",
            "attack_sessions",
            "operators",
            "audit_entries",
        }
    finally:
        await engine.dispose()
        subprocess.run(
            [sys.executable, "-m", "alembic", "downgrade", "base"],
            check=True,
            env=environment,
            capture_output=True,
            text=True,
        )
