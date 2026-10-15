import pytest
from sqlalchemy import inspect
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from tests.support import run_migrations


@pytest.mark.asyncio
async def test_canonical_schema_applies_to_real_postgresql(test_database_url: str) -> None:
    if not (make_url(test_database_url).database or "").endswith("_test"):
        pytest.fail("TEST_DATABASE_URL must name a dedicated database ending in _test")

    run_migrations(test_database_url, "upgrade", "head")
    engine = create_async_engine(test_database_url)
    try:
        async with engine.connect() as connection:
            table_names = await connection.run_sync(
                lambda sync_connection: set(inspect(sync_connection).get_table_names())
                - {"alembic_version"}
            )
            security_event_indexes = await connection.run_sync(
                lambda sync_connection: {
                    index["name"]
                    for index in inspect(sync_connection).get_indexes("security_events")
                }
            )
        assert table_names == {
            "trap_profiles",
            "traps",
            "security_events",
            "attack_sessions",
            "operators",
            "audit_entries",
        }
        assert {
            "idx_security_events_received_id",
            "idx_security_events_attack_session",
        } <= security_event_indexes
    finally:
        await engine.dispose()
        run_migrations(test_database_url, "downgrade", "base")
