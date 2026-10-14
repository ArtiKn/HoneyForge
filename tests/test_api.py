from uuid import uuid4

import httpx
import pytest

from center.api.main import app


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as instance:
        yield instance


@pytest.mark.anyio
async def test_health_and_router_stubs(client: httpx.AsyncClient) -> None:
    assert (await client.get("/api/health")).json() == {"status": "ok"}
    for path in (
        "/api/v1/auth/ping",
        "/api/telemetry/ping",
    ):
        assert (await client.get(path)).status_code == 200
    for protected_path in (
        "/api/v1/trap-profiles/ping",
        "/api/v1/traps/ping",
        "/api/v1/security-events/ping",
        "/api/v1/dashboard",
    ):
        assert (await client.get(protected_path)).status_code == 401


@pytest.mark.anyio
async def test_masked_telemetry_endpoint_accepts_javascript_content_type(
    client: httpx.AsyncClient,
) -> None:
    payload = {
        "events": [
            {
                "id": str(uuid4()),
                "schema_version": 1,
                "trap_id": str(uuid4()),
                "attack_session_id": str(uuid4()),
                "event_type": "connection_opened",
                "observed_at": "2026-10-12T12:00:00Z",
                "source_ip": "192.0.2.10",
                "source_port": 4242,
                "target_service": "ssh",
                "target_port": 22,
                "payload": {},
            }
        ]
    }
    response = await client.post(
        "/assets/v2/init",
        headers={"Content-Type": "application/javascript"},
        json=payload,
    )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_masked_telemetry_endpoint_rejects_invalid_batch(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/assets/v2/init",
        headers={"Content-Type": "application/javascript"},
        content=b'{"events":[{}]}',
    )
    assert response.status_code == 422


def test_openapi_documents_masked_content_type_without_dangling_refs() -> None:
    schema = app.openapi()
    request_body = schema["paths"]["/assets/v2/init"]["post"]["requestBody"]
    event_schema = request_body["content"]["application/javascript"]["schema"]
    assert event_schema["title"] == "TelemetryBatch"
    assert "$defs" in event_schema

