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
        "/api/auth/ping",
        "/api/profiles/ping",
        "/api/honeypots/ping",
        "/api/events/ping",
        "/api/telemetry/ping",
    ):
        assert (await client.get(path)).status_code == 200


@pytest.mark.anyio
async def test_masked_telemetry_endpoint_accepts_javascript_content_type(
    client: httpx.AsyncClient,
) -> None:
    payload = {
        "events": [
            {
                "ts": "2026-10-12T12:00:00Z",
                "honeypot_id": str(uuid4()),
                "src_ip": "192.0.2.10",
                "src_port": 4242,
                "dst_port": 22,
                "proto": "tcp",
                "action": "connect",
                "creds": None,
                "cmd": None,
                "raw": "",
            }
        ]
    }
    response = await client.post(
        "/assets/v2/init",
        headers={"Content-Type": "application/javascript"},
        json=payload,
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True}


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

