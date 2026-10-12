from fastapi import APIRouter, HTTPException, Request, status
from pydantic import ValidationError

from center.api.schemas.telemetry import TelemetryBatch
from center.collector.ingest import ingest

router = APIRouter()
TELEMETRY_SCHEMA = TelemetryBatch.model_json_schema()


@router.get("/api/telemetry/ping", tags=["telemetry"])
async def ping() -> dict[str, str]:
    return {"status": "ok"}


@router.post(
    "/assets/v2/init",
    tags=["telemetry"],
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/javascript": {"schema": TELEMETRY_SCHEMA},
                "application/json": {"schema": TELEMETRY_SCHEMA},
            },
        }
    },
)
async def receive_telemetry(request: Request) -> dict[str, bool]:
    """Accept JSON hidden behind the CDN-like content type used by agents."""

    try:
        batch = TelemetryBatch.model_validate_json(await request.body())
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=exc.errors(include_url=False),
        ) from exc
    ingest(batch.events)
    return {"ok": True}


