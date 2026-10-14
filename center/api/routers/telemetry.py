from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import ValidationError

from center.api.schemas.telemetry import TelemetryBatch
from center.api.event_ingestion import SecurityEventIngestor
from center.api.trap_access import TrapAccess

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
async def receive_telemetry(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, list[str]]:
    """Accept JSON hidden behind the CDN-like content type used by agents."""

    try:
        batch = TelemetryBatch.model_validate_json(await request.body())
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=exc.errors(include_url=False),
        ) from exc
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    credential = authorization.removeprefix("Bearer ")
    async with request.app.state.database.session_factory() as session:
        trap = await TrapAccess(session).authenticate(credential)
        if trap is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        if any(event.trap_id != trap.id for event in batch.events):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Telemetry batch contains an event for another Trap",
            )
        accepted = await SecurityEventIngestor(session).ingest(trap, batch.events)
        await session.commit()
    return {"accepted": [str(event_id) for event_id in accepted]}


