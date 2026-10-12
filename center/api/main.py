"""Control API stub (task 2.1).

Provides the health check required by the center stack (task 6.1) and the
Nginx proxy check (task 6.4), plus the masked telemetry endpoint (task 4.2).
"""

from __future__ import annotations

from fastapi import FastAPI, Request

from config import settings

app = FastAPI(
    title="HoneyForge Control API",
    version="0.1.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url=None,
)


@app.get("/api/health", tags=["system"])
async def health() -> dict[str, str]:
    """Return service health (task 6.4 acceptance check)."""
    return {"status": "ok", "service": "api"}


@app.post(settings.telemetry_path, include_in_schema=False)
async def telemetry(request: Request) -> dict[str, int]:
    """Accept masked telemetry behind a CDN-like path (task 4.2)."""
    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001
        payload = {}

    events = payload.get("events", []) if isinstance(payload, dict) else []
    return {"accepted": len(events)}
