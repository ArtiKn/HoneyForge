"""Control API stub (task 2.1).

Provides the health check required by the center stack (task 6.1) and the
Nginx proxy check (task 6.4), plus the masked telemetry endpoint (task 4.2).
"""

from __future__ import annotations

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware

from center.api.config import get_settings
from center.api.realtime.ws_manager import manager
from center.api.routers import auth, events, honeypots, profiles, telemetry


settings = get_settings()
app = FastAPI(title=settings.app_name, debug=settings.debug)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(profiles.router, prefix="/api/profiles", tags=["profiles"])
app.include_router(honeypots.router, prefix="/api/honeypots", tags=["honeypots"])
app.include_router(events.router, prefix="/api/events", tags=["events"])
app.include_router(telemetry.router)


@app.get("/api/health", tags=["health"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.post(settings.telemetry_path, include_in_schema=False)
async def telemetry(request: Request) -> dict[str, int]:
    """Accept masked telemetry behind a CDN-like path (task 4.2)."""
    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001
        payload = {}

    events = payload.get("events", []) if isinstance(payload, dict) else []
    return {"accepted": len(events)}
  