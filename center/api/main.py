"""Control API application (task 2.1).

Wires the routers, CORS, the health check used by the center stack (task 6.1)
and the Nginx proxy check (task 6.4), and the realtime WebSocket.
The masked telemetry endpoint (task 4.2) lives in ``routers/telemetry.py``.
"""

from __future__ import annotations

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from center.api.config import get_settings
from center.api.realtime.ws_manager import manager
from center.api.routers import auth, security_events, telemetry, trap_profiles, traps


settings = get_settings()
app = FastAPI(title=settings.app_name, debug=settings.debug)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(trap_profiles.router, prefix="/api/v1/trap-profiles", tags=["trap-profiles"])
app.include_router(traps.router, prefix="/api/v1/traps", tags=["traps"])
app.include_router(
    security_events.router,
    prefix="/api/v1/security-events",
    tags=["security-events"],
)
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
