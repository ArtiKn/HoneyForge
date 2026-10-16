"""Control API application (task 2.1).

Wires the routers, CORS, the health check used by the center stack (task 6.1)
and the Nginx proxy check (task 6.4), and the realtime WebSocket.
The masked telemetry endpoint (task 4.2) lives in ``routers/telemetry.py``.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress

from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from center.api.auth_dependencies import SESSION_COOKIE, require_operator
from center.api.config import Settings, get_settings, validate_deployment_secrets
from center.api.database import Database
from center.api.operator_auth import operator_for_session, seed_operator
from center.api.realtime.pg_listener import SecurityEventRelay
from center.api.realtime.ws_manager import ConnectionManager
from center.api.retention import DataRetention, monitor_retention
from center.api.routers import (
    agent,
    auth,
    dashboard,
    security_events,
    telemetry,
    trap_profiles,
    traps,
)
from center.api.trap_access import monitor_offline_traps


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or get_settings()
    database = Database(app_settings.database_url)
    connections = ConnectionManager()
    event_relay = SecurityEventRelay(
        app_settings.database_url, connections, database.session_factory
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        validate_deployment_secrets(app_settings)
        await seed_operator(
            database.session_factory,
            app_settings.operator_username,
            app_settings.operator_password,
            app_settings.operator_role,
        )
        if (
            app_settings.operator_viewer_username
            and app_settings.operator_viewer_password
        ):
            await seed_operator(
                database.session_factory,
                app_settings.operator_viewer_username,
                app_settings.operator_viewer_password,
                "viewer",
            )
        await event_relay.start()
        health_monitor = asyncio.create_task(
            monitor_offline_traps(
                database.session_factory,
                health_timeout_seconds=app_settings.health_timeout_seconds,
                sweep_interval_seconds=app_settings.health_sweep_interval_seconds,
            )
        )
        retention_monitor = asyncio.create_task(
            monitor_retention(
                DataRetention(
                    database.session_factory,
                    security_days=app_settings.security_data_retention_days,
                    audit_days=app_settings.audit_entry_retention_days,
                ),
                sweep_interval_seconds=app_settings.retention_sweep_interval_seconds,
            )
        )
        try:
            yield
        finally:
            await event_relay.stop()
            health_monitor.cancel()
            retention_monitor.cancel()
            with suppress(asyncio.CancelledError):
                await health_monitor
            with suppress(asyncio.CancelledError):
                await retention_monitor
            await database.close()

    application = FastAPI(
        title=app_settings.app_name,
        debug=app_settings.debug,
        lifespan=lifespan,
    )
    application.state.settings = app_settings
    application.state.database = database
    application.state.connections = connections
    application.state.event_relay = event_relay
    application.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @application.middleware("http")
    async def validate_origin(request: Request, call_next):
        if request.url.path.startswith("/api/v1/") and request.method not in {
            "GET",
            "HEAD",
            "OPTIONS",
        }:
            if request.headers.get("origin") not in app_settings.cors_origins:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Untrusted origin"},
                )
        return await call_next(request)

    application.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
    protected = [Depends(require_operator)]
    application.include_router(
        dashboard.router,
        prefix="/api/v1/dashboard",
        tags=["dashboard"],
        dependencies=protected,
    )
    application.include_router(
        trap_profiles.router,
        prefix="/api/v1/trap-profiles",
        tags=["trap-profiles"],
        dependencies=protected,
    )
    application.include_router(
        traps.router,
        prefix="/api/v1/traps",
        tags=["traps"],
        dependencies=protected,
    )
    application.include_router(
        security_events.router,
        prefix="/api/v1/security-events",
        tags=["security-events"],
        dependencies=protected,
    )
    application.include_router(telemetry.router)
    application.include_router(agent.router)

    @application.get("/health", tags=["health"])
    @application.get("/api/health", tags=["health"], include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/ready", tags=["health"])
    @application.get("/api/ready", tags=["health"], include_in_schema=False)
    async def ready():
        try:
            await database.ready()
        except SQLAlchemyError:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unavailable"},
            )
        return {"status": "ready"}

    @application.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        async with database.session_factory() as session:
            operator = await operator_for_session(
                session,
                websocket.cookies.get(SESSION_COOKIE),
                app_settings.jwt_secret,
            )
        if operator is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        if not await connections.connect(websocket):
            return
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            connections.disconnect(websocket)

    return application


app = create_app()
