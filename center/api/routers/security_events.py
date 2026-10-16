from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from ipaddress import ip_address
from sqlalchemy.ext.asyncio import AsyncSession

from center.api.database import get_db
from center.api.security_event_csv import render_security_event_csv
from center.api.security_event_query import (
    InvalidSecurityEventCursor,
    SecurityEventFilters,
    SecurityEventQuery,
)
from center.api.schemas.security_event import SecurityEventPage

router = APIRouter()

SecurityEventType = Literal[
    "connection_opened",
    "authentication_attempt",
    "command_entered",
    "http_request",
    "connection_closed",
    "payload_received",
    "database_query",
]

EXPORT_LIMIT_DEFAULT = 10_000
EXPORT_LIMIT_MAXIMUM = 50_000


class SecurityEventFilterParams:
    """Investigation filters shared by the list view and the IoC export."""

    def __init__(
        self,
        trap_id: UUID | None = None,
        attack_session_id: UUID | None = None,
        event_type: SecurityEventType | None = None,
        source_ip: str | None = None,
        received_from: datetime | None = None,
        received_to: datetime | None = None,
    ) -> None:
        if source_ip is not None:
            try:
                source_ip = str(ip_address(source_ip.strip()))
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Укажите IP источника без порта и маски сети, например 192.0.2.44 или 2001:db8::1.",
                ) from exc
        for value in (received_from, received_to):
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Security Event time filters must include a UTC offset",
                )
        if (
            received_from is not None
            and received_to is not None
            and received_from > received_to
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="received_from must not be later than received_to",
            )
        self.trap_id = trap_id
        self.attack_session_id = attack_session_id
        self.event_type = event_type
        self.source_ip = source_ip
        self.received_from = received_from
        self.received_to = received_to

    def to_filters(self) -> SecurityEventFilters:
        return SecurityEventFilters(
            trap_id=self.trap_id,
            attack_session_id=self.attack_session_id,
            event_type=self.event_type,
            source_ip=self.source_ip,
            received_from=self.received_from,
            received_to=self.received_to,
        )


@router.get("/ping")
async def ping() -> dict[str, str]:
    return {"status": "ok"}


@router.get("", response_model=SecurityEventPage)
async def list_security_events(
    session: Annotated[AsyncSession, Depends(get_db)],
    filters: Annotated[SecurityEventFilterParams, Depends()],
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> SecurityEventPage:
    try:
        return await SecurityEventQuery(session).page(
            filters.to_filters(), cursor=cursor, limit=limit
        )
    except InvalidSecurityEventCursor as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid Security Event cursor",
        ) from exc


@router.get(
    "/export.csv",
    response_class=Response,
    responses={
        200: {
            "content": {"text/csv": {}},
            "description": "Security Events as an IoC CSV export",
        }
    },
)
async def export_security_events_csv(
    session: Annotated[AsyncSession, Depends(get_db)],
    filters: Annotated[SecurityEventFilterParams, Depends()],
    limit: Annotated[int, Query(ge=1, le=EXPORT_LIMIT_MAXIMUM)] = EXPORT_LIMIT_DEFAULT,
) -> Response:
    """Export the filtered Security Events for sharing outside the center (FR-C7)."""

    rows = await SecurityEventQuery(session).export_rows(
        filters.to_filters(), limit=limit
    )
    document = render_security_event_csv(rows)
    filename = f"honeyforge-ioc-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.csv"
    return Response(
        content=document,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )