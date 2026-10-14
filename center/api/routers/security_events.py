from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import IPvAnyAddress
from sqlalchemy.ext.asyncio import AsyncSession

from center.api.database import get_db
from center.api.security_event_query import (
    InvalidSecurityEventCursor,
    SecurityEventFilters,
    SecurityEventQuery,
)
from center.api.schemas.security_event import SecurityEventPage

router = APIRouter()


@router.get("/ping")
async def ping() -> dict[str, str]:
    return {"status": "ok"}


@router.get("", response_model=SecurityEventPage)
async def list_security_events(
    session: Annotated[AsyncSession, Depends(get_db)],
    trap_id: UUID | None = None,
    attack_session_id: UUID | None = None,
    event_type: Literal[
        "connection_opened",
        "authentication_attempt",
        "command_entered",
        "http_request",
        "connection_closed",
    ]
    | None = None,
    source_ip: IPvAnyAddress | None = None,
    received_from: datetime | None = None,
    received_to: datetime | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> SecurityEventPage:
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
    try:
        return await SecurityEventQuery(session).page(
            SecurityEventFilters(
                trap_id=trap_id,
                attack_session_id=attack_session_id,
                event_type=event_type,
                source_ip=str(source_ip) if source_ip is not None else None,
                received_from=received_from,
                received_to=received_to,
            ),
            cursor=cursor,
            limit=limit,
        )
    except InvalidSecurityEventCursor as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid Security Event cursor",
        ) from exc

