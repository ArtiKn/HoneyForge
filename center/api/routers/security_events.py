import base64
import binascii
import json
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from center.api.database import get_db
from center.api.models import SecurityEvent
from center.api.schemas.security_event import SecurityEventPage

router = APIRouter()


@router.get("/ping")
async def ping() -> dict[str, str]:
    return {"status": "ok"}


def _encode_cursor(received_at: datetime, event_id: UUID) -> str:
    value = json.dumps([received_at.isoformat(), str(event_id)]).encode()
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    try:
        padding = "=" * (-len(cursor) % 4)
        received_at, event_id = json.loads(
            base64.urlsafe_b64decode(cursor + padding).decode()
        )
        parsed_at = datetime.fromisoformat(received_at)
        if parsed_at.tzinfo is None:
            raise ValueError
        return parsed_at, UUID(event_id)
    except (
        ValueError,
        TypeError,
        binascii.Error,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid Security Event cursor",
        ) from exc


@router.get("", response_model=SecurityEventPage)
async def list_security_events(
    session: Annotated[AsyncSession, Depends(get_db)],
    trap_id: UUID | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> SecurityEventPage:
    statement = select(SecurityEvent).order_by(
        desc(SecurityEvent.received_at), desc(SecurityEvent.id)
    )
    if trap_id is not None:
        statement = statement.where(SecurityEvent.trap_id == trap_id)
    if cursor is not None:
        received_at, event_id = _decode_cursor(cursor)
        statement = statement.where(
            or_(
                SecurityEvent.received_at < received_at,
                and_(
                    SecurityEvent.received_at == received_at,
                    SecurityEvent.id < event_id,
                ),
            )
        )
    events = list(await session.scalars(statement.limit(limit + 1)))
    has_more = len(events) > limit
    items = events[:limit]
    next_cursor = (
        _encode_cursor(items[-1].received_at, items[-1].id)
        if has_more and items
        else None
    )
    return SecurityEventPage(items=items, next_cursor=next_cursor)

