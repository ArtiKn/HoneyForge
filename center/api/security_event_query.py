import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from center.api.models import SecurityEvent
from center.api.schemas.security_event import SecurityEventPage


class InvalidSecurityEventCursor(ValueError):
    pass


@dataclass(frozen=True)
class SecurityEventFilters:
    trap_id: UUID | None = None
    attack_session_id: UUID | None = None
    event_type: str | None = None
    source_ip: str | None = None
    received_from: datetime | None = None
    received_to: datetime | None = None


class SecurityEventQuery:
    """Apply investigation filters and stable pagination behind one interface."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def page(
        self,
        filters: SecurityEventFilters,
        *,
        cursor: str | None,
        limit: int,
    ) -> SecurityEventPage:
        statement = select(SecurityEvent).order_by(
            desc(SecurityEvent.received_at), desc(SecurityEvent.id)
        )
        comparisons = {
            SecurityEvent.trap_id: filters.trap_id,
            SecurityEvent.attack_session_id: filters.attack_session_id,
            SecurityEvent.event_type: filters.event_type,
            SecurityEvent.source_ip: filters.source_ip,
        }
        for column, value in comparisons.items():
            if value is not None:
                statement = statement.where(column == value)
        if filters.received_from is not None:
            statement = statement.where(
                SecurityEvent.received_at >= filters.received_from
            )
        if filters.received_to is not None:
            statement = statement.where(SecurityEvent.received_at <= filters.received_to)
        if cursor is not None:
            received_at, event_id = self._decode_cursor(cursor)
            statement = statement.where(
                or_(
                    SecurityEvent.received_at < received_at,
                    and_(
                        SecurityEvent.received_at == received_at,
                        SecurityEvent.id < event_id,
                    ),
                )
            )
        events = list(await self._session.scalars(statement.limit(limit + 1)))
        has_more = len(events) > limit
        items = events[:limit]
        next_cursor = (
            self._encode_cursor(items[-1].received_at, items[-1].id)
            if has_more and items
            else None
        )
        return SecurityEventPage(items=items, next_cursor=next_cursor)

    @staticmethod
    def _encode_cursor(received_at: datetime, event_id: UUID) -> str:
        value = json.dumps([received_at.isoformat(), str(event_id)]).encode()
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    @staticmethod
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
            raise InvalidSecurityEventCursor from exc
