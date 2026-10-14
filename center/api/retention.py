import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from center.api.models import AttackSession, AuditEntry, SecurityEvent


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RetentionResult:
    security_events: int
    attack_sessions: int
    audit_entries: int


class DataRetention:
    """Apply the independent security and audit retention policies atomically."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        security_days: int,
        audit_days: int,
    ) -> None:
        self._session_factory = session_factory
        self._security_period = timedelta(days=security_days)
        self._audit_period = timedelta(days=audit_days)

    async def cleanup(self, now: datetime) -> RetentionResult:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("retention time must include a UTC offset")
        security_cutoff = now.astimezone(UTC) - self._security_period
        audit_cutoff = now.astimezone(UTC) - self._audit_period
        async with self._session_factory() as session:
            events = await session.execute(
                delete(SecurityEvent).where(
                    SecurityEvent.received_at < security_cutoff
                ).returning(SecurityEvent.attack_session_id)
            )
            expired_event_session_ids = list(events.scalars())
            expired_session_ids = set(expired_event_session_ids)
            sessions = await session.execute(
                delete(AttackSession).where(
                    or_(
                        AttackSession.id.in_(expired_session_ids),
                        AttackSession.started_at < security_cutoff,
                    ),
                    ~exists(
                        select(SecurityEvent.id).where(
                            SecurityEvent.attack_session_id == AttackSession.id
                        )
                    ),
                )
            )
            audit_entries = await session.execute(
                delete(AuditEntry).where(AuditEntry.created_at < audit_cutoff)
            )
            await session.commit()
        return RetentionResult(
            security_events=len(expired_event_session_ids),
            attack_sessions=sessions.rowcount,
            audit_entries=audit_entries.rowcount,
        )


async def monitor_retention(
    retention: DataRetention,
    *,
    sweep_interval_seconds: float,
) -> None:
    while True:
        await asyncio.sleep(sweep_interval_seconds)
        try:
            await retention.cleanup(datetime.now(UTC))
        except Exception:
            logger.exception("Data retention sweep failed")
