from datetime import UTC, datetime
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from center.api.models import AttackSession, SecurityEvent, Trap
from center.api.schemas.security_event import SecurityEventSchema


class SecurityEventIngestor:
    """Atomically persist one Trap's sessions and deduplicated Security Events."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def ingest(
        self, trap: Trap, events: list[SecurityEventSchema]
    ) -> list[UUID]:
        received_at = datetime.now(UTC)
        unique_events: dict[UUID, SecurityEventSchema] = {}
        for incoming in events:
            previous = unique_events.get(incoming.id)
            if previous is not None and previous != incoming:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Security Event UUID collides with different data",
                )
            unique_events[incoming.id] = incoming

        lock_keys = {
            incoming.id.int & ((1 << 63) - 1) for incoming in unique_events.values()
        } | {
            -1 - (incoming.attack_session_id.int & ((1 << 63) - 1))
            for incoming in unique_events.values()
        }
        for lock_key in sorted(lock_keys):
            await self.session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_key)"),
                {"lock_key": lock_key},
            )

        existing_by_id: dict[UUID, SecurityEvent] = {}
        for incoming in unique_events.values():
            existing = await self.session.get(SecurityEvent, incoming.id)
            if existing is not None:
                if not self._same_event(existing, incoming, trap.id):
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                        detail="Security Event UUID collides with different data",
                    )
                existing_by_id[incoming.id] = existing
                continue

        new_events = [
            event for event in unique_events.values() if event.id not in existing_by_id
        ]
        session_events: dict[UUID, SecurityEventSchema] = {}
        for incoming in sorted(
            new_events, key=lambda event: (event.attack_session_id, event.observed_at)
        ):
            session_events.setdefault(incoming.attack_session_id, incoming)

        for incoming in session_events.values():
            await self.session.execute(
                insert(AttackSession)
                .values(
                    id=incoming.attack_session_id,
                    trap_id=trap.id,
                    source_ip=incoming.source_ip,
                    started_at=incoming.observed_at,
                    protocol=incoming.target_service or "unknown",
                    session_metadata={},
                )
                .on_conflict_do_nothing(index_elements=[AttackSession.id])
            )

        attack_sessions = list(
            await self.session.scalars(
                select(AttackSession)
                .where(AttackSession.id.in_(session_events))
                .order_by(AttackSession.id)
                .with_for_update()
            )
        )
        attack_sessions_by_id = {item.id: item for item in attack_sessions}
        if any(item.trap_id != trap.id for item in attack_sessions):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Attack Session belongs to another Trap",
            )

        for incoming in new_events:
            attack_session = attack_sessions_by_id.get(incoming.attack_session_id)
            if attack_session is None:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Attack Session could not be created",
                )
            if incoming.event_type == "connection_closed":
                attack_session.ended_at = max(
                    filter(None, (attack_session.ended_at, incoming.observed_at))
                )

            result = await self.session.execute(
                insert(SecurityEvent)
                .values(
                    id=incoming.id,
                    schema_version=incoming.schema_version,
                    trap_id=trap.id,
                    attack_session_id=incoming.attack_session_id,
                    event_type=incoming.event_type,
                    observed_at=incoming.observed_at,
                    received_at=received_at,
                    source_ip=incoming.source_ip,
                    source_port=incoming.source_port,
                    target_service=incoming.target_service,
                    target_port=incoming.target_port,
                    payload=incoming.payload,
                )
                .on_conflict_do_nothing(index_elements=[SecurityEvent.id])
                .returning(SecurityEvent.id)
            )
            if result.scalar_one_or_none() is None:
                owner = await self.session.scalar(
                    select(SecurityEvent.trap_id).where(SecurityEvent.id == incoming.id)
                )
                if owner != trap.id:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                        detail="Security Event belongs to another Trap",
                    )
        return [incoming.id for incoming in events]

    @staticmethod
    def _same_event(
        existing: SecurityEvent, incoming: SecurityEventSchema, trap_id: UUID
    ) -> bool:
        return (
            existing.trap_id == trap_id
            and existing.schema_version == incoming.schema_version
            and existing.attack_session_id == incoming.attack_session_id
            and existing.event_type == incoming.event_type
            and existing.observed_at == incoming.observed_at
            and str(existing.source_ip) == str(incoming.source_ip)
            and existing.source_port == incoming.source_port
            and existing.target_service == incoming.target_service
            and existing.target_port == incoming.target_port
            and existing.payload == incoming.payload
        )
