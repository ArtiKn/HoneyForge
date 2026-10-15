import asyncio
import hashlib
import hmac
import logging
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select, update
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from center.api.models import AuditEntry, Trap

logger = logging.getLogger(__name__)


class TrapAccess:
    """Own credential and health transitions for one Trap fleet."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        enrollment_minutes: int = 10,
        overlap_minutes: int = 5,
        health_timeout_seconds: int = 90,
        now: datetime | None = None,
    ) -> None:
        self.session = session
        self.enrollment_lifetime = timedelta(minutes=enrollment_minutes)
        self.overlap_lifetime = timedelta(minutes=overlap_minutes)
        self.health_timeout = timedelta(seconds=health_timeout_seconds)
        self._fixed_now = now is not None
        self.now = now or datetime.now(UTC)

    async def issue(self, trap: Trap) -> str:
        await self.session.flush()
        token = self._credential(trap.id)
        trap.enrollment_token_hash = self._hash(token)
        trap.enrollment_token_expires_at = self.now + self.enrollment_lifetime
        trap.enrollment_token_used_at = None
        return token

    async def enroll(self, token: str, source_ip: str | None) -> tuple[Trap, str] | None:
        trap = await self._trap_from_credential(token, lock=True)
        if not self._fixed_now:
            self.now = datetime.now(UTC)
        valid = (
            trap is not None
            and trap.status == "provisioning"
            and trap.enrollment_token_used_at is None
            and trap.enrollment_token_expires_at is not None
            and trap.enrollment_token_expires_at > self.now
            and self._matches(token, trap.enrollment_token_hash)
        )
        if not valid or trap is None:
            return None
        secret = self._credential(trap.id)
        trap.current_secret_hash = self._hash(secret)
        trap.enrollment_token_used_at = self.now
        trap.enrollment_token_hash = None
        trap.status = "online"
        trap.last_seen_at = self.now
        self._audit(trap, "trap.enrolled", source_ip)
        return trap, secret

    async def authenticate(self, secret: str) -> Trap | None:
        trap = await self._trap_from_credential(secret, lock=True)
        if not self._fixed_now:
            self.now = datetime.now(UTC)
        if trap is None or trap.status == "revoked":
            return None
        current = self._matches(secret, trap.current_secret_hash)
        previous = (
            trap.previous_secret_valid_until is not None
            and trap.previous_secret_valid_until > self.now
            and self._matches(secret, trap.previous_secret_hash)
        )
        return trap if current or previous else None

    async def rotate(self, trap: Trap, source_ip: str | None) -> str:
        if (
            trap.previous_secret_valid_until is not None
            and trap.previous_secret_valid_until > self.now
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Secret rotation overlap is still active",
            )
        secret = self._credential(trap.id)
        trap.previous_secret_hash = trap.current_secret_hash
        trap.previous_secret_valid_until = self.now + self.overlap_lifetime
        trap.current_secret_hash = self._hash(secret)
        self._audit(trap, "trap.secret.rotated", source_ip)
        return secret

    def revoke(self, trap: Trap, operator_id: UUID, source_ip: str | None) -> None:
        trap.status = "revoked"
        trap.enrollment_token_hash = None
        trap.current_secret_hash = None
        trap.previous_secret_hash = None
        trap.previous_secret_valid_until = None
        self._audit(trap, "trap.revoked", source_ip, operator_id)

    def set_enabled(
        self, trap: Trap, enabled: bool, operator_id: UUID, source_ip: str | None
    ) -> bool:
        """Apply the operator's desired state; return whether it changed."""

        if trap.enabled == enabled:
            return False
        trap.enabled = enabled
        self._audit(
            trap,
            "trap.started" if enabled else "trap.stopped",
            source_ip,
            operator_id,
        )
        return True

    def archive(self, trap: Trap, operator_id: UUID, source_ip: str | None) -> bool:
        """Soft-archive a Trap and stop its services; return whether it changed."""

        if trap.is_archived:
            return False
        trap.is_archived = True
        trap.enabled = False
        trap.enrollment_token_hash = None
        trap.enrollment_token_expires_at = None
        self._audit(trap, "trap.archived", source_ip, operator_id)
        return True

    def report_health(
        self,
        trap: Trap,
        *,
        agent_version: str,
        active_profile_version: int,
        buffer_depth: int,
        configuration_errors: list[str],
        buffer_loss: dict[str, object] | None = None,
        enabled: bool | None = None,
    ) -> None:
        trap.last_seen_at = self.now
        trap.agent_version = agent_version
        agent_meta = {
            "active_profile_version": active_profile_version,
            "buffer_depth": buffer_depth,
            "configuration_errors": configuration_errors,
        }
        if enabled is not None:
            agent_meta["enabled_applied"] = enabled
        if buffer_loss is not None:
            agent_meta["buffer_loss"] = buffer_loss
        elif "buffer_loss" in trap.agent_meta:
            agent_meta["buffer_loss"] = trap.agent_meta["buffer_loss"]
        trap.agent_meta = agent_meta
        trap.status = "degraded" if configuration_errors else "online"

    async def mark_offline(self) -> int:
        result = await self.session.execute(
            update(Trap)
            .where(
                Trap.status.in_(("online", "degraded")),
                Trap.last_seen_at < self.now - self.health_timeout,
            )
            .values(status="offline")
        )
        return result.rowcount

    async def _trap_from_credential(
        self, credential: str, *, lock: bool = False
    ) -> Trap | None:
        try:
            trap_id = UUID(credential.split(".", 1)[0])
        except (ValueError, IndexError):
            return None
        statement = select(Trap).where(Trap.id == trap_id)
        if lock:
            statement = statement.with_for_update()
        return await self.session.scalar(statement)

    def _audit(
        self,
        trap: Trap,
        action: str,
        source_ip: str | None,
        operator_id: UUID | None = None,
    ) -> None:
        self.session.add(
            AuditEntry(
                operator_id=operator_id,
                action=action,
                entity="trap",
                entity_id=trap.id,
                details={},
                source_ip=source_ip,
            )
        )

    @staticmethod
    def _credential(trap_id: UUID) -> str:
        return f"{trap_id}.{secrets.token_urlsafe(32)}"

    @staticmethod
    def _hash(credential: str) -> str:
        return hashlib.sha256(credential.encode()).hexdigest()

    @classmethod
    def _matches(cls, credential: str, expected: str | None) -> bool:
        return expected is not None and hmac.compare_digest(
            cls._hash(credential), expected
        )


async def monitor_offline_traps(
    session_factory: Callable[[], AsyncSession],
    *,
    health_timeout_seconds: int,
    sweep_interval_seconds: int,
) -> None:
    """Continuously reconcile silent Agents into the offline state."""

    while True:
        await asyncio.sleep(sweep_interval_seconds)
        try:
            async with session_factory() as session:
                await TrapAccess(
                    session, health_timeout_seconds=health_timeout_seconds
                ).mark_offline()
                await session.commit()
        except Exception:
            logger.exception("Trap health sweep failed")
