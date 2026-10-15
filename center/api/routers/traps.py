from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from center.api.auth_dependencies import CurrentOperator
from center.api.database import get_db
from center.api.models import AuditEntry, AttackSession, SecurityEvent, Trap, TrapProfile
from center.api.schemas.trap import (
    EnrollmentTokenResponse,
    TrapCreate,
    TrapProvisioned,
    TrapRead,
    TrapUpdate,
)
from center.api.trap_access import TrapAccess

router = APIRouter()


@router.get("/ping")
async def ping() -> dict[str, str]:
    return {"status": "ok"}


@router.post("", response_model=TrapProvisioned, status_code=status.HTTP_201_CREATED)
async def create_trap(
    payload: TrapCreate,
    operator: CurrentOperator,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> TrapProvisioned:
    profile = await session.get(TrapProfile, payload.trap_profile_id)
    if profile is None or profile.is_archived:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
    trap = Trap(**payload.model_dump(), status="provisioning", is_archived=False)
    session.add(trap)
    settings = request.app.state.settings
    enrollment_token = await TrapAccess(
        session, enrollment_minutes=settings.enrollment_token_minutes
    ).issue(trap)
    session.add(
        AuditEntry(
            operator_id=operator.id,
            action="trap.created",
            entity="trap",
            entity_id=trap.id,
            details={},
            source_ip=request.client.host if request.client else None,
        )
    )
    return TrapProvisioned(
        **TrapRead.model_validate(trap).model_dump(),
        enrollment_token=enrollment_token,
    )


@router.get("", response_model=list[TrapRead])
async def list_traps(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> list[Trap]:
    settings = request.app.state.settings
    await TrapAccess(
        session, health_timeout_seconds=settings.health_timeout_seconds
    ).mark_offline()
    return list(await session.scalars(select(Trap).order_by(Trap.name)))


@router.get("/{trap_id}", response_model=TrapRead)
async def read_trap(
    trap_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> Trap:
    trap = await session.get(Trap, trap_id)
    if trap is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return trap


@router.patch("/{trap_id}", response_model=TrapRead)
async def update_trap(
    trap_id: UUID,
    payload: TrapUpdate,
    operator: CurrentOperator,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> Trap:
    trap = await session.scalar(select(Trap).where(Trap.id == trap_id).with_for_update())
    if trap is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if trap.is_archived:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Archived Traps cannot be changed",
        )
    changes = payload.model_dump(exclude_unset=True)
    source_ip = request.client.host if request.client else None
    profile_change = _profile_change(trap, changes.pop("trap_profile_id", None))
    if profile_change is not None:
        profile = await session.get(TrapProfile, profile_change)
        if profile is None or profile.is_archived:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
        previous_profile_id = trap.trap_profile_id
        trap.trap_profile_id = profile_change
        session.add(
            AuditEntry(
                operator_id=operator.id,
                action="trap.profile_changed",
                entity="trap",
                entity_id=trap.id,
                details={
                    "from": str(previous_profile_id),
                    "to": str(profile_change),
                    "profile_version": profile.version,
                },
                source_ip=source_ip,
            )
        )
    changed_fields = sorted(field for field, value in changes.items() if getattr(trap, field) != value)
    for field, value in changes.items():
        setattr(trap, field, value)
    if changed_fields:
        session.add(
            AuditEntry(
                operator_id=operator.id,
                action="trap.updated",
                entity="trap",
                entity_id=trap.id,
                details={"fields": changed_fields},
                source_ip=source_ip,
            )
        )
    return trap


@router.post("/{trap_id}/start", response_model=TrapRead)
async def start_trap(
    trap_id: UUID,
    operator: CurrentOperator,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> Trap:
    trap = await _mutable_trap(session, trap_id)
    TrapAccess(session).set_enabled(
        trap, True, operator.id, request.client.host if request.client else None
    )
    return trap


@router.post("/{trap_id}/stop", response_model=TrapRead)
async def stop_trap(
    trap_id: UUID,
    operator: CurrentOperator,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> Trap:
    trap = await _mutable_trap(session, trap_id)
    TrapAccess(session).set_enabled(
        trap, False, operator.id, request.client.host if request.client else None
    )
    return trap


@router.post("/{trap_id}/archive", response_model=TrapRead)
async def archive_trap(
    trap_id: UUID,
    operator: CurrentOperator,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> Trap:
    trap = await session.scalar(select(Trap).where(Trap.id == trap_id).with_for_update())
    if trap is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    TrapAccess(session).archive(
        trap, operator.id, request.client.host if request.client else None
    )
    return trap


@router.delete("/{trap_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_or_archive_trap(
    trap_id: UUID,
    operator: CurrentOperator,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Delete an unused Trap; keep history by archiving a referenced one."""

    trap = await session.scalar(select(Trap).where(Trap.id == trap_id).with_for_update())
    if trap is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    source_ip = request.client.host if request.client else None
    if await _has_history(session, trap_id):
        TrapAccess(session).archive(trap, operator.id, source_ip)
        return
    await session.delete(trap)
    session.add(
        AuditEntry(
            operator_id=operator.id,
            action="trap.deleted",
            entity="trap",
            entity_id=trap_id,
            details={},
            source_ip=source_ip,
        )
    )


async def _mutable_trap(session: AsyncSession, trap_id: UUID) -> Trap:
    """Lock a Trap that a start/stop command may act on."""

    trap = await session.scalar(select(Trap).where(Trap.id == trap_id).with_for_update())
    if trap is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if trap.is_archived or trap.status == "revoked":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Archived or revoked Traps cannot be started or stopped",
        )
    return trap


async def _has_history(session: AsyncSession, trap_id: UUID) -> bool:
    """Whether a Trap owns Security Events or Attack Sessions."""

    event = await session.scalar(
        select(SecurityEvent.id).where(SecurityEvent.trap_id == trap_id).limit(1)
    )
    if event is not None:
        return True
    session_record = await session.scalar(
        select(AttackSession.id).where(AttackSession.trap_id == trap_id).limit(1)
    )
    return session_record is not None


def _profile_change(trap: Trap, requested: UUID | None) -> UUID | None:
    """Return a requested Trap Profile only when it actually changes."""

    if requested is None or requested == trap.trap_profile_id:
        return None
    return requested


@router.post("/{trap_id}/revoke", response_model=TrapRead)
async def revoke_trap(
    trap_id: UUID,
    operator: CurrentOperator,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> Trap:
    trap = await session.scalar(select(Trap).where(Trap.id == trap_id).with_for_update())
    if trap is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    TrapAccess(session).revoke(
        trap, operator.id, request.client.host if request.client else None
    )
    return trap


@router.post("/{trap_id}/enrollment-token", response_model=EnrollmentTokenResponse)
async def reissue_enrollment_token(
    trap_id: UUID,
    operator: CurrentOperator,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> EnrollmentTokenResponse:
    """Recover an interrupted provisioning flow without rotating an online Trap."""

    trap = await session.scalar(select(Trap).where(Trap.id == trap_id).with_for_update())
    if trap is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if trap.status != "provisioning":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Enrollment tokens can only be reissued for provisioning Traps",
        )
    token = await TrapAccess(
        session,
        enrollment_minutes=request.app.state.settings.enrollment_token_minutes,
    ).issue(trap)
    session.add(
        AuditEntry(
            operator_id=operator.id,
            action="trap.enrollment_token.reissued",
            entity="trap",
            entity_id=trap.id,
            details={},
            source_ip=request.client.host if request.client else None,
        )
    )
    return EnrollmentTokenResponse(enrollment_token=token)

