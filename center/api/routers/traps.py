from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from center.api.auth_dependencies import CurrentOperator
from center.api.database import get_db
from center.api.models import AuditEntry, Trap, TrapProfile
from center.api.schemas.trap import TrapCreate, TrapProvisioned, TrapRead
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

