from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from center.api.database import get_db
from center.api.schemas.trap import (
    AgentHealthReport,
    EnrollmentRequest,
    EnrollmentResponse,
    RotationResponse,
)
from center.api.trap_access import TrapAccess

router = APIRouter(prefix="/assets/v2", tags=["agent"])


@router.post("/enroll", response_model=EnrollmentResponse)
async def enroll(
    payload: EnrollmentRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> EnrollmentResponse:
    result = await TrapAccess(session).enroll(
        payload.enrollment_token, request.client.host if request.client else None
    )
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid enrollment credential",
        )
    trap, secret = result
    return EnrollmentResponse(trap_id=trap.id, trap_secret=secret)


@router.post("/health", status_code=status.HTTP_204_NO_CONTENT)
async def health(
    payload: AgentHealthReport,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    access = _access(request, session)
    trap = await access.authenticate(_bearer(authorization))
    if trap is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    access.report_health(trap, **payload.model_dump())


@router.post("/rotate", response_model=RotationResponse)
async def rotate(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
) -> RotationResponse:
    access = _access(request, session)
    trap = await access.authenticate(_bearer(authorization))
    if trap is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    secret = await access.rotate(trap, request.client.host if request.client else None)
    return RotationResponse(trap_secret=secret)


def _access(request: Request, session: AsyncSession) -> TrapAccess:
    settings = request.app.state.settings
    return TrapAccess(
        session,
        overlap_minutes=settings.trap_secret_overlap_minutes,
        health_timeout_seconds=settings.health_timeout_seconds,
    )


def _bearer(header: str | None) -> str:
    if header is None or not header.startswith("Bearer "):
        return ""
    return header.removeprefix("Bearer ")
