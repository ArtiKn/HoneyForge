from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from center.api.auth_dependencies import CurrentOperator, SESSION_COOKIE
from center.api.database import get_db
from center.api.models import AuditEntry
from center.api.operator_auth import authenticate, create_session_token
from center.api.schemas.auth import LoginRequest

router = APIRouter()


@router.get("/ping")
async def ping() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/login", status_code=status.HTTP_204_NO_CONTENT)
async def login(
    credentials: LoginRequest,
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    operator = await authenticate(
        session,
        credentials.username,
        credentials.password,
        request.client.host if request.client else None,
    )
    if operator is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    settings = request.app.state.settings
    lifetime_seconds = settings.access_token_expire_minutes * 60
    response.set_cookie(
        SESSION_COOKIE,
        create_session_token(operator, settings.jwt_secret, lifetime_seconds),
        max_age=lifetime_seconds,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    operator: CurrentOperator,
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    operator.session_version += 1
    session.add(
        AuditEntry(
            operator_id=operator.id,
            action="operator.logout",
            entity="operator",
            entity_id=operator.id,
            details={},
            source_ip=request.client.host if request.client else None,
        )
    )
    response.delete_cookie(
        SESSION_COOKIE,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )

