from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from center.api.database import get_db
from center.api.models import Operator
from center.api.operator_auth import operator_for_session

SESSION_COOKIE = "honeyforge_session"


async def require_operator(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> Operator:
    settings = request.app.state.settings
    operator = await operator_for_session(session, session_token, settings.jwt_secret)
    if operator is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return operator


CurrentOperator = Annotated[Operator, Depends(require_operator)]
