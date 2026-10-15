from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from center.api.database import get_db
from center.api.models import AuditEntry, Operator
from center.api.operator_auth import ROLE_ADMIN, operator_for_session

SESSION_COOKIE = "honeyforge_session"
FORBIDDEN_ACTION = "operator.access.denied"


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


async def require_admin(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
    operator: Annotated[Operator, Depends(require_operator)],
) -> Operator:
    """Allow only Operators whose role holds full access.

    A denied attempt is preserved in the audit trail before the request is
    rejected, so a read-only Operator cannot probe mutations unnoticed.
    """

    if operator.role == ROLE_ADMIN:
        return operator
    session.add(
        AuditEntry(
            operator_id=operator.id,
            action=FORBIDDEN_ACTION,
            entity="operator",
            entity_id=operator.id,
            details={"method": request.method, "path": request.url.path},
            source_ip=request.client.host if request.client else None,
        )
    )
    await session.commit()
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Operator role cannot perform this action",
    )


CurrentOperator = Annotated[Operator, Depends(require_operator)]
AdminOperator = Annotated[Operator, Depends(require_admin)]
