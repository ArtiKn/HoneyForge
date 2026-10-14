from fastapi import APIRouter

from center.api.auth_dependencies import CurrentOperator

router = APIRouter()


@router.get("")
async def dashboard(operator: CurrentOperator) -> dict[str, str]:
    return {"operator": operator.username}
