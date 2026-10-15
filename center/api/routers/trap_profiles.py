from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from center.api.auth_dependencies import AdminOperator
from center.api.database import get_db
from center.api.models import AuditEntry, Trap, TrapProfile
from center.api.schemas.trap_profile import (
    TrapProfileCreate,
    TrapProfileRead,
    TrapProfileUpdate,
)

router = APIRouter()


@router.get("/ping")
async def ping() -> dict[str, str]:
    return {"status": "ok"}


@router.post(
    "",
    response_model=TrapProfileRead,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
)
async def create_trap_profile(
    payload: TrapProfileCreate,
    operator: AdminOperator,
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> TrapProfile:
    trap_profile = TrapProfile(
        name=payload.name,
        interaction_level=payload.interaction_level,
        services=[service.model_dump(exclude_none=True) for service in payload.services],
        banners={},
        config={},
        decoy_credentials=[
            credential.model_dump(exclude_none=True)
            for credential in payload.decoy_credentials
        ],
        logging=payload.logging.model_dump(),
        masking=payload.masking.model_dump(exclude_none=True),
        version=1,
        is_archived=False,
    )
    session.add(trap_profile)
    await session.flush()
    session.add(
        AuditEntry(
            operator_id=operator.id,
            action="trap_profile.created",
            entity="trap_profile",
            entity_id=trap_profile.id,
            details={"version": trap_profile.version},
            source_ip=request.client.host if request.client else None,
        )
    )
    response.headers["ETag"] = f'"{trap_profile.version}"'
    return trap_profile


@router.get("", response_model=list[TrapProfileRead], response_model_exclude_none=True)
async def list_trap_profiles(
    session: Annotated[AsyncSession, Depends(get_db)],
) -> list[TrapProfile]:
    return list(
        await session.scalars(select(TrapProfile).order_by(TrapProfile.name))
    )


@router.get(
    "/{trap_profile_id}",
    response_model=TrapProfileRead,
    response_model_exclude_none=True,
)
async def read_trap_profile(
    trap_profile_id: UUID,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> TrapProfile:
    trap_profile = await session.get(TrapProfile, trap_profile_id)
    if trap_profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    response.headers["ETag"] = f'"{trap_profile.version}"'
    return trap_profile


@router.put(
    "/{trap_profile_id}",
    response_model=TrapProfileRead,
    response_model_exclude_none=True,
)
async def update_trap_profile(
    trap_profile_id: UUID,
    payload: TrapProfileUpdate,
    operator: AdminOperator,
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db)],
    if_match: Annotated[str | None, Header()] = None,
) -> TrapProfile:
    expected_version = _parse_etag(if_match)
    result = await session.execute(
        update(TrapProfile)
        .where(
            TrapProfile.id == trap_profile_id,
            TrapProfile.version == expected_version,
            TrapProfile.is_archived.is_(False),
        )
        .values(
            name=payload.name,
            interaction_level=payload.interaction_level,
            services=[
                service.model_dump(exclude_none=True) for service in payload.services
            ],
            decoy_credentials=[
                credential.model_dump(exclude_none=True)
                for credential in payload.decoy_credentials
            ],
            logging=payload.logging.model_dump(),
            masking=payload.masking.model_dump(exclude_none=True),
            version=TrapProfile.version + 1,
        )
        .returning(TrapProfile)
    )
    trap_profile = result.scalar_one_or_none()
    if trap_profile is None:
        if await session.get(TrapProfile, trap_profile_id) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Trap Profile changed; reload it before editing",
        )
    session.add(
        AuditEntry(
            operator_id=operator.id,
            action="trap_profile.updated",
            entity="trap_profile",
            entity_id=trap_profile.id,
            details={"version": trap_profile.version},
            source_ip=request.client.host if request.client else None,
        )
    )
    response.headers["ETag"] = f'"{trap_profile.version}"'
    return trap_profile


def _parse_etag(value: str | None) -> int:
    if value is None:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail="If-Match is required",
        )
    try:
        version = int(value.removeprefix('W/').strip('"'))
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="If-Match must contain a profile version",
        ) from error
    if version < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="If-Match must contain a profile version",
        )
    return version


@router.delete("/{trap_profile_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_or_archive_trap_profile(
    trap_profile_id: UUID,
    operator: AdminOperator,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
    if_match: Annotated[str | None, Header()] = None,
) -> None:
    expected_version = _parse_etag(if_match)
    trap_profile = await session.scalar(
        select(TrapProfile)
        .where(TrapProfile.id == trap_profile_id)
        .with_for_update()
    )
    if trap_profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if trap_profile.version != expected_version:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Trap Profile changed; reload it before editing",
        )
    if trap_profile.is_archived:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Archived Trap Profiles cannot be changed",
        )

    has_assignment = (
        await session.scalar(
            select(Trap.id).where(Trap.trap_profile_id == trap_profile_id).limit(1)
        )
        is not None
    )
    if has_assignment:
        trap_profile.is_archived = True
        trap_profile.version += 1
        action = "trap_profile.archived"
        details = {"version": trap_profile.version}
    else:
        action = "trap_profile.deleted"
        details = {"version": trap_profile.version}
        await session.delete(trap_profile)

    session.add(
        AuditEntry(
            operator_id=operator.id,
            action=action,
            entity="trap_profile",
            entity_id=trap_profile_id,
            details=details,
            source_ip=request.client.host if request.client else None,
        )
    )

