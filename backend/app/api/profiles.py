from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..orm import Profile, utcnow
from ..schemas import ProfileIn, ProfileList, ProfileOut

router = APIRouter(tags=["profiles"])


def _to_out(profile: Profile) -> ProfileOut:
    return ProfileOut(
        id=profile.id,
        name=profile.name,
        description=profile.description,
        config=profile.config,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


async def _get_or_404(session: AsyncSession, profile_id: int) -> Profile:
    profile = await session.get(Profile, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


async def _check_name_free(session: AsyncSession, name: str, exclude_id: int | None = None) -> None:
    stmt = select(Profile).where(Profile.name == name)
    existing = (await session.execute(stmt)).scalar_one_or_none()
    if existing is not None and existing.id != exclude_id:
        raise HTTPException(status_code=409, detail=f"A profile named '{name}' already exists")


@router.get("/profiles", response_model=ProfileList)
async def list_profiles(session: AsyncSession = Depends(get_session)) -> ProfileList:
    rows = (await session.execute(select(Profile).order_by(Profile.name))).scalars().all()
    return ProfileList(items=[_to_out(p) for p in rows])


@router.post("/profiles", response_model=ProfileOut, status_code=201)
async def create_profile(payload: ProfileIn, session: AsyncSession = Depends(get_session)) -> ProfileOut:
    await _check_name_free(session, payload.name)
    profile = Profile(
        name=payload.name,
        description=payload.description,
        config_json=json.dumps(payload.config.model_dump(exclude={"profile_id"})),
    )
    session.add(profile)
    await session.commit()
    await session.refresh(profile)
    return _to_out(profile)


@router.put("/profiles/{profile_id}", response_model=ProfileOut)
async def update_profile(
    profile_id: int, payload: ProfileIn, session: AsyncSession = Depends(get_session)
) -> ProfileOut:
    profile = await _get_or_404(session, profile_id)
    await _check_name_free(session, payload.name, exclude_id=profile_id)
    profile.name = payload.name
    profile.description = payload.description
    profile.config_json = json.dumps(payload.config.model_dump(exclude={"profile_id"}))
    profile.updated_at = utcnow()
    await session.commit()
    await session.refresh(profile)
    return _to_out(profile)


@router.delete("/profiles/{profile_id}", status_code=204)
async def delete_profile(profile_id: int, session: AsyncSession = Depends(get_session)) -> Response:
    profile = await _get_or_404(session, profile_id)
    await session.delete(profile)
    await session.commit()
    return Response(status_code=204)
