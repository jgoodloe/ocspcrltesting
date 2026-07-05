"""Global-admin endpoints: user management and the full audit log."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..authz import Principal, current_principal
from ..db import get_session
from ..orm import AuditLog, User
from ..provisioning import ensure_personal_workspace
from ..schemas import AuditEntryOut, AuditList, LocalUserCreateIn, UserOut
from ..security import hash_password
from .auth import _user_out

router = APIRouter(tags=["admin"])


async def require_global_admin(principal: Principal = Depends(current_principal)) -> Principal:
    if not principal.is_global_admin:
        raise HTTPException(status_code=403, detail="Global admin required")
    return principal


@router.get("/admin/users", response_model=list[UserOut])
async def list_users(
    _: Principal = Depends(require_global_admin), session: AsyncSession = Depends(get_session)
) -> list[UserOut]:
    rows = (await session.execute(select(User).order_by(User.id))).scalars().all()
    return [_user_out(u) for u in rows]


@router.post("/admin/users", response_model=UserOut, status_code=201)
async def create_local_user(
    payload: LocalUserCreateIn,
    principal: Principal = Depends(require_global_admin),
    session: AsyncSession = Depends(get_session),
) -> UserOut:
    existing = (
        await session.execute(
            select(User).where(User.provider == "local", User.subject == payload.username)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="A local user with that username already exists")
    user = User(
        provider="local",
        subject=payload.username,
        display_name=payload.display_name or payload.username,
        password_hash=hash_password(payload.password),
        is_global_admin=payload.is_global_admin,
        is_active=True,
    )
    session.add(user)
    await session.flush()
    await ensure_personal_workspace(session, user)
    await audit.record(
        session, "user.create", user=principal.user, target=payload.username,
        detail={"provider": "local", "global_admin": payload.is_global_admin}, commit=False,
    )
    await session.commit()
    return _user_out(user)


@router.post("/admin/users/{user_id}/active", response_model=UserOut)
async def set_user_active(
    user_id: int,
    active: bool = Query(...),
    principal: Principal = Depends(require_global_admin),
    session: AsyncSession = Depends(get_session),
) -> UserOut:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not active and user.id == principal.user.id:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account")
    user.is_active = active
    await audit.record(
        session, "user.active", user=principal.user, target=user.subject, detail={"active": active}, commit=False
    )
    await session.commit()
    return _user_out(user)


@router.get("/admin/audit", response_model=AuditList)
async def global_audit(
    _: Principal = Depends(require_global_admin),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> AuditList:
    total = int((await session.execute(select(func.count(AuditLog.id)))).scalar_one())
    rows = (
        await session.execute(
            select(AuditLog).order_by(AuditLog.ts.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()
    items = []
    for r in rows:
        try:
            detail = json.loads(r.detail_json or "{}")
        except ValueError:
            detail = {}
        items.append(
            AuditEntryOut(id=r.id, ts=r.ts, actor=r.actor, event=r.event, workspace_id=r.workspace_id, target=r.target, detail=detail)
        )
    return AuditList(items=items, total=total)
