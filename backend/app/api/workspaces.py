"""Workspace management: CRUD, members, per-workspace policy and audit."""

from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..authz import Principal, Role, WorkspaceContext, current_principal, get_membership, require_workspace
from ..db import get_session
from ..orm import AuditLog, User, Workspace, WorkspaceMember
from ..schemas import (
    AuditEntryOut,
    AuditList,
    MemberAddIn,
    MemberList,
    MemberOut,
    MemberRoleIn,
    WorkspaceCreateIn,
    WorkspaceOut,
    WorkspaceUpdateIn,
)
from ..settings import get_settings
from .auth import _workspace_out

router = APIRouter(tags=["workspaces"])


async def _visible_workspaces(session: AsyncSession, principal: Principal):
    if principal.is_global_admin:
        rows = (await session.execute(select(Workspace).order_by(Workspace.name))).scalars().all()
        return [(w, "admin") for w in rows]
    q = (
        await session.execute(
            select(Workspace, WorkspaceMember)
            .join(WorkspaceMember, WorkspaceMember.workspace_id == Workspace.id)
            .where(WorkspaceMember.user_id == principal.user.id)
            .order_by(Workspace.name)
        )
    ).all()
    return [(w, m.role) for (w, m) in q]


@router.get("/workspaces", response_model=list[WorkspaceOut])
async def list_workspaces(
    principal: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)
) -> list[WorkspaceOut]:
    return [_workspace_out(w, role) for (w, role) in await _visible_workspaces(session, principal)]


@router.post("/workspaces", response_model=WorkspaceOut, status_code=201)
async def create_workspace(
    payload: WorkspaceCreateIn,
    principal: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> WorkspaceOut:
    settings = get_settings()
    ws = Workspace(
        name=payload.name,
        kind="shared",
        owner_user_id=principal.user.id or None,
        allow_private_targets=False,
        max_concurrent_runs=min(2, settings.max_concurrent_runs),
    )
    session.add(ws)
    await session.flush()
    if principal.user.id:
        session.add(WorkspaceMember(workspace_id=ws.id, user_id=principal.user.id, role="admin"))
    await audit.record(
        session, "workspace.create", user=principal.user, workspace_id=ws.id, target=payload.name, commit=False
    )
    await session.commit()
    return _workspace_out(ws, "admin")


@router.get("/workspaces/{workspace_id}", response_model=WorkspaceOut)
async def get_workspace(ctx: WorkspaceContext = Depends(require_workspace(Role.viewer))) -> WorkspaceOut:
    return _workspace_out(ctx.workspace, ctx.role.name)


@router.patch("/workspaces/{workspace_id}", response_model=WorkspaceOut)
async def update_workspace(
    payload: WorkspaceUpdateIn,
    ctx: WorkspaceContext = Depends(require_workspace(Role.admin)),
    session: AsyncSession = Depends(get_session),
) -> WorkspaceOut:
    settings = get_settings()
    ws = ctx.workspace
    if payload.name is not None:
        ws.name = payload.name
    if payload.run_visibility is not None:
        ws.run_visibility = payload.run_visibility
    if payload.allow_private_targets is not None:
        # The deployment-wide setting is a hard ceiling.
        if payload.allow_private_targets and not settings.allow_private_targets:
            raise HTTPException(
                status_code=400,
                detail="Private/loopback targets are disabled for this deployment (OCSPWEB_ALLOW_PRIVATE_TARGETS)",
            )
        ws.allow_private_targets = payload.allow_private_targets
    if payload.max_concurrent_runs is not None:
        if payload.max_concurrent_runs > settings.max_concurrent_runs:
            raise HTTPException(
                status_code=400,
                detail=f"max_concurrent_runs cannot exceed the deployment ceiling of {settings.max_concurrent_runs}",
            )
        ws.max_concurrent_runs = payload.max_concurrent_runs
    if payload.oidc_group_admin is not None:
        ws.oidc_group_admin = payload.oidc_group_admin or None
    if payload.oidc_group is not None:
        ws.oidc_group = payload.oidc_group or None
    if payload.oidc_group_viewer is not None:
        ws.oidc_group_viewer = payload.oidc_group_viewer or None
    await audit.record(
        session, "workspace.update", user=ctx.principal.user, workspace_id=ws.id,
        target=ws.name, detail=payload.model_dump(exclude_none=True), commit=False,
    )
    await session.commit()
    return _workspace_out(ws, ctx.role.name)


@router.delete("/workspaces/{workspace_id}", status_code=204)
async def delete_workspace(
    ctx: WorkspaceContext = Depends(require_workspace(Role.admin)),
    session: AsyncSession = Depends(get_session),
) -> Response:
    if ctx.workspace.kind == "personal":
        raise HTTPException(status_code=400, detail="Personal workspaces cannot be deleted")
    await audit.record(
        session, "workspace.delete", user=ctx.principal.user, workspace_id=ctx.workspace.id,
        target=ctx.workspace.name, commit=False,
    )
    await session.delete(ctx.workspace)
    await session.commit()
    return Response(status_code=204)


# ---- members --------------------------------------------------------------


@router.get("/workspaces/{workspace_id}/members", response_model=MemberList)
async def list_members(
    ctx: WorkspaceContext = Depends(require_workspace(Role.viewer)),
    session: AsyncSession = Depends(get_session),
) -> MemberList:
    rows = (
        await session.execute(
            select(WorkspaceMember, User)
            .join(User, User.id == WorkspaceMember.user_id)
            .where(WorkspaceMember.workspace_id == ctx.workspace.id)
        )
    ).all()
    return MemberList(
        items=[
            MemberOut(
                user_id=u.id, role=m.role, email=u.email, display_name=u.display_name,
                provider=u.provider, source=m.source or "manual",
            )
            for (m, u) in rows
        ]
    )


@router.post("/workspaces/{workspace_id}/members", response_model=MemberOut, status_code=201)
async def add_member(
    payload: MemberAddIn,
    ctx: WorkspaceContext = Depends(require_workspace(Role.admin)),
    session: AsyncSession = Depends(get_session),
) -> MemberOut:
    if payload.user_id is None and not payload.email:
        raise HTTPException(status_code=400, detail="Provide user_id or email")
    if payload.user_id is not None:
        user = await session.get(User, payload.user_id)
    else:
        user = (
            await session.execute(select(User).where(User.email == payload.email))
        ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found (they must have logged in at least once)")
    if await get_membership(session, user.id, ctx.workspace.id) is not None:
        raise HTTPException(status_code=409, detail="User is already a member")
    Role.parse(payload.role)  # validate
    # Explicitly manual: an admin added this person, so OIDC group sync must
    # never revoke or override it.
    session.add(
        WorkspaceMember(
            workspace_id=ctx.workspace.id, user_id=user.id, role=payload.role, source="manual"
        )
    )
    await audit.record(
        session, "member.add", user=ctx.principal.user, workspace_id=ctx.workspace.id,
        target=user.email or user.subject, detail={"role": payload.role}, commit=False,
    )
    await session.commit()
    return MemberOut(user_id=user.id, role=payload.role, email=user.email, display_name=user.display_name, provider=user.provider)


@router.patch("/workspaces/{workspace_id}/members/{user_id}", response_model=MemberOut)
async def change_member_role(
    user_id: int,
    payload: MemberRoleIn,
    ctx: WorkspaceContext = Depends(require_workspace(Role.admin)),
    session: AsyncSession = Depends(get_session),
) -> MemberOut:
    member = await get_membership(session, user_id, ctx.workspace.id)
    if member is None:
        raise HTTPException(status_code=404, detail="Not a member")
    await _guard_last_admin(session, ctx.workspace.id, user_id, new_role=payload.role)
    member.role = payload.role
    # A hand-set role pins the membership: from now on it's authoritative and
    # OIDC group sync leaves it alone.
    member.source = "manual"
    user = await session.get(User, user_id)
    await audit.record(
        session, "member.role", user=ctx.principal.user, workspace_id=ctx.workspace.id,
        target=(user.email if user else str(user_id)), detail={"role": payload.role}, commit=False,
    )
    await session.commit()
    return MemberOut(user_id=user_id, role=payload.role, email=user.email if user else None, display_name=user.display_name if user else None, provider=user.provider if user else None)


@router.delete("/workspaces/{workspace_id}/members/{user_id}", status_code=204)
async def remove_member(
    user_id: int,
    ctx: WorkspaceContext = Depends(require_workspace(Role.admin)),
    session: AsyncSession = Depends(get_session),
) -> Response:
    member = await get_membership(session, user_id, ctx.workspace.id)
    if member is None:
        raise HTTPException(status_code=404, detail="Not a member")
    await _guard_last_admin(session, ctx.workspace.id, user_id, new_role=None)
    await session.delete(member)
    await audit.record(
        session, "member.remove", user=ctx.principal.user, workspace_id=ctx.workspace.id,
        target=str(user_id), commit=False,
    )
    await session.commit()
    return Response(status_code=204)


async def _guard_last_admin(session: AsyncSession, workspace_id: int, user_id: int, new_role: Optional[str]) -> None:
    """Prevent removing/demoting the last admin of a workspace."""
    if new_role == "admin":
        return
    admins = (
        await session.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.role == "admin"
            )
        )
    ).scalars().all()
    if len(admins) <= 1 and any(a.user_id == user_id for a in admins):
        raise HTTPException(status_code=400, detail="A workspace must keep at least one admin")


# ---- per-workspace audit --------------------------------------------------


@router.get("/workspaces/{workspace_id}/audit", response_model=AuditList)
async def workspace_audit(
    ctx: WorkspaceContext = Depends(require_workspace(Role.admin)),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
) -> AuditList:
    rows = (
        await session.execute(
            select(AuditLog)
            .where(AuditLog.workspace_id == ctx.workspace.id)
            .order_by(AuditLog.ts.desc())
            .limit(limit)
        )
    ).scalars().all()
    return AuditList(items=[_audit_out(r) for r in rows], total=len(rows))


def _audit_out(r: AuditLog) -> AuditEntryOut:
    try:
        detail = json.loads(r.detail_json or "{}")
    except ValueError:
        detail = {}
    return AuditEntryOut(
        id=r.id, ts=r.ts, actor=r.actor, event=r.event, workspace_id=r.workspace_id, target=r.target, detail=detail
    )
