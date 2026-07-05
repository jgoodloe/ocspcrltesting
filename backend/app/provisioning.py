"""User / workspace provisioning shared by auth flows and startup."""

from __future__ import annotations

import logging
from typing import List, Optional

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .orm import CACertificate, Profile, Run, User, Workspace, WorkspaceMember, utcnow
from .security import hash_password
from .settings import Settings

logger = logging.getLogger("ocspweb.provisioning")


async def ensure_personal_workspace(session: AsyncSession, user: User) -> Workspace:
    """Return the user's personal workspace, creating it (with an admin
    membership) on first need."""
    existing = (
        await session.execute(
            select(Workspace).where(
                Workspace.owner_user_id == user.id, Workspace.kind == "personal"
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    name = (user.display_name or user.email or user.subject or "Personal").strip()
    ws = Workspace(
        name=f"{name}'s workspace" if not name.endswith("workspace") else name,
        kind="personal",
        owner_user_id=user.id,
    )
    session.add(ws)
    await session.flush()
    session.add(WorkspaceMember(workspace_id=ws.id, user_id=user.id, role="admin"))
    await session.flush()
    return ws


async def get_or_create_oidc_user(
    session: AsyncSession,
    subject: str,
    email: Optional[str],
    display_name: Optional[str],
) -> User:
    """Match on the OIDC ``sub`` (never email), provisioning on first login."""
    user = (
        await session.execute(
            select(User).where(User.provider == "oidc", User.subject == subject)
        )
    ).scalar_one_or_none()
    if user is None:
        user = User(
            provider="oidc",
            subject=subject,
            email=email,
            display_name=display_name or email or subject,
            is_active=True,
        )
        session.add(user)
        await session.flush()
        await ensure_personal_workspace(session, user)
        logger.info("provisioned OIDC user sub=%s", subject)
    else:
        # Refresh display fields (email is display-only and mutable).
        if email:
            user.email = email
        if display_name:
            user.display_name = display_name
    user.last_login_at = utcnow()
    await session.commit()
    return user


def _entitled_role(ws: Workspace, groups: set[str]) -> Optional[str]:
    """The highest workspace role the user's IdP groups grant, or None."""
    if ws.oidc_group_admin and ws.oidc_group_admin in groups:
        return "admin"
    if ws.oidc_group and ws.oidc_group in groups:
        return "member"
    if ws.oidc_group_viewer and ws.oidc_group_viewer in groups:
        return "viewer"
    return None


async def sync_oidc_group_memberships(session: AsyncSession, user: User, groups: List[str]) -> None:
    """Reconcile the user's group-driven workspace memberships from the IdP.

    Authoritative for the memberships it owns (``source == "oidc"``): a matching
    group grants/updates the mapped role, and losing every matching group in a
    workspace revokes that membership. Memberships an admin set by hand
    (``source == "manual"``) are never touched — neither upgraded, downgraded,
    nor removed — so manual grants always win.
    """
    group_set = {g for g in groups if g}
    # Every workspace that maps at least one group to a role is a candidate,
    # even when the user matches none of them (that's how revocation happens).
    workspaces = (
        await session.execute(
            select(Workspace).where(
                or_(
                    Workspace.oidc_group_admin.is_not(None),
                    Workspace.oidc_group.is_not(None),
                    Workspace.oidc_group_viewer.is_not(None),
                )
            )
        )
    ).scalars().all()

    changed = False
    for ws in workspaces:
        member = (
            await session.execute(
                select(WorkspaceMember).where(
                    WorkspaceMember.workspace_id == ws.id, WorkspaceMember.user_id == user.id
                )
            )
        ).scalar_one_or_none()
        # Respect anything an admin set by hand; only manage our own rows.
        if member is not None and (member.source or "manual") != "oidc":
            continue

        role = _entitled_role(ws, group_set)
        if role is not None:
            if member is None:
                session.add(
                    WorkspaceMember(
                        workspace_id=ws.id, user_id=user.id, role=role, source="oidc"
                    )
                )
                changed = True
            elif member.role != role:
                member.role = role
                changed = True
        elif member is not None:
            # No matching group any more -> drop the group-managed membership.
            await session.delete(member)
            changed = True

    if changed:
        await session.commit()


async def ensure_bootstrap_admin(session: AsyncSession, settings: Settings) -> None:
    """Ensure the break-glass local global-admin exists when configured. Only
    creates the account (or resets its password if it exists); never demotes."""
    if not settings.bootstrap_admin_password:
        return
    username = settings.bootstrap_admin_username
    user = (
        await session.execute(
            select(User).where(User.provider == "local", User.subject == username)
        )
    ).scalar_one_or_none()
    if user is None:
        user = User(
            provider="local",
            subject=username,
            display_name=username,
            password_hash=hash_password(settings.bootstrap_admin_password),
            is_global_admin=True,
            is_active=True,
        )
        session.add(user)
        await session.flush()
        await ensure_personal_workspace(session, user)
        await session.commit()
        logger.info("created break-glass admin %r", username)
    else:
        # Keep the break-glass password in sync with the env so the operator
        # can always recover access; ensure admin + active.
        user.password_hash = hash_password(settings.bootstrap_admin_password)
        user.is_global_admin = True
        user.is_active = True
        await session.commit()


async def user_count(session: AsyncSession) -> int:
    return int((await session.execute(select(func.count(User.id)))).scalar_one())


DEFAULT_WORKSPACE_NAME = "Default"


async def ensure_default_workspace(session: AsyncSession) -> Workspace:
    """A singleton shared workspace used in open (no-auth) mode and as the
    home for data migrated from before multi-user support."""
    ws = (
        await session.execute(
            select(Workspace).where(Workspace.kind == "shared", Workspace.name == DEFAULT_WORKSPACE_NAME)
        )
    ).scalars().first()
    if ws is None:
        ws = Workspace(name=DEFAULT_WORKSPACE_NAME, kind="shared", run_visibility="all")
        session.add(ws)
        await session.flush()
    return ws


async def backfill_default_workspace(session: AsyncSession, workspace_id: int) -> int:
    """Assign any pre-multi-user rows (runs/profiles/CA certs with NULL
    ``workspace_id``) to the default workspace. Returns the number of rows
    touched. Idempotent."""
    touched = 0
    for model in (Run, Profile, CACertificate):
        result = await session.execute(
            update(model)
            .where(model.workspace_id.is_(None))
            .values(workspace_id=workspace_id)
        )
        touched += int(result.rowcount or 0)
    if touched:
        await session.commit()
        logger.info("backfilled %d legacy rows into the default workspace", touched)
    return touched


async def backfill_member_source(session: AsyncSession) -> None:
    """Mark memberships that predate the ``source`` column as ``manual`` so the
    authoritative OIDC group sync never mistakes them for group-managed rows and
    revokes them. Idempotent."""
    result = await session.execute(
        update(WorkspaceMember)
        .where(WorkspaceMember.source.is_(None))
        .values(source="manual")
    )
    if result.rowcount:
        await session.commit()


async def run_startup_provisioning(session: AsyncSession, settings: Settings) -> None:
    """Idempotent boot-time setup: break-glass admin, default workspace, and a
    one-time backfill of legacy data into it."""
    await ensure_bootstrap_admin(session, settings)
    default_ws = await ensure_default_workspace(session)
    await session.commit()
    await backfill_default_workspace(session, default_ws.id)
    await backfill_member_source(session)
