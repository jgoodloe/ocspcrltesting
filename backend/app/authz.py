"""Authorization: roles, the authenticated principal, and workspace access.

A single request is authenticated either by a signed session cookie or by a
Bearer API token. The resulting :class:`Principal` carries the user plus, for
token auth, the token's workspace/role ceiling. Every workspace-scoped route
depends on :func:`require_workspace`, which is the one place membership and
role are checked.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import Optional, Tuple

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_session
from .orm import ApiToken, Run, User, Workspace, WorkspaceMember, utcnow
from .security import hash_token, looks_like_api_token, verify_session
from .settings import get_settings


class Role(IntEnum):
    viewer = 1
    member = 2
    admin = 3

    @classmethod
    def parse(cls, value: str) -> "Role":
        try:
            return cls[value]
        except KeyError:
            raise ValueError(f"invalid role: {value!r}")


@dataclass
class Principal:
    user: User
    # For API-token auth: the token's workspace scope (None = all the user's
    # workspaces) and the role it may not exceed.
    token_workspace_id: Optional[int] = None
    token_role_ceiling: Optional[Role] = None

    @property
    def is_global_admin(self) -> bool:
        return bool(self.user.is_global_admin)


def auth_active() -> bool:
    """True when authentication is enforced. Auth is on whenever any auth
    mechanism is configured; otherwise the app runs open (single-user/dev)."""
    s = get_settings()
    return bool(s.session_secret or s.bootstrap_admin_password or s.oidc_enabled or s.auth_password)


async def _principal_from_request(request: Request, session: AsyncSession) -> Optional[Principal]:
    # 1) Bearer API token
    authz = request.headers.get("Authorization", "")
    if authz.lower().startswith("bearer "):
        raw = authz.split(" ", 1)[1].strip()
        if looks_like_api_token(raw):
            row = (
                await session.execute(select(ApiToken).where(ApiToken.token_hash == hash_token(raw)))
            ).scalar_one_or_none()
            if row is None or row.revoked_at is not None:
                return None
            user = await session.get(User, row.user_id)
            if user is None or not user.is_active:
                return None
            row.last_used_at = utcnow()
            await session.commit()
            return Principal(
                user=user,
                token_workspace_id=row.workspace_id,
                token_role_ceiling=Role.parse(row.role_ceiling),
            )
        return None

    # 2) Signed session cookie
    settings = get_settings()
    cookie = request.cookies.get(settings.session_cookie_name)
    if cookie:
        user_id = verify_session(settings.session_signing_key, cookie, settings.session_ttl_seconds)
        if user_id is not None:
            user = await session.get(User, user_id)
            if user is not None and user.is_active:
                return Principal(user=user)
    return None


async def current_principal(
    request: Request, session: AsyncSession = Depends(get_session)
) -> Principal:
    """FastAPI dependency: the authenticated principal, or 401.

    When auth is not configured the app runs open and a synthetic anonymous
    global-admin principal is returned so existing single-user deployments keep
    working with zero ceremony.
    """
    if not auth_active():
        return Principal(user=_anonymous_admin())
    principal = await _principal_from_request(request, session)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return principal


def _anonymous_admin() -> User:
    u = User(id=0, provider="local", subject="__anonymous__", display_name="Anonymous", is_global_admin=True, is_active=True)
    u.created_at = datetime.min
    return u


async def current_user(principal: Principal = Depends(current_principal)) -> User:
    return principal.user


async def get_membership(session: AsyncSession, user_id: int, workspace_id: int) -> Optional[WorkspaceMember]:
    return (
        await session.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == user_id,
            )
        )
    ).scalar_one_or_none()


@dataclass
class WorkspaceContext:
    workspace: Workspace
    principal: Principal
    role: Role  # effective role in this workspace (capped by token ceiling)

    def at_least(self, role: Role) -> bool:
        return self.role >= role


async def _default_workspace_for(session: AsyncSession, principal: Principal) -> Tuple[Workspace, Role]:
    """The workspace to use when a request does not name one: the user's
    personal workspace, or (in open/global-admin mode) the singleton default."""
    from .provisioning import ensure_default_workspace, ensure_personal_workspace

    if principal.user.id:
        # A real user: prefer their personal workspace.
        personal = (
            await session.execute(
                select(Workspace).where(
                    Workspace.owner_user_id == principal.user.id, Workspace.kind == "personal"
                )
            )
        ).scalars().first()
        if personal is None:
            personal = await ensure_personal_workspace(session, principal.user)
            await session.commit()
        return personal, Role.admin
    # Open mode (anonymous global admin): the shared default workspace.
    ws = await ensure_default_workspace(session)
    await session.commit()
    return ws, Role.admin


def active_workspace(min_role: Role = Role.viewer):
    """Dependency: resolve the workspace from an optional ``workspace_id``
    query parameter, defaulting to the caller's personal/default workspace so
    single-user use needs no ceremony. Authorizes at ``min_role``."""

    async def dependency(
        workspace_id: Optional[int] = None,
        principal: Principal = Depends(current_principal),
        session: AsyncSession = Depends(get_session),
    ) -> WorkspaceContext:
        if workspace_id is None and principal.token_workspace_id is not None:
            # A workspace-scoped token must never fall back to the owner's
            # personal/default workspace: resolve to its own scope so the
            # confinement holds even when the caller omits ``workspace_id``.
            workspace_id = principal.token_workspace_id
        if workspace_id is None:
            ws, role = await _default_workspace_for(session, principal)
        else:
            ws = await session.get(Workspace, workspace_id)
            if ws is None:
                raise HTTPException(status_code=404, detail="Workspace not found")
            if principal.token_workspace_id is not None and principal.token_workspace_id != workspace_id:
                raise HTTPException(status_code=403, detail="Token is not scoped to this workspace")
            if principal.is_global_admin:
                role = Role.admin
            else:
                membership = await get_membership(session, principal.user.id, workspace_id)
                if membership is None:
                    raise HTTPException(status_code=403, detail="Not a member of this workspace")
                role = Role.parse(membership.role)
        if principal.token_role_ceiling is not None and role > principal.token_role_ceiling:
            role = principal.token_role_ceiling
        if role < min_role:
            raise HTTPException(status_code=403, detail=f"Requires {min_role.name} role")
        return WorkspaceContext(workspace=ws, principal=principal, role=role)

    return dependency


async def authorize_workspace_role(
    session: AsyncSession, principal: Principal, workspace_id: int, min_role: Role
) -> WorkspaceContext:
    """Resolve and authorize an *explicit* workspace at ``min_role`` for the
    given principal. Used by cross-workspace actions (e.g. sharing) where the
    target workspace is not the request's active one. Raises 403/404 exactly
    like the standard dependencies."""
    workspace = await session.get(Workspace, workspace_id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    if principal.token_workspace_id is not None and principal.token_workspace_id != workspace_id:
        raise HTTPException(status_code=403, detail="Token is not scoped to this workspace")
    if principal.is_global_admin:
        effective = Role.admin
    else:
        membership = await get_membership(session, principal.user.id, workspace_id)
        if membership is None:
            raise HTTPException(status_code=403, detail="Not a member of this workspace")
        effective = Role.parse(membership.role)
    if principal.token_role_ceiling is not None and effective > principal.token_role_ceiling:
        effective = principal.token_role_ceiling
    if effective < min_role:
        raise HTTPException(status_code=403, detail=f"Requires {min_role.name} role")
    return WorkspaceContext(workspace=workspace, principal=principal, role=effective)


def require_workspace(min_role: Role = Role.viewer):
    """Dependency factory: resolve and authorize the workspace named by the
    ``workspace_id`` path/query parameter at ``min_role`` or higher."""

    async def dependency(
        workspace_id: int,
        principal: Principal = Depends(current_principal),
        session: AsyncSession = Depends(get_session),
    ) -> WorkspaceContext:
        workspace = await session.get(Workspace, workspace_id)
        if workspace is None:
            raise HTTPException(status_code=404, detail="Workspace not found")

        # An API token scoped to a specific workspace may only touch that one.
        if principal.token_workspace_id is not None and principal.token_workspace_id != workspace_id:
            raise HTTPException(status_code=403, detail="Token is not scoped to this workspace")

        if principal.is_global_admin:
            effective = Role.admin
        else:
            membership = await get_membership(session, principal.user.id, workspace_id)
            if membership is None:
                raise HTTPException(status_code=403, detail="Not a member of this workspace")
            effective = Role.parse(membership.role)

        # A token can only ever act up to its role ceiling.
        if principal.token_role_ceiling is not None and effective > principal.token_role_ceiling:
            effective = principal.token_role_ceiling

        if effective < min_role:
            raise HTTPException(status_code=403, detail=f"Requires {min_role.name} role")
        return WorkspaceContext(workspace=workspace, principal=principal, role=effective)

    return dependency


async def _principal_from_token(raw: str, session: AsyncSession) -> Optional[Principal]:
    if not looks_like_api_token(raw):
        return None
    row = (
        await session.execute(select(ApiToken).where(ApiToken.token_hash == hash_token(raw)))
    ).scalar_one_or_none()
    if row is None or row.revoked_at is not None:
        return None
    user = await session.get(User, row.user_id)
    if user is None or not user.is_active:
        return None
    row.last_used_at = utcnow()
    await session.commit()
    return Principal(
        user=user, token_workspace_id=row.workspace_id, token_role_ceiling=Role.parse(row.role_ceiling)
    )


async def principal_from_websocket(websocket, session: AsyncSession) -> Optional[Principal]:
    """Resolve the principal for a WebSocket. Browsers cannot set custom
    headers on WS handshakes, so a ``token`` query parameter is accepted in
    addition to the session cookie and Authorization header."""
    if not auth_active():
        return Principal(user=_anonymous_admin())
    authz = websocket.headers.get("Authorization", "")
    if authz.lower().startswith("bearer "):
        p = await _principal_from_token(authz.split(" ", 1)[1].strip(), session)
        if p is not None:
            return p
    token = websocket.query_params.get("token")
    if token:
        p = await _principal_from_token(token.strip(), session)
        if p is not None:
            return p
    settings = get_settings()
    cookie = websocket.cookies.get(settings.session_cookie_name)
    if cookie:
        user_id = verify_session(settings.session_signing_key, cookie, settings.session_ttl_seconds)
        if user_id is not None:
            user = await session.get(User, user_id)
            if user is not None and user.is_active:
                return Principal(user=user)
    return None


async def authorize_run_view(session: AsyncSession, principal: Principal, run: Run) -> bool:
    """True when ``principal`` may view ``run`` (workspace membership + the
    workspace's run-visibility policy). Used by the streaming endpoints, which
    cannot use the standard workspace dependency."""
    workspace = await session.get(Workspace, run.workspace_id)
    if workspace is None:
        return False
    if principal.token_workspace_id is not None and principal.token_workspace_id != workspace.id:
        return False
    if principal.is_global_admin:
        return True
    membership = await get_membership(session, principal.user.id, workspace.id)
    if membership is None:
        return False
    role = Role.parse(membership.role)
    if principal.token_role_ceiling is not None and role > principal.token_role_ceiling:
        role = principal.token_role_ceiling
    if (
        workspace.run_visibility == "own"
        and role < Role.admin
        and run.created_by_user_id
        and run.created_by_user_id != principal.user.id
    ):
        return False
    return True
