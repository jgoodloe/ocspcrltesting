"""Authentication endpoints: local login, OIDC login/callback, session, /me."""

from __future__ import annotations

import logging
import secrets
import time
from typing import Dict, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..authz import Role, current_principal, current_user, Principal
from ..db import get_session
from ..orm import User, Workspace, WorkspaceMember, utcnow
from ..provisioning import get_or_create_oidc_user, sync_oidc_group_memberships
from ..schemas import AuthConfigOut, LoginIn, MeOut, UserOut, WorkspaceOut
from ..security import sign_session, verify_password
from ..settings import get_settings

logger = logging.getLogger("ocspweb.auth")

router = APIRouter(tags=["auth"])

# Very small in-process login rate limiter (per username+ip): N failures in a
# window blocks further attempts briefly. Good enough for break-glass local
# auth; OIDC is the primary path.
_FAILURES: Dict[str, Tuple[int, float]] = {}
_MAX_FAILURES = 5
_WINDOW = 300.0


def _rate_key(request: Request, username: str) -> str:
    ip = request.client.host if request.client else "?"
    return f"{ip}:{username}"


def _rate_limited(key: str) -> bool:
    count, first = _FAILURES.get(key, (0, 0.0))
    if count >= _MAX_FAILURES and (time.monotonic() - first) < _WINDOW:
        return True
    return False


def _record_failure(key: str) -> None:
    count, first = _FAILURES.get(key, (0, 0.0))
    if (time.monotonic() - first) >= _WINDOW:
        count, first = 0, time.monotonic()
    _FAILURES[key] = (count + 1, first or time.monotonic())


def _clear_failures(key: str) -> None:
    _FAILURES.pop(key, None)


def _set_session_cookie(response: Response, user_id: int) -> None:
    settings = get_settings()
    response.set_cookie(
        settings.session_cookie_name,
        sign_session(settings.session_signing_key, user_id),
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path=(settings.base_path or "") + "/",
    )


def _clear_session_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        settings.session_cookie_name, path=(settings.base_path or "") + "/"
    )


def _public_prefix() -> str:
    return get_settings().base_path or ""


@router.get("/auth/config", response_model=AuthConfigOut)
async def auth_config() -> AuthConfigOut:
    from ..authz import auth_active

    settings = get_settings()
    return AuthConfigOut(
        auth_required=auth_active(),
        local_login_enabled=settings.local_login_enabled,
        oidc_enabled=settings.oidc_enabled,
        oidc_login_url=f"{_public_prefix()}/api/auth/oidc/login" if settings.oidc_enabled else None,
    )


@router.post("/auth/login", response_model=UserOut)
async def local_login(
    payload: LoginIn, request: Request, response: Response, session: AsyncSession = Depends(get_session)
) -> UserOut:
    settings = get_settings()
    if not settings.local_login_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Local login is disabled")
    key = _rate_key(request, payload.username)
    if _rate_limited(key):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts; try again later")

    user = (
        await session.execute(
            select(User).where(User.provider == "local", User.subject == payload.username)
        )
    ).scalar_one_or_none()
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        _record_failure(key)
        await audit.record(session, "login.failure", actor=payload.username, detail={"provider": "local"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    _clear_failures(key)
    user.last_login_at = utcnow()
    await session.commit()
    _set_session_cookie(response, user.id)
    await audit.record(session, "login.success", user=user, detail={"provider": "local"})
    return _user_out(user)


@router.post("/auth/logout", status_code=204)
async def logout(response: Response) -> Response:
    _clear_session_cookie(response)
    return Response(status_code=204)


@router.get("/auth/me", response_model=MeOut)
async def me(
    principal: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)
) -> MeOut:
    user = principal.user
    if principal.is_global_admin:
        rows = (await session.execute(select(Workspace))).scalars().all()
        memberships = {}
    else:
        rows_q = (
            await session.execute(
                select(Workspace, WorkspaceMember)
                .join(WorkspaceMember, WorkspaceMember.workspace_id == Workspace.id)
                .where(WorkspaceMember.user_id == user.id)
            )
        ).all()
        rows = [w for (w, _m) in rows_q]
        memberships = {w.id: m.role for (w, m) in rows_q}
    workspaces = [
        _workspace_out(w, role=("admin" if principal.is_global_admin else memberships.get(w.id)))
        for w in rows
    ]
    return MeOut(user=_user_out(user), workspaces=workspaces)


# ---- OIDC -----------------------------------------------------------------

# Transient state store for the OIDC authorization-code flow (CSRF + nonce).
_OIDC_STATE: Dict[str, float] = {}
_OIDC_STATE_TTL = 600.0


def _oidc_redirect_uri(request: Request) -> str:
    settings = get_settings()
    if settings.public_base_url:
        base = settings.public_base_url.rstrip("/")
        return f"{base}{_public_prefix()}/api/auth/oidc/callback"
    return str(request.url_for("oidc_callback"))


def _get_oauth():
    from authlib.integrations.starlette_client import OAuth

    settings = get_settings()
    oauth = OAuth()
    oauth.register(
        name="authentik",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        server_metadata_url=settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs={"scope": " ".join(settings.oidc_scope_list)},
    )
    return oauth.create_client("authentik")


@router.get("/auth/oidc/login")
async def oidc_login(request: Request):
    settings = get_settings()
    if not settings.oidc_enabled:
        raise HTTPException(status_code=404, detail="OIDC is not configured")
    client = _get_oauth()
    state = secrets.token_urlsafe(24)
    _OIDC_STATE[state] = time.monotonic()
    return await client.authorize_redirect(request, _oidc_redirect_uri(request), state=state)


@router.get("/auth/oidc/callback", name="oidc_callback")
async def oidc_callback(request: Request, response: Response, session: AsyncSession = Depends(get_session)):
    from fastapi.responses import RedirectResponse

    settings = get_settings()
    if not settings.oidc_enabled:
        raise HTTPException(status_code=404, detail="OIDC is not configured")

    # Drop expired states, then validate.
    now = time.monotonic()
    for s, t in list(_OIDC_STATE.items()):
        if now - t > _OIDC_STATE_TTL:
            _OIDC_STATE.pop(s, None)
    state = request.query_params.get("state", "")
    if state not in _OIDC_STATE:
        raise HTTPException(status_code=400, detail="Invalid or expired OIDC state")
    _OIDC_STATE.pop(state, None)

    client = _get_oauth()
    try:
        token = await client.authorize_access_token(request)
    except Exception as exc:  # pragma: no cover - network path
        logger.warning("OIDC token exchange failed: %s", exc)
        await audit.record(session, "login.failure", detail={"provider": "oidc", "error": str(exc)})
        raise HTTPException(status_code=401, detail="OIDC authentication failed") from exc

    claims = token.get("userinfo") or {}
    sub = claims.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="OIDC response missing subject")
    user = await get_or_create_oidc_user(
        session, subject=str(sub), email=claims.get("email"), display_name=claims.get("name")
    )
    groups = claims.get(settings.oidc_group_claim) or []
    if isinstance(groups, str):
        groups = [groups]
    await sync_oidc_group_memberships(session, user, [str(g) for g in groups])

    _set_session_cookie(response, user.id)
    await audit.record(session, "login.success", user=user, detail={"provider": "oidc"})
    redirect = RedirectResponse(url=(_public_prefix() or "") + "/", status_code=303)
    redirect.raw_headers.extend(response.raw_headers)  # carry the Set-Cookie
    return redirect


# ---- serializers ----------------------------------------------------------


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        provider=user.provider,
        subject=user.subject,
        email=user.email,
        display_name=user.display_name,
        is_global_admin=bool(user.is_global_admin),
        is_active=bool(user.is_active),
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


def _workspace_out(w: Workspace, role: Optional[str]) -> WorkspaceOut:
    return WorkspaceOut(
        id=w.id,
        name=w.name,
        kind=w.kind,
        run_visibility=w.run_visibility,  # type: ignore[arg-type]
        allow_private_targets=bool(w.allow_private_targets),
        max_concurrent_runs=w.max_concurrent_runs,
        oidc_group=w.oidc_group,
        role=role,  # type: ignore[arg-type]
        created_at=w.created_at,
    )
