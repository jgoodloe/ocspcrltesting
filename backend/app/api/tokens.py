"""Per-user API tokens (scoped, role-capped, hashed, revocable)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..authz import Principal, Role, current_principal, get_membership
from ..db import get_session
from ..orm import ApiToken, Workspace, utcnow
from ..schemas import TokenCreatedOut, TokenCreateIn, TokenList, TokenOut
from ..security import generate_api_token, hash_token

router = APIRouter(tags=["api-tokens"])


def _out(t: ApiToken) -> TokenOut:
    return TokenOut(
        id=t.id, name=t.name, workspace_id=t.workspace_id, role_ceiling=t.role_ceiling,  # type: ignore[arg-type]
        created_at=t.created_at, last_used_at=t.last_used_at,
    )


@router.get("/tokens", response_model=TokenList)
async def list_tokens(
    principal: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)
) -> TokenList:
    rows = (
        await session.execute(
            select(ApiToken).where(ApiToken.user_id == principal.user.id, ApiToken.revoked_at.is_(None))
        )
    ).scalars().all()
    return TokenList(items=[_out(t) for t in rows])


@router.post("/tokens", response_model=TokenCreatedOut, status_code=201)
async def create_token(
    payload: TokenCreateIn,
    principal: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> TokenCreatedOut:
    if principal.token_role_ceiling is not None:
        raise HTTPException(status_code=403, detail="API tokens cannot be created with a token")
    Role.parse(payload.role_ceiling)  # validate
    if payload.workspace_id is not None:
        ws = await session.get(Workspace, payload.workspace_id)
        if ws is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        # The user must be a member of a workspace to scope a token to it.
        if not principal.is_global_admin and await get_membership(session, principal.user.id, ws.id) is None:
            raise HTTPException(status_code=403, detail="Not a member of that workspace")

    raw = generate_api_token()
    token = ApiToken(
        user_id=principal.user.id,
        workspace_id=payload.workspace_id,
        name=payload.name,
        token_hash=hash_token(raw),
        role_ceiling=payload.role_ceiling,
    )
    session.add(token)
    await audit.record(
        session, "token.create", user=principal.user, workspace_id=payload.workspace_id,
        target=payload.name, detail={"role_ceiling": payload.role_ceiling}, commit=False,
    )
    await session.commit()
    out = _out(token)
    return TokenCreatedOut(**out.model_dump(), token=raw)


@router.delete("/tokens/{token_id}", status_code=204)
async def revoke_token(
    token_id: int,
    principal: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> Response:
    token = await session.get(ApiToken, token_id)
    if token is None or token.user_id != principal.user.id:
        raise HTTPException(status_code=404, detail="Token not found")
    token.revoked_at = utcnow()
    await audit.record(session, "token.revoke", user=principal.user, target=token.name, commit=False)
    await session.commit()
    return Response(status_code=204)
