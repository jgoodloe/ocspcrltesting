"""OIDC group -> workspace role mapping (authoritative sync).

Covers the four contracts of ``sync_oidc_group_memberships``:
  * a matching group grants the mapped role (highest tier wins),
  * losing every matching group revokes the group-managed membership,
  * a membership an admin set by hand is never touched,
  * changing a group-managed role by hand pins it (sync stops managing it).
"""

from __future__ import annotations

import asyncio

import pytest


@pytest.fixture()
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("OCSPWEB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("OCSPWEB_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'rbac.sqlite3'}")
    monkeypatch.setenv("OCSPWEB_AUTH_PASSWORD", "")

    from backend.app import db as dbmod
    from backend.app import settings as settingsmod

    settingsmod.get_settings.cache_clear()
    dbmod._engine = None
    dbmod._session_factory = None
    yield dbmod
    settingsmod.get_settings.cache_clear()
    dbmod._engine = None
    dbmod._session_factory = None


def _run(db, coro_fn):
    async def main():
        await db.init_db()
        async with db.session_factory()() as session:
            result = await coro_fn(session)
        await db.dispose_db()
        return result

    return asyncio.run(main())


async def _seed_ws_and_user(session, **group_map):
    from backend.app.orm import User, Workspace

    ws = Workspace(name="Shared", kind="shared", **group_map)
    user = User(provider="oidc", subject="sub-1", email="u@example.com", is_active=True)
    session.add_all([ws, user])
    await session.flush()
    return ws, user


async def _role_in(session, ws_id, user_id):
    from sqlalchemy import select

    from backend.app.orm import WorkspaceMember

    m = (
        await session.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == ws_id, WorkspaceMember.user_id == user_id
            )
        )
    ).scalar_one_or_none()
    return (m.role, m.source) if m else None


def test_group_grants_and_highest_tier_wins(db):
    async def body(session):
        from backend.app.provisioning import sync_oidc_group_memberships

        ws, user = await _seed_ws_and_user(
            session,
            oidc_group_admin="ocsp-admins",
            oidc_group="ocsp-members",
            oidc_group_viewer="ocsp-viewers",
        )
        # In both member and admin groups -> admin (highest) wins.
        await sync_oidc_group_memberships(session, user, ["ocsp-members", "ocsp-admins"])
        return await _role_in(session, ws.id, user.id)

    assert _run(db, body) == ("admin", "oidc")


def test_viewer_only(db):
    async def body(session):
        from backend.app.provisioning import sync_oidc_group_memberships

        ws, user = await _seed_ws_and_user(session, oidc_group_viewer="ocsp-viewers")
        await sync_oidc_group_memberships(session, user, ["ocsp-viewers"])
        return await _role_in(session, ws.id, user.id)

    assert _run(db, body) == ("viewer", "oidc")


def test_leaving_group_revokes_membership(db):
    async def body(session):
        from backend.app.provisioning import sync_oidc_group_memberships

        ws, user = await _seed_ws_and_user(session, oidc_group="ocsp-members")
        await sync_oidc_group_memberships(session, user, ["ocsp-members"])
        granted = await _role_in(session, ws.id, user.id)
        # Next login with no matching group -> membership removed.
        await sync_oidc_group_memberships(session, user, ["something-else"])
        revoked = await _role_in(session, ws.id, user.id)
        return granted, revoked

    granted, revoked = _run(db, body)
    assert granted == ("member", "oidc")
    assert revoked is None


def test_downgrade_on_group_change(db):
    async def body(session):
        from backend.app.provisioning import sync_oidc_group_memberships

        ws, user = await _seed_ws_and_user(
            session, oidc_group_admin="ocsp-admins", oidc_group_viewer="ocsp-viewers"
        )
        await sync_oidc_group_memberships(session, user, ["ocsp-admins"])
        was = await _role_in(session, ws.id, user.id)
        await sync_oidc_group_memberships(session, user, ["ocsp-viewers"])
        now = await _role_in(session, ws.id, user.id)
        return was, now

    was, now = _run(db, body)
    assert was == ("admin", "oidc")
    assert now == ("viewer", "oidc")


def test_manual_membership_is_never_touched(db):
    async def body(session):
        from backend.app.orm import WorkspaceMember
        from backend.app.provisioning import sync_oidc_group_memberships

        ws, user = await _seed_ws_and_user(session, oidc_group_admin="ocsp-admins")
        # Admin hand-added this user as member; groups say they'd be admin.
        session.add(
            WorkspaceMember(workspace_id=ws.id, user_id=user.id, role="member", source="manual")
        )
        await session.flush()
        # Even matching the admin group must not upgrade a manual grant...
        await sync_oidc_group_memberships(session, user, ["ocsp-admins"])
        kept = await _role_in(session, ws.id, user.id)
        # ...and dropping the group must not revoke a manual grant.
        await sync_oidc_group_memberships(session, user, [])
        still = await _role_in(session, ws.id, user.id)
        return kept, still

    kept, still = _run(db, body)
    assert kept == ("member", "manual")
    assert still == ("member", "manual")
