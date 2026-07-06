"""Multi-user auth, workspace isolation, roles, tokens and policy ceilings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FAKE_WORKER = REPO_ROOT / "backend" / "tests" / "fake_worker.py"


def _make_client(tmp_path, monkeypatch, **env):
    """Build a TestClient with auth configured (a break-glass admin + a stable
    session secret). Each call rebuilds settings/engine for isolation."""
    monkeypatch.setenv("OCSPWEB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("OCSPWEB_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'auth.sqlite3'}")
    monkeypatch.setenv("OCSPWEB_WORKER_PYTHON", str(FAKE_WORKER))
    monkeypatch.setenv("OCSPWEB_MAX_CONCURRENT_RUNS", "4")
    monkeypatch.setenv("OCSPWEB_SESSION_SECRET", "test-session-secret")
    monkeypatch.setenv("OCSPWEB_SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("OCSPWEB_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("OCSPWEB_BOOTSTRAP_ADMIN_PASSWORD", "admin-pw!")
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    from backend.app import db, jobs, settings

    settings.get_settings.cache_clear()
    jobs.reset_job_manager()
    db._engine = None
    db._session_factory = None

    from fastapi.testclient import TestClient

    from backend.app.main import create_app

    return TestClient(create_app())


@pytest.fixture()
def auth_env(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    with client:
        yield client
    from backend.app import db, jobs, settings

    settings.get_settings.cache_clear()
    jobs.reset_job_manager()
    db._engine = None
    db._session_factory = None


def _login(client, username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r


def test_auth_required_when_configured(auth_env):
    # No session -> protected endpoints are 401.
    assert auth_env.get("/api/test-runs").status_code == 401
    assert auth_env.get("/api/profiles").status_code == 401
    # Public endpoints stay open.
    assert auth_env.get("/api/health").status_code == 200
    cfg = auth_env.get("/api/auth/config").json()
    assert cfg["auth_required"] is True
    assert cfg["local_login_enabled"] is True


def test_bootstrap_admin_login_and_me(auth_env):
    auth_env.cookies.clear()
    _login(auth_env, "admin", "admin-pw!")
    me = auth_env.get("/api/auth/me").json()
    assert me["user"]["is_global_admin"] is True
    assert me["user"]["subject"] == "admin"
    # Global admin sees every workspace (at least the default one).
    assert any(w["name"] == "Default" for w in me["workspaces"])


def test_bad_password_rejected(auth_env):
    auth_env.cookies.clear()
    r = auth_env.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401


def test_admin_creates_user_and_workspace_isolation(auth_env):
    auth_env.cookies.clear()
    _login(auth_env, "admin", "admin-pw!")

    # Create two local users.
    for name in ("alice", "bob"):
        r = auth_env.post(
            "/api/admin/users",
            json={"username": name, "password": f"{name}-secret"},
        )
        assert r.status_code == 201, r.text

    # Alice logs in and creates a profile in her personal workspace.
    auth_env.cookies.clear()
    _login(auth_env, "alice", "alice-secret")
    alice_me = auth_env.get("/api/auth/me").json()
    alice_ws = alice_me["workspaces"][0]["id"]
    r = auth_env.post(
        "/api/profiles",
        json={"name": "alice-p", "config": {"ocsp_url": "http://8.8.8.8/ocsp"}},
    )
    assert r.status_code == 201, r.text
    assert auth_env.get("/api/profiles").json()["items"][0]["name"] == "alice-p"

    # Bob logs in: he cannot see Alice's profiles and cannot reach her workspace.
    auth_env.cookies.clear()
    _login(auth_env, "bob", "bob-secret")
    assert auth_env.get("/api/profiles").json()["items"] == []
    assert auth_env.get(f"/api/profiles?workspace_id={alice_ws}").status_code == 403


def test_membership_roles_and_run_visibility(auth_env):
    auth_env.cookies.clear()
    _login(auth_env, "admin", "admin-pw!")
    for name in ("carol", "dave"):
        auth_env.post("/api/admin/users", json={"username": name, "password": f"{name}-secret"})

    # Admin creates a shared workspace with run_visibility "own".
    r = auth_env.post("/api/workspaces", json={"name": "team"})
    assert r.status_code == 201, r.text
    team = r.json()["id"]
    auth_env.patch(f"/api/workspaces/{team}", json={"run_visibility": "own"})

    # Users must have logged in once before they can be added.
    auth_env.cookies.clear()
    _login(auth_env, "carol", "carol-secret")
    auth_env.cookies.clear()
    _login(auth_env, "dave", "dave-secret")

    auth_env.cookies.clear()
    _login(auth_env, "admin", "admin-pw!")
    assert auth_env.post(f"/api/workspaces/{team}/members", json={"email": None, "user_id": None, "role": "member"}).status_code == 400
    # Add by username lookup via email is unavailable (local users have no email);
    # fetch their ids from the admin user list.
    users = {u["subject"]: u["id"] for u in auth_env.get("/api/admin/users").json()}
    for name, role in (("carol", "member"), ("dave", "viewer")):
        r = auth_env.post(
            f"/api/workspaces/{team}/members", json={"user_id": users[name], "role": role}
        )
        assert r.status_code == 201, r.text

    # A viewer cannot create runs (needs member).
    auth_env.cookies.clear()
    _login(auth_env, "dave", "dave-secret")
    assert (
        auth_env.post(
            f"/api/test-runs?workspace_id={team}",
            data={"config": json.dumps({"ocsp_url": "http://8.8.8.8/ocsp"})},
        ).status_code
        == 403
    )


def test_api_token_auth_and_scope(auth_env):
    auth_env.cookies.clear()
    _login(auth_env, "admin", "admin-pw!")
    me = auth_env.get("/api/auth/me").json()
    personal = [w for w in me["workspaces"] if w["kind"] == "personal"][0]["id"]

    r = auth_env.post(
        "/api/tokens",
        json={"name": "ci", "workspace_id": personal, "role_ceiling": "viewer"},
    )
    assert r.status_code == 201, r.text
    token = r.json()["token"]
    assert token.startswith("ocspt_")

    # A fresh client (no cookies) authenticates with the bearer token.
    from fastapi.testclient import TestClient  # noqa: F401

    auth_env.cookies.clear()
    headers = {"Authorization": f"Bearer {token}"}
    # Viewer ceiling: can read...
    assert auth_env.get(f"/api/profiles?workspace_id={personal}", headers=headers).status_code == 200
    # ...but cannot write (needs member).
    assert (
        auth_env.post(
            f"/api/profiles?workspace_id={personal}",
            headers=headers,
            json={"name": "x", "config": {"ocsp_url": "http://8.8.8.8/ocsp"}},
        ).status_code
        == 403
    )


def test_token_scope_not_bypassable_by_omitting_workspace_id(auth_env):
    """A workspace-scoped token must resolve to its own workspace even when the
    caller omits ``workspace_id`` — never the owner's personal workspace
    (regression for the scope-confinement bypass, issues #32/#38)."""
    auth_env.cookies.clear()
    _login(auth_env, "admin", "admin-pw!")
    me = auth_env.get("/api/auth/me").json()
    personal = [w for w in me["workspaces"] if w["kind"] == "personal"][0]["id"]

    team = auth_env.post("/api/workspaces", json={"name": "scoped-team"}).json()["id"]

    # A profile in each workspace so we can tell which one a request resolves to.
    assert auth_env.post(
        f"/api/profiles?workspace_id={personal}",
        json={"name": "in-personal", "config": {"ocsp_url": "http://8.8.8.8/ocsp"}},
    ).status_code == 201
    assert auth_env.post(
        f"/api/profiles?workspace_id={team}",
        json={"name": "in-team", "config": {"ocsp_url": "http://8.8.8.8/ocsp"}},
    ).status_code == 201

    # Token scoped to the shared team workspace.
    token = auth_env.post(
        "/api/tokens", json={"name": "ci", "workspace_id": team, "role_ceiling": "member"}
    ).json()["token"]

    auth_env.cookies.clear()
    headers = {"Authorization": f"Bearer {token}"}
    # No workspace_id: must land in the scoped (team) workspace, not personal.
    listing = auth_env.get("/api/profiles", headers=headers)
    assert listing.status_code == 200, listing.text
    names = {p["name"] for p in listing.json()["items"]}
    assert names == {"in-team"}
    # Explicitly targeting a different workspace is still forbidden.
    assert auth_env.get(f"/api/profiles?workspace_id={personal}", headers=headers).status_code == 403


def test_share_profile_requires_contributor_in_target(auth_env):
    """Sharing copies into the target workspace and is refused for viewers
    (issues #26/#27)."""
    auth_env.cookies.clear()
    _login(auth_env, "admin", "admin-pw!")
    for name in ("erin", "frank"):
        auth_env.post("/api/admin/users", json={"username": name, "password": f"{name}-secret"})
    users = {u["subject"]: u["id"] for u in auth_env.get("/api/admin/users").json()}

    contributor_ws = auth_env.post("/api/workspaces", json={"name": "contrib"}).json()["id"]
    viewer_ws = auth_env.post("/api/workspaces", json={"name": "viewonly"}).json()["id"]

    auth_env.cookies.clear()
    _login(auth_env, "erin", "erin-secret")
    erin_me = auth_env.get("/api/auth/me").json()
    erin_personal = erin_me["workspaces"][0]["id"]
    prof = auth_env.post(
        f"/api/profiles?workspace_id={erin_personal}",
        json={"name": "shareme", "config": {"ocsp_url": "http://8.8.8.8/ocsp"}},
    ).json()

    auth_env.cookies.clear()
    _login(auth_env, "admin", "admin-pw!")
    auth_env.post(
        f"/api/workspaces/{contributor_ws}/members",
        json={"user_id": users["erin"], "role": "member"},
    )
    auth_env.post(
        f"/api/workspaces/{viewer_ws}/members",
        json={"user_id": users["erin"], "role": "viewer"},
    )

    auth_env.cookies.clear()
    _login(auth_env, "erin", "erin-secret")
    # Viewer in the target -> refused.
    denied = auth_env.post(
        f"/api/profiles/{prof['id']}/share?workspace_id={erin_personal}",
        json={"target_workspace_id": viewer_ws},
    )
    assert denied.status_code == 403, denied.text
    # Member in the target -> copied.
    ok = auth_env.post(
        f"/api/profiles/{prof['id']}/share?workspace_id={erin_personal}",
        json={"target_workspace_id": contributor_ws},
    )
    assert ok.status_code == 201, ok.text
    shared = auth_env.get(f"/api/profiles?workspace_id={contributor_ws}").json()["items"]
    assert [p["name"] for p in shared] == ["shareme"]


def test_policy_ceiling_enforced(auth_env):
    # allow_private_targets defaults off for the deployment, so a workspace
    # cannot enable it.
    auth_env.cookies.clear()
    _login(auth_env, "admin", "admin-pw!")
    r = auth_env.post("/api/workspaces", json={"name": "lab"})
    ws = r.json()["id"]
    resp = auth_env.patch(f"/api/workspaces/{ws}", json={"allow_private_targets": True})
    assert resp.status_code == 400
    # And max_concurrent_runs cannot exceed the deployment ceiling (4).
    resp = auth_env.patch(f"/api/workspaces/{ws}", json={"max_concurrent_runs": 10})
    assert resp.status_code == 400


def test_audit_log_records_events(auth_env):
    auth_env.cookies.clear()
    _login(auth_env, "admin", "admin-pw!")
    auth_env.post("/api/workspaces", json={"name": "audited"})
    entries = auth_env.get("/api/admin/audit").json()["items"]
    events = {e["event"] for e in entries}
    assert "login.success" in events
    assert "workspace.create" in events
