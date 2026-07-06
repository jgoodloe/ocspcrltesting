"""Legacy-database upgrade path.

A deployment created before the multi-user schema has ``runs`` / ``profiles`` /
``ca_certificates`` tables without the ``workspace_id`` (and
``created_by_user_id``) columns. ``Base.metadata.create_all`` only creates
*missing tables* — it never alters an existing one — so on boot the startup
backfill used to crash with ``sqlite3.OperationalError: no such column:
workspace_id``. ``init_db`` now reconciles those tables additively; these tests
lock that behaviour in.
"""

from __future__ import annotations

import asyncio

from sqlalchemy import create_engine


def _build_legacy_db(db_path) -> None:
    """Create pre-multi-user tables (no workspace columns) and seed a row each."""
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE runs ("
            "id VARCHAR(36) PRIMARY KEY, ocsp_url TEXT NOT NULL, status VARCHAR(20) NOT NULL, "
            "created_at DATETIME NOT NULL, started_at DATETIME, finished_at DATETIME, "
            "config_json TEXT NOT NULL, error TEXT, current_activity TEXT, "
            "totals_json TEXT NOT NULL, latency_json TEXT, last_seq INTEGER NOT NULL)"
        )
        conn.exec_driver_sql(
            "CREATE TABLE profiles ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(120) NOT NULL, description TEXT, "
            "config_json TEXT NOT NULL, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)"
        )
        # Faithful to the pre-multi-user schema: a GLOBAL unique on the
        # fingerprint (later relaxed to a per-workspace composite).
        conn.exec_driver_sql(
            "CREATE TABLE ca_certificates ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(200) NOT NULL, pem TEXT NOT NULL, "
            "subject TEXT NOT NULL, issuer TEXT NOT NULL, serial_number TEXT NOT NULL, "
            "fingerprint_sha256 VARCHAR(64) NOT NULL, not_before DATETIME NOT NULL, "
            "not_after DATETIME NOT NULL, is_ca INTEGER NOT NULL, source VARCHAR(20) NOT NULL, "
            "source_url TEXT, created_at DATETIME NOT NULL, "
            "CONSTRAINT uq_ca_certificates_fingerprint UNIQUE (fingerprint_sha256))"
        )
        conn.exec_driver_sql(
            "INSERT INTO ca_certificates "
            "(name, pem, subject, issuer, serial_number, fingerprint_sha256, not_before, "
            "not_after, is_ca, source, created_at) VALUES "
            "('legacy-ca','-----BEGIN-----','CN=CA','CN=CA','1','deadbeef',"
            "'2026-01-01T00:00:00+00:00','2030-01-01T00:00:00+00:00',1,'upload',"
            "'2026-01-01T00:00:00+00:00')"
        )
        conn.exec_driver_sql(
            "INSERT INTO runs (id, ocsp_url, status, created_at, config_json, totals_json, last_seq) "
            "VALUES ('legacy-run-1','http://ocsp.example','completed',"
            "'2026-01-01T00:00:00+00:00','{}','{}',0)"
        )
        conn.exec_driver_sql(
            "INSERT INTO profiles (name, description, config_json, created_at, updated_at) "
            "VALUES ('legacy-profile','x','{}','2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00')"
        )
        cols = [r[1] for r in conn.exec_driver_sql("PRAGMA table_info(runs)").fetchall()]
        assert "workspace_id" not in cols  # precondition: genuinely legacy
    engine.dispose()


def _boot(monkeypatch, tmp_path):
    db_file = tmp_path / "legacy.sqlite3"
    _build_legacy_db(db_file)

    monkeypatch.setenv("OCSPWEB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("OCSPWEB_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.setenv("OCSPWEB_AUTH_PASSWORD", "")

    from backend.app import db, settings

    settings.get_settings.cache_clear()
    db._engine = None
    db._session_factory = None

    from sqlalchemy import text

    from backend.app.provisioning import run_startup_provisioning

    async def run():
        await db.init_db()
        async with db.session_factory()() as session:
            await run_startup_provisioning(session, settings.get_settings())
        async with db.session_factory()() as session:
            cols = {r[1] for r in (await session.execute(text("PRAGMA table_info(runs)"))).all()}
            run_ws = (
                await session.execute(text("SELECT workspace_id FROM runs WHERE id='legacy-run-1'"))
            ).scalar_one()
            prof_ws = (
                await session.execute(
                    text("SELECT workspace_id FROM profiles WHERE name='legacy-profile'")
                )
            ).scalar_one()
        # Re-run to prove idempotency (no duplicate-column / index errors).
        await db.init_db()
        await db.dispose_db()
        return cols, run_ws, prof_ws

    try:
        return asyncio.run(run())
    finally:
        settings.get_settings.cache_clear()
        db._engine = None
        db._session_factory = None


def test_legacy_db_boots_and_backfills(monkeypatch, tmp_path):
    cols, run_ws, prof_ws = _boot(monkeypatch, tmp_path)

    # Missing columns were added to the pre-existing tables...
    assert {"workspace_id", "created_by_user_id"} <= cols
    # ...and the legacy rows were backfilled into a (the Default) workspace.
    assert run_ws is not None
    assert prof_ws is not None
    assert run_ws == prof_ws


def test_legacy_ca_cert_global_unique_relaxed_to_composite(monkeypatch, tmp_path):
    """The pre-multi-user global unique on ca_certificates.fingerprint_sha256 is
    relaxed to (workspace_id, fingerprint_sha256) so the same CA can live in
    more than one workspace — but duplicates within a workspace still fail."""
    import pytest
    from sqlalchemy import create_engine, text

    _boot(monkeypatch, tmp_path)  # runs init_db (the reconciliation) once

    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.sqlite3'}")
    try:
        row = (
            "INSERT INTO ca_certificates "
            "(workspace_id, name, pem, subject, issuer, serial_number, fingerprint_sha256, "
            "not_before, not_after, is_ca, source, created_at) VALUES "
            "({ws}, 'c', 'p', 's', 'i', '1', 'sharedfp', "
            "'2026-01-01T00:00:00+00:00', '2030-01-01T00:00:00+00:00', 1, 'upload', "
            "'2026-01-01T00:00:00+00:00')"
        )
        # Same fingerprint in two different workspaces: now allowed.
        with engine.begin() as conn:
            conn.exec_driver_sql(row.format(ws=1))
            conn.exec_driver_sql(row.format(ws=2))
        # Duplicate within the same workspace: still rejected.
        with pytest.raises(Exception):
            with engine.begin() as conn:
                conn.exec_driver_sql(row.format(ws=1))
        # The legacy row survived the table rebuild.
        with engine.begin() as conn:
            n = conn.exec_driver_sql(
                "SELECT COUNT(*) FROM ca_certificates WHERE fingerprint_sha256='deadbeef'"
            ).scalar()
        assert n == 1
    finally:
        engine.dispose()
