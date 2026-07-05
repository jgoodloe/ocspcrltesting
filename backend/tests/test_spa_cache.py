"""SPA caching headers.

The index.html shell must never be cached (it points at the current hashed
bundles, so a stale copy pins the browser to an old build after an upgrade),
while the content-hashed assets under /assets are safe to cache forever.
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(
        '<!doctype html><html><head><base href="/"></head><body></body></html>',
        encoding="utf-8",
    )
    (dist / "assets" / "index-abc123.js").write_text("console.log('hi')", encoding="utf-8")

    monkeypatch.setenv("OCSPWEB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("OCSPWEB_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'spa.sqlite3'}")
    monkeypatch.setenv("OCSPWEB_AUTH_PASSWORD", "")
    monkeypatch.setenv("OCSPWEB_FRONTEND_DIST", str(dist))

    from backend.app import db, jobs, settings

    settings.get_settings.cache_clear()
    jobs.reset_job_manager()
    db._engine = None
    db._session_factory = None

    from fastapi.testclient import TestClient

    from backend.app.main import create_app

    with TestClient(create_app()) as c:
        yield c

    settings.get_settings.cache_clear()
    jobs.reset_job_manager()
    db._engine = None
    db._session_factory = None


def test_spa_index_is_not_cached(client):
    resp = client.get("/runs/some-deep-link")  # any non-API path -> SPA shell
    assert resp.status_code == 200
    assert "no-cache" in resp.headers.get("cache-control", "").lower()


def test_hashed_assets_are_immutably_cached(client):
    resp = client.get("/assets/index-abc123.js")
    assert resp.status_code == 200
    cc = resp.headers.get("cache-control", "").lower()
    assert "immutable" in cc and "max-age=31536000" in cc


def test_api_404_stays_json_not_spa(client):
    resp = client.get("/api/does-not-exist")
    assert resp.status_code == 404
    assert resp.headers.get("content-type", "").startswith("application/json")
