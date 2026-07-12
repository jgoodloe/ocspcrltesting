from __future__ import annotations


def test_health(app_client):
    response = app_client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in ("ok", "degraded")
    assert body["database"] == "ok"


def test_version(app_client):
    body = app_client.get("/api/version").json()
    from backend.app import APP_NAME, __version__

    assert body["name"] == APP_NAME
    assert body["version"] == __version__
    assert body["engine"] == "ocsp_tester"
