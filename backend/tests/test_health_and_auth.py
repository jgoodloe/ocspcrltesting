from __future__ import annotations

import base64


def test_health(app_client):
    response = app_client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in ("ok", "degraded")
    assert body["database"] == "ok"


def test_version(app_client):
    body = app_client.get("/api/version").json()
    assert body["name"] == "ocsp-testing-web"
    assert body["engine"] == "ocsp_tester"


def test_basic_auth_enforced(app_client):
    from backend.app.settings import get_settings

    settings = get_settings()
    settings.auth_password = "s3cret"
    try:
        assert app_client.get("/api/version").status_code == 401
        header = "Basic " + base64.b64encode(b"admin:s3cret").decode()
        assert app_client.get("/api/version", headers={"Authorization": header}).status_code == 200
        bad = "Basic " + base64.b64encode(b"admin:wrong").decode()
        assert app_client.get("/api/version", headers={"Authorization": bad}).status_code == 401
    finally:
        settings.auth_password = ""
