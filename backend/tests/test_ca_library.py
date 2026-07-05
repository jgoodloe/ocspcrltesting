"""Tests for the saved CA certificate library and saved_certs run wiring."""

from __future__ import annotations

import json

from .conftest import base_run_config


def _upload_ca(app_client, cert_fixtures, name=None):
    data = {"name": name} if name else {}
    return app_client.post(
        "/api/ca-certs",
        params=data,
        files={"file": ("ca.pem", cert_fixtures["ca_pem"])},
    )


def test_ca_upload_list_delete(app_client, cert_fixtures):
    created = _upload_ca(app_client, cert_fixtures, name="Test Lab Root")
    assert created.status_code == 201, created.text
    body = created.json()
    assert len(body["created"]) == 1
    assert body["skipped_duplicates"] == 0
    entry = body["created"][0]
    assert entry["name"] == "Test Lab Root"
    assert entry["is_ca"] is True
    assert entry["self_signed"] is True
    assert entry["source"] == "upload"

    # Re-upload is deduplicated by fingerprint.
    again = _upload_ca(app_client, cert_fixtures)
    assert again.status_code == 201
    assert again.json()["created"] == []
    assert again.json()["skipped_duplicates"] == 1

    listing = app_client.get("/api/ca-certs").json()
    assert [c["name"] for c in listing["items"]] == ["Test Lab Root"]

    assert app_client.delete(f"/api/ca-certs/{entry['id']}").status_code == 204
    assert app_client.get("/api/ca-certs").json()["items"] == []
    assert app_client.delete(f"/api/ca-certs/{entry['id']}").status_code == 404


def test_ca_upload_rejects_garbage(app_client):
    resp = app_client.post("/api/ca-certs", files={"file": ("x.pem", b"not a cert")})
    assert resp.status_code == 400


def test_ca_rename(app_client, cert_fixtures):
    entry = _upload_ca(app_client, cert_fixtures, name="Original").json()["created"][0]
    renamed = app_client.patch(f"/api/ca-certs/{entry['id']}", json={"name": "Renamed CA"})
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["name"] == "Renamed CA"
    listing = app_client.get("/api/ca-certs").json()
    assert [c["name"] for c in listing["items"]] == ["Renamed CA"]

    assert app_client.patch("/api/ca-certs/999999", json={"name": "x"}).status_code == 404
    assert app_client.patch(f"/api/ca-certs/{entry['id']}", json={"name": ""}).status_code == 422


def test_well_known_list(app_client):
    body = app_client.get("/api/ca-certs/well-known").json()
    names = [c["name"] for c in body["items"]]
    assert "Federal Common Policy CA G2" in names
    assert all(c["url"].startswith("http") for c in body["items"])


def test_fetch_blocked_by_ssrf_policy(app_client):
    resp = app_client.post("/api/ca-certs/fetch", json={"url": "http://127.0.0.1/ca.crt"})
    assert resp.status_code == 403


def test_run_with_saved_issuer(app_client, cert_fixtures):
    entry = _upload_ca(app_client, cert_fixtures, name="Lab Issuer").json()["created"][0]

    config = base_run_config(saved_certs={"issuer_cert": entry["id"]})
    response = app_client.post("/api/test-runs", data={"config": json.dumps(config)})
    assert response.status_code == 201, response.text
    run_id = response.json()["id"]

    detail = app_client.get(f"/api/test-runs/{run_id}").json()
    assert detail["config"]["files"]["issuer_cert"] == "Lab Issuer (saved CA)"
    assert detail["config"]["saved_certs"] == {"issuer_cert": entry["id"]}


def test_run_requires_issuer_from_somewhere(app_client):
    config = base_run_config()
    response = app_client.post("/api/test-runs", data={"config": json.dumps(config)})
    assert response.status_code == 400
    assert "issuer_cert is required" in response.json()["detail"]


def test_run_rejects_conflicting_issuer(app_client, cert_fixtures):
    entry = _upload_ca(app_client, cert_fixtures).json()["created"][0]
    config = base_run_config(saved_certs={"issuer_cert": entry["id"]})
    response = app_client.post(
        "/api/test-runs",
        data={"config": json.dumps(config)},
        files={"issuer_cert": ("issuer.pem", cert_fixtures["ca_pem"])},
    )
    assert response.status_code == 400
    assert "both an uploaded file and a saved certificate" in response.json()["detail"]


def test_run_rejects_missing_saved_cert(app_client):
    config = base_run_config(saved_certs={"issuer_cert": 424242})
    response = app_client.post("/api/test-runs", data={"config": json.dumps(config)})
    assert response.status_code == 400
    assert "not found in the CA library" in response.json()["detail"]


def test_saved_cert_slot_validation(app_client, cert_fixtures):
    entry = _upload_ca(app_client, cert_fixtures).json()["created"][0]
    config = base_run_config(saved_certs={"client_key": entry["id"]})
    response = app_client.post("/api/test-runs", data={"config": json.dumps(config)})
    assert response.status_code == 400


def test_catalog_has_scopes(app_client):
    body = app_client.get("/api/test-catalog").json()
    by_key = {c["key"]: c for c in body["categories"]}
    assert by_key["performance"]["label"].endswith("(OCSP)")
    assert by_key["security"]["label"].endswith("(OCSP)")
    assert all(t["scope"] == "ocsp" for t in by_key["performance"]["tests"])
    crl_scopes = {t["name"]: t["scope"] for t in by_key["crl"]["tests"]}
    assert crl_scopes["CRL vs OCSP consistency check"] == "crl+ocsp"
    assert crl_scopes["OCSP response signature validation"] == "ocsp"
    assert crl_scopes["CRL signature verification"] == "crl"
    pv_scopes = {t["name"]: t["scope"] for t in by_key["path_validation"]["tests"]}
    assert pv_scopes["Revoked (EE) by OCSP: OCSP response is revoked status"] == "ocsp"
    assert pv_scopes["Revoked (EE) in Fresh CRL: EE serial number on most recent CRL"] == "crl"
