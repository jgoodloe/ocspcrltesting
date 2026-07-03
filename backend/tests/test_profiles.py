from __future__ import annotations

from .conftest import base_run_config


def _payload(name="Lab responder", **overrides):
    return {"name": name, "description": "test profile", "config": base_run_config(**overrides)}


def test_profile_crud(app_client):
    created = app_client.post("/api/profiles", json=_payload())
    assert created.status_code == 201, created.text
    profile = created.json()
    assert profile["name"] == "Lab responder"
    assert profile["config"]["ocsp_url"] == "http://8.8.8.8/ocsp"

    listing = app_client.get("/api/profiles").json()
    assert len(listing["items"]) == 1

    updated = app_client.put(
        f"/api/profiles/{profile['id']}",
        json=_payload(name="Renamed", ocsp_url="http://8.8.4.4/ocsp"),
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Renamed"
    assert updated.json()["config"]["ocsp_url"] == "http://8.8.4.4/ocsp"

    assert app_client.delete(f"/api/profiles/{profile['id']}").status_code == 204
    assert app_client.get("/api/profiles").json()["items"] == []


def test_duplicate_profile_name_conflict(app_client):
    assert app_client.post("/api/profiles", json=_payload()).status_code == 201
    assert app_client.post("/api/profiles", json=_payload()).status_code == 409


def test_profile_not_found(app_client):
    assert app_client.put("/api/profiles/999", json=_payload()).status_code == 404
    assert app_client.delete("/api/profiles/999").status_code == 404


def test_profile_validation(app_client):
    bad = _payload()
    bad["config"]["ocsp_url"] = "ldap://nope"
    assert app_client.post("/api/profiles", json=bad).status_code == 422
