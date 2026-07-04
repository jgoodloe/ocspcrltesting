"""Tests for the test catalog, fine-grained selection and save-run-as-profile."""

from __future__ import annotations

import json
import time

from .conftest import base_run_config


def _create_run(app_client, cert_fixtures, **config_overrides):
    config = base_run_config(**config_overrides)
    files = {"issuer_cert": ("issuer.pem", cert_fixtures["ca_pem"])}
    return app_client.post("/api/test-runs", data={"config": json.dumps(config)}, files=files)


def _wait_terminal(app_client, run_id, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = app_client.get(f"/api/test-runs/{run_id}").json()
        if body["status"] in ("completed", "failed", "cancelled", "timed_out"):
            return body
        time.sleep(0.1)
    raise AssertionError(f"run {run_id} did not finish; last status {body['status']}")


# --------------------------------------------------------------- catalog ----


def test_test_catalog(app_client):
    body = app_client.get("/api/test-catalog").json()
    keys = [c["key"] for c in body["categories"]]
    assert "protocol" in keys and "path_validation" in keys
    protocol = next(c for c in body["categories"] if c["key"] == "protocol")
    names = [t["name"] for t in protocol["tests"]]
    assert "HTTP GET transport" in names
    assert all(t["description"] for t in protocol["tests"])
    crl = next(c for c in body["categories"] if c["key"] == "crl")
    dynamic = [t for t in crl["tests"] if t["dynamic"]]
    assert [t["name"] for t in dynamic] == ["Fetch and parse CRL"]


def test_catalog_matches_engine_test_names():
    """Every catalog entry must exist verbatim in the engine sources so
    selection filters actually match emitted results."""
    from pathlib import Path

    from backend.app.test_catalog import TEST_CATALOG

    root = Path(__file__).resolve().parents[2]
    sources = list((root / "ocsp_tester").glob("tests_*.py"))
    # "Fetch and parse CRL" (explicit CRL URLs) is implemented by the executor.
    sources.append(root / "backend" / "app" / "worker" / "executor.py")
    engine_src = "\n".join(p.read_text(encoding="utf-8") for p in sources)
    for category, tests in TEST_CATALOG.items():
        for test in tests:
            assert test["name"] in engine_src, f"{category}: {test['name']!r} not found in engine"


# ------------------------------------------------- global selection setting ----


def test_global_selection_roundtrip(app_client):
    assert app_client.get("/api/settings/test-selection").json()["tests"] is None

    selection = {"protocol": ["HTTP GET transport", "HTTP POST transport"]}
    put = app_client.put("/api/settings/test-selection", json={"tests": selection})
    assert put.status_code == 200, put.text
    assert put.json()["tests"] == selection
    assert put.json()["updated_at"] is not None

    got = app_client.get("/api/settings/test-selection").json()
    assert got["tests"] == selection

    # Reset back to run-all
    put = app_client.put("/api/settings/test-selection", json={"tests": None})
    assert put.status_code == 200
    assert app_client.get("/api/settings/test-selection").json()["tests"] is None


def test_global_selection_validation(app_client):
    bad_cat = app_client.put("/api/settings/test-selection", json={"tests": {"nope": []}})
    assert bad_cat.status_code == 400
    assert "Unknown test category" in bad_cat.json()["detail"]

    bad_name = app_client.put(
        "/api/settings/test-selection", json={"tests": {"protocol": ["No such test"]}}
    )
    assert bad_name.status_code == 400
    assert "Unknown test" in bad_name.json()["detail"]


# ------------------------------------------------ selection resolution ----


def test_run_records_custom_selection(app_client, cert_fixtures):
    selection = {"mode": "custom", "tests": {"protocol": ["HTTP GET transport"]}}
    response = _create_run(app_client, cert_fixtures, test_selection=selection)
    assert response.status_code == 201, response.text
    run_id = response.json()["id"]
    detail = app_client.get(f"/api/test-runs/{run_id}").json()
    assert detail["config"]["resolved_test_selection"] == {"protocol": ["HTTP GET transport"]}


def test_run_rejects_unknown_custom_selection(app_client, cert_fixtures):
    selection = {"mode": "custom", "tests": {"protocol": ["No such test"]}}
    response = _create_run(app_client, cert_fixtures, test_selection=selection)
    assert response.status_code == 400
    assert "Unknown test" in response.json()["detail"]


def test_run_resolves_global_selection(app_client, cert_fixtures):
    stored = {"security": ["Nonce echo in response"]}
    assert (
        app_client.put("/api/settings/test-selection", json={"tests": stored}).status_code == 200
    )
    response = _create_run(app_client, cert_fixtures, test_selection={"mode": "global", "tests": {}})
    assert response.status_code == 201, response.text
    run_id = response.json()["id"]
    detail = app_client.get(f"/api/test-runs/{run_id}").json()
    assert detail["config"]["resolved_test_selection"] == stored

    # Default mode "all" resolves to no restriction.
    response = _create_run(app_client, cert_fixtures)
    detail = app_client.get(f"/api/test-runs/{response.json()['id']}").json()
    assert detail["config"]["resolved_test_selection"] is None


# ------------------------------------------------- save run as profile ----


def test_save_run_as_profile(app_client, cert_fixtures):
    selection = {"mode": "custom", "tests": {"protocol": ["HTTP GET transport"]}}
    response = _create_run(app_client, cert_fixtures, name="baseline", test_selection=selection)
    run_id = response.json()["id"]
    _wait_terminal(app_client, run_id)

    created = app_client.post(
        f"/api/test-runs/{run_id}/profile",
        json={"name": "From run", "description": "saved after the fact"},
    )
    assert created.status_code == 201, created.text
    profile = created.json()
    assert profile["config"]["ocsp_url"] == "http://8.8.8.8/ocsp"
    assert profile["config"]["test_selection"] == selection
    # Run-only bookkeeping must not leak into the profile.
    assert "files" not in profile["config"]
    assert "resolved_test_selection" not in profile["config"]

    # Profile is usable from the profiles API.
    listing = app_client.get("/api/profiles").json()
    assert [p["name"] for p in listing["items"]] == ["From run"]

    # Duplicate names conflict.
    dup = app_client.post(f"/api/test-runs/{run_id}/profile", json={"name": "From run"})
    assert dup.status_code == 409

    missing = app_client.post("/api/test-runs/does-not-exist/profile", json={"name": "x"})
    assert missing.status_code == 404


# ------------------------------------------------- engine selection unit ----


def test_selection_should_run():
    from ocsp_tester import selection

    try:
        assert selection.should_run("anything") is True
        selection.set_active(["HTTP GET transport", "Fetch and parse CRL"])
        assert selection.should_run("HTTP GET transport") is True
        assert selection.should_run("HTTP POST transport") is False
        # Dynamic names match by prefix.
        assert selection.should_run("Fetch and parse CRL: http://crl.example/ca.crl") is True
        assert selection.any_selected("HTTP POST transport", "HTTP GET transport") is True
        assert selection.any_selected("HTTP POST transport") is False
        selection.set_active([])
        assert selection.should_run("HTTP GET transport") is False
    finally:
        selection.set_active(None)
    assert selection.should_run("HTTP POST transport") is True


def test_executor_attach_diagnostics_by_time_window():
    from datetime import datetime, timedelta

    from backend.app.worker.executor import RunExecutor
    from ocsp_tester.models import TestCaseResult, TestStatus

    r1 = TestCaseResult(id="1", category="Protocol", name="A", status=TestStatus.PASS)
    r1.started_at = datetime(2026, 1, 1, 0, 0, 0)
    r1.ended_at = datetime(2026, 1, 1, 0, 0, 10)
    r2 = TestCaseResult(id="2", category="Protocol", name="B", status=TestStatus.PASS)
    r2.started_at = datetime(2026, 1, 1, 0, 0, 11)
    r2.ended_at = datetime(2026, 1, 1, 0, 0, 20)

    records = [
        {"kind": "http", "url": "http://x/1", "_started": r1.started_at + timedelta(seconds=1)},
        {"kind": "command", "command": "openssl ocsp", "_started": r2.started_at + timedelta(seconds=2)},
        {"kind": "http", "url": "http://x/orphan", "_started": r2.ended_at + timedelta(seconds=5)},
    ]
    RunExecutor._attach_diagnostics(object.__new__(RunExecutor), [r1, r2], records)

    assert [h["url"] for h in r1.details["diagnostics"]["http"]] == ["http://x/1"]
    assert "commands" not in r1.details["diagnostics"]
    assert [c["command"] for c in r2.details["diagnostics"]["commands"]] == ["openssl ocsp"]
    # The private timestamp key never reaches the stored payload.
    assert all("_started" not in h for h in r1.details["diagnostics"]["http"])
