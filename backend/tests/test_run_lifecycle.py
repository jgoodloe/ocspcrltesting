from __future__ import annotations

import csv
import io
import json
import time

from .conftest import base_run_config


def _create_run(app_client, cert_fixtures, **config_overrides):
    config = base_run_config(**config_overrides)
    files = {
        "issuer_cert": ("issuer.pem", cert_fixtures["ca_pem"]),
        "good_cert": ("leaf.der", cert_fixtures["leaf_der"]),
    }
    return app_client.post("/api/test-runs", data={"config": json.dumps(config)}, files=files)


def _wait_terminal(app_client, run_id, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = app_client.get(f"/api/test-runs/{run_id}").json()
        if body["status"] in ("completed", "failed", "cancelled", "timed_out"):
            return body
        time.sleep(0.1)
    raise AssertionError(f"run {run_id} did not finish; last status {body['status']}")


def test_full_run_lifecycle(app_client, cert_fixtures):
    response = _create_run(app_client, cert_fixtures)
    assert response.status_code == 201, response.text
    run = response.json()
    run_id = run["id"]
    assert run["status"] in ("queued", "running")

    final = _wait_terminal(app_client, run_id)
    assert final["status"] == "completed"
    assert final["totals"] == {"total": 2, "pass": 1, "fail": 1}
    assert final["latency"]["median_ms"] == 42

    # Results endpoint with filters
    results = app_client.get(f"/api/test-runs/{run_id}/results").json()
    assert results["total"] == 2
    only_fail = app_client.get(f"/api/test-runs/{run_id}/results?status=FAIL").json()
    assert only_fail["total"] == 1
    assert only_fail["items"][0]["category"] == "Status"
    search = app_client.get(f"/api/test-runs/{run_id}/results?q=GET transport").json()
    assert search["total"] == 1

    # Logs persisted
    logs = app_client.get(f"/api/test-runs/{run_id}/logs").json()
    messages = [line["message"] for line in logs["items"]]
    assert "fake worker starting" in messages
    assert logs["last_seq"] >= len(logs["items"])

    # Uploaded config is sanitized and reported
    detail = app_client.get(f"/api/test-runs/{run_id}").json()
    assert detail["config"]["ocsp_url"] == "http://8.8.8.8/ocsp"
    assert detail["config"]["files"]["issuer_cert"] == "issuer.pem"

    # Cancel after completion conflicts
    assert app_client.post(f"/api/test-runs/{run_id}/cancel").status_code == 409

    # Listing includes the run
    listing = app_client.get("/api/test-runs").json()
    assert listing["total"] == 1

    # Delete removes everything
    assert app_client.delete(f"/api/test-runs/{run_id}").status_code == 204
    assert app_client.get(f"/api/test-runs/{run_id}").status_code == 404


def test_worker_crash_marks_run_failed(app_client, cert_fixtures):
    response = _create_run(app_client, cert_fixtures, name="crash")
    run_id = response.json()["id"]
    final = _wait_terminal(app_client, run_id)
    assert final["status"] == "failed"
    assert "simulated crash" in (final["error"] or "")


def test_cancel_hanging_run(app_client, cert_fixtures):
    response = _create_run(app_client, cert_fixtures, name="hang")
    run_id = response.json()["id"]
    time.sleep(0.5)
    cancel = app_client.post(f"/api/test-runs/{run_id}/cancel")
    assert cancel.status_code == 200
    final = _wait_terminal(app_client, run_id, timeout=20.0)
    assert final["status"] == "cancelled"


def test_ssrf_blocked_url_rejected(app_client, cert_fixtures):
    response = _create_run(app_client, cert_fixtures, ocsp_url="http://127.0.0.1/ocsp")
    assert response.status_code == 403
    assert "Blocked outbound request" in response.json()["detail"]


def test_invalid_issuer_rejected(app_client):
    config = base_run_config()
    response = app_client.post(
        "/api/test-runs",
        data={"config": json.dumps(config)},
        files={"issuer_cert": ("issuer.pem", b"not a cert")},
    )
    assert response.status_code == 400
    assert "issuer_cert" in response.json()["detail"]


def test_invalid_config_rejected(app_client, cert_fixtures):
    response = app_client.post(
        "/api/test-runs",
        data={"config": json.dumps({"ocsp_url": "not-a-url"})},
        files={"issuer_cert": ("issuer.pem", cert_fixtures["ca_pem"])},
    )
    assert response.status_code == 400


def test_stream_replay_sse(app_client, cert_fixtures):
    response = _create_run(app_client, cert_fixtures)
    run_id = response.json()["id"]
    _wait_terminal(app_client, run_id)

    with app_client.stream("GET", f"/api/test-runs/{run_id}/stream/sse") as stream:
        payloads = []
        for line in stream.iter_lines():
            if line.startswith("data: ") and line != "data: {}":
                payloads.append(json.loads(line[len("data: "):]))
            if line.startswith("event: end"):
                break
    types = [p["type"] for p in payloads]
    assert "log" in types
    assert "result" in types
    assert types[-1] == "run_status"
    assert payloads[-1]["data"]["status"] == "completed"
    seqs = [p["seq"] for p in payloads]
    assert seqs == sorted(seqs)


def test_exports(app_client, cert_fixtures):
    response = _create_run(app_client, cert_fixtures)
    run_id = response.json()["id"]
    _wait_terminal(app_client, run_id)

    json_export = app_client.get(f"/api/test-runs/{run_id}/export/json")
    assert json_export.status_code == 200
    assert "attachment" in json_export.headers["content-disposition"]
    payload = json_export.json()
    assert payload["run"]["id"] == run_id
    assert len(payload["results"]) == 2
    assert any("fake worker" in log["message"] for log in payload["logs"])

    csv_export = app_client.get(f"/api/test-runs/{run_id}/export/csv")
    assert csv_export.status_code == 200
    rows = list(csv.DictReader(io.StringIO(csv_export.text)))
    assert len(rows) == 2
    assert {row["status"] for row in rows} == {"PASS", "FAIL"}
    assert rows[0]["category"] in ("Protocol", "Status")
