from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.app.worker.analysis import enrich_result

RUN_CONFIG = {"nonce_enabled": True, "nonce_length": 32, "max_age_hours": 24}


def _result(status="PASS", details=None, name="test", category="Protocol"):
    return {
        "id": "x",
        "category": category,
        "name": name,
        "status": status,
        "message": "",
        "details": details or {},
    }


def _fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_stale_next_update_downgrades_to_warn():
    past = _fmt(datetime.now(timezone.utc) - timedelta(hours=2))
    enriched = enrich_result(_result(details={"next_update": past}), RUN_CONFIG)
    assert enriched["status"] == "WARN"
    assert any("nextUpdate" in w for w in enriched["details"]["warnings"])


def test_fresh_response_stays_pass():
    future = _fmt(datetime.now(timezone.utc) + timedelta(hours=4))
    recent = _fmt(datetime.now(timezone.utc) - timedelta(minutes=10))
    enriched = enrich_result(
        _result(details={"next_update": future, "this_update": recent}), RUN_CONFIG
    )
    assert enriched["status"] == "PASS"
    assert "warnings" not in enriched["details"]


def test_nonce_not_echoed_warns():
    enriched = enrich_result(_result(details={"nonce_echoed": False}), RUN_CONFIG)
    assert enriched["status"] == "WARN"
    assert any("RFC 9654" in w for w in enriched["details"]["warnings"])


def test_deprecated_signature_algorithm_warns():
    enriched = enrich_result(
        _result(details={"signature_algorithm_oid": "1.2.840.113549.1.1.5"}), RUN_CONFIG
    )
    assert enriched["status"] == "WARN"
    assert any("sha1WithRSAEncryption" in w for w in enriched["details"]["warnings"])


def test_fail_status_is_not_upgraded_or_masked():
    past = _fmt(datetime.now(timezone.utc) - timedelta(hours=2))
    enriched = enrich_result(_result(status="FAIL", details={"next_update": past}), RUN_CONFIG)
    assert enriched["status"] == "FAIL"


def test_rfc_refs_added_by_category():
    enriched = enrich_result(_result(category="IKEv2"), RUN_CONFIG)
    assert any("RFC 4806" in ref for ref in enriched["details"]["rfc_refs"])
