"""producedAt freshness threshold (issue #40): only warn once the OCSP
response's producedAt is older than 18 hours; a few hours is routine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ocsp_tester.tests_crl import _produced_at_issue

NOW = datetime(2026, 7, 6, 2, 0, 0, tzinfo=timezone.utc)


def test_recent_produced_at_does_not_warn():
    # The report's example: ~3h34m old must not warn.
    assert _produced_at_issue(NOW - timedelta(hours=3, minutes=34), NOW) is None
    assert _produced_at_issue(NOW - timedelta(hours=17, minutes=59), NOW) is None


def test_between_18_and_24_hours_warns():
    assert _produced_at_issue(NOW - timedelta(hours=19), NOW) == "producedAt somewhat old"


def test_older_than_24_hours_is_critical():
    assert _produced_at_issue(NOW - timedelta(hours=25), NOW) == "producedAt very old"


def test_future_produced_at_flagged():
    assert _produced_at_issue(NOW + timedelta(minutes=5), NOW) == "producedAt in future"
