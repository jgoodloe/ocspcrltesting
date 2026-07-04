"""Tests for engine log-level prefix mapping (issue #10)."""

from __future__ import annotations

from backend.app.worker.loglevels import split_level_prefix


def test_split_level_prefix_maps_levels():
    assert split_level_prefix("[DEBUG] chain depth 0") == ("DEBUG", "chain depth 0")
    assert split_level_prefix("[INFO] starting tests") == ("INFO", "starting tests")
    assert split_level_prefix("[WARN] stale CRL") == ("WARN", "stale CRL")
    assert split_level_prefix("[WARNING] stale CRL") == ("WARN", "stale CRL")
    assert split_level_prefix("[ERROR] boom") == ("ERROR", "boom")
    assert split_level_prefix("[error] boom") == ("ERROR", "boom")


def test_split_level_prefix_passthrough():
    # No prefix: level defaults, message untouched.
    assert split_level_prefix("plain message") == ("INFO", "plain message")
    # Unknown bracket token is not a level; leave it in the message.
    assert split_level_prefix("[NETGUARD] blocked") == ("INFO", "[NETGUARD] blocked")
    # Only the leading prefix is stripped.
    assert split_level_prefix("[DEBUG] keep [INFO] inner") == ("DEBUG", "keep [INFO] inner")
