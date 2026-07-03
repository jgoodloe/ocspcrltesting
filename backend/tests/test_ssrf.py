from __future__ import annotations

import pytest

from backend.app.ssrf import BlockedTargetError, NetworkPolicy, validate_url

STRICT = NetworkPolicy(allow_private=False)
LAB = NetworkPolicy(allow_private=True)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/ocsp",
        "http://localhost/ocsp",
        "http://10.1.2.3/ocsp",
        "http://192.168.1.10:8080/ocsp",
        "http://172.16.0.1/ocsp",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/ocsp",
        "ftp://example.com/thing",
        "file:///etc/passwd",
    ],
)
def test_blocked_by_default(url):
    with pytest.raises(BlockedTargetError):
        validate_url(url, STRICT)


def test_public_ip_allowed():
    validate_url("http://8.8.8.8/ocsp", STRICT)


def test_lab_mode_allows_private_but_not_metadata():
    validate_url("http://10.1.2.3/ocsp", LAB)
    validate_url("http://localhost/ocsp", LAB)
    with pytest.raises(BlockedTargetError):
        validate_url("http://169.254.169.254/latest/meta-data/", LAB)


def test_operator_blocklist():
    policy = NetworkPolicy(allow_private=False, blocked_hosts=("evil.example",))
    with pytest.raises(BlockedTargetError) as excinfo:
        validate_url("http://evil.example/ocsp", policy)
    assert "block list" in str(excinfo.value)
