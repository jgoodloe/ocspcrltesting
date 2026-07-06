from __future__ import annotations

import pytest

from backend.app import ssrf
from backend.app.ssrf import BlockedTargetError, NetworkPolicy, guarded_fetch, validate_url

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


# --- guarded_fetch: redirect hops must be re-validated (issue #28) ----------


class _FakeResponse:
    def __init__(self, *, status=200, location=None, body=b""):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self._body = body
        self.closed = False

    @property
    def is_redirect(self):
        return "Location" in self.headers and self.status_code in (301, 302, 303, 307, 308)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=65536):
        yield self._body

    def close(self):
        self.closed = True


def _install_fake_requests(monkeypatch, responder):
    """Patch requests.get (imported lazily inside guarded_fetch) with a fake
    that returns whatever ``responder(url)`` yields — no real network."""
    import requests

    def fake_get(url, timeout=None, stream=None, allow_redirects=None):
        assert allow_redirects is False, "guarded_fetch must disable auto-redirects"
        return responder(url)

    monkeypatch.setattr(requests, "get", fake_get)


def test_guarded_fetch_revalidates_redirect_to_metadata(monkeypatch):
    """A public URL that 302-redirects to the metadata IP must be blocked at
    the redirect hop, not silently followed."""

    def responder(url):
        if url == "http://ok.example/x":
            return _FakeResponse(status=302, location="http://169.254.169.254/latest/meta-data/")
        return _FakeResponse(body=b"should-never-be-reached")

    _install_fake_requests(monkeypatch, responder)
    with pytest.raises(BlockedTargetError):
        guarded_fetch("http://ok.example/x", STRICT, timeout=5, max_bytes=1024)


def test_guarded_fetch_revalidates_redirect_to_private(monkeypatch):
    def responder(url):
        if "attacker" in url:
            return _FakeResponse(status=301, location="http://10.0.0.5/internal")
        return _FakeResponse(body=b"nope")

    _install_fake_requests(monkeypatch, responder)
    with pytest.raises(BlockedTargetError):
        guarded_fetch("http://attacker.example/redir", STRICT, timeout=5, max_bytes=1024)


def test_guarded_fetch_allows_public_no_redirect(monkeypatch):
    def responder(url):
        return _FakeResponse(body=b"cert-bytes")

    _install_fake_requests(monkeypatch, responder)
    assert guarded_fetch("http://8.8.8.8/ca.crt", STRICT, timeout=5, max_bytes=1024) == b"cert-bytes"


def test_guarded_fetch_enforces_size_cap(monkeypatch):
    def responder(url):
        return _FakeResponse(body=b"x" * 5000)

    _install_fake_requests(monkeypatch, responder)
    with pytest.raises(ValueError):
        guarded_fetch("http://8.8.8.8/big", STRICT, timeout=5, max_bytes=1024)
