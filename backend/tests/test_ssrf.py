from __future__ import annotations

import ipaddress
import socket

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


# --- IPv4-mapped IPv6 normalization (issue #39) -----------------------------


def test_ipv4_mapped_metadata_blocked_even_in_lab_mode(monkeypatch):
    _stub_resolve(monkeypatch)
    # The mapped spelling of the metadata IP must still be blocked, in lab mode.
    with pytest.raises(BlockedTargetError):
        validate_url("http://[::ffff:169.254.169.254]/latest/meta-data/", LAB)


def test_ipv4_mapped_loopback_blocked_by_default(monkeypatch):
    _stub_resolve(monkeypatch)
    with pytest.raises(BlockedTargetError):
        validate_url("http://[::ffff:127.0.0.1]/x", STRICT)


# --- DNS-pinning resolver for the worker (issue #29) ------------------------


def test_pinning_resolver_filters_blocked_addresses(monkeypatch):
    """Once installed, getaddrinfo only ever returns policy-approved addresses,
    so curl/openssl/requests can only connect to allowed IPs."""

    def fake_getaddrinfo(host, *a, **k):
        ip = "127.0.0.1" if host == "internal" else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    saved = socket.getaddrinfo
    ssrf._resolver_installed = False
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    try:
        ssrf.install_pinning_resolver(STRICT)
        assert socket.getaddrinfo("public", None)  # allowed
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo("internal", None)  # loopback filtered out
    finally:
        socket.getaddrinfo = saved
        ssrf._resolver_installed = False


# --- guarded_fetch: redirect re-validation + IP pinning (issues #28, #29) ----


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


def _stub_resolve(monkeypatch):
    """Offline DNS: IP literals resolve to themselves, names to a fixed public
    IP. Keeps validation deterministic and network-free."""

    def fake_resolve(host):
        try:
            return [ipaddress.ip_address(host)]
        except ValueError:
            return [ipaddress.ip_address("93.184.216.34")]

    monkeypatch.setattr(ssrf, "resolve_host", fake_resolve)


def _install_fake_requests(monkeypatch, responder):
    """Patch requests.get (imported lazily inside guarded_fetch) with a fake
    that returns whatever ``responder(url)`` yields — no real network."""
    import requests

    calls = []

    def fake_get(url, headers=None, timeout=None, stream=None, allow_redirects=None):
        assert allow_redirects is False, "guarded_fetch must disable auto-redirects"
        calls.append((url, headers or {}))
        return responder(url)

    monkeypatch.setattr(requests, "get", fake_get)
    return calls


def test_guarded_fetch_revalidates_redirect_to_metadata(monkeypatch):
    """A public URL that 302-redirects to the metadata IP must be blocked at
    the redirect hop, not silently followed."""
    _stub_resolve(monkeypatch)

    def responder(url):
        if "169.254" in url:
            return _FakeResponse(body=b"should-never-be-reached")
        return _FakeResponse(status=302, location="http://169.254.169.254/latest/meta-data/")

    _install_fake_requests(monkeypatch, responder)
    with pytest.raises(BlockedTargetError):
        guarded_fetch("http://ok.example/x", STRICT, timeout=5, max_bytes=1024)


def test_guarded_fetch_revalidates_redirect_to_private(monkeypatch):
    _stub_resolve(monkeypatch)

    def responder(url):
        if "10.0.0" in url:
            return _FakeResponse(body=b"nope")
        return _FakeResponse(status=301, location="http://10.0.0.5/internal")

    _install_fake_requests(monkeypatch, responder)
    with pytest.raises(BlockedTargetError):
        guarded_fetch("http://attacker.example/redir", STRICT, timeout=5, max_bytes=1024)


def test_guarded_fetch_pins_http_to_validated_ip(monkeypatch):
    """The connection is opened to the validated IP with the original Host
    header — the hostname is not re-resolved by requests."""
    _stub_resolve(monkeypatch)
    calls = _install_fake_requests(monkeypatch, lambda url: _FakeResponse(body=b"cert-bytes"))
    body = guarded_fetch("http://ok.example/ca.crt", STRICT, timeout=5, max_bytes=1024)
    assert body == b"cert-bytes"
    url, headers = calls[0]
    assert url == "http://93.184.216.34/ca.crt"  # pinned to the resolved IP
    assert headers.get("Host") == "ok.example"


def test_guarded_fetch_allows_public_no_redirect(monkeypatch):
    _stub_resolve(monkeypatch)
    _install_fake_requests(monkeypatch, lambda url: _FakeResponse(body=b"cert-bytes"))
    assert guarded_fetch("http://8.8.8.8/ca.crt", STRICT, timeout=5, max_bytes=1024) == b"cert-bytes"


def test_guarded_fetch_enforces_size_cap(monkeypatch):
    _stub_resolve(monkeypatch)
    _install_fake_requests(monkeypatch, lambda url: _FakeResponse(body=b"x" * 5000))
    with pytest.raises(ValueError):
        guarded_fetch("http://8.8.8.8/big", STRICT, timeout=5, max_bytes=1024)
