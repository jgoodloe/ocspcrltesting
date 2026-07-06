"""OCSP POST probes use the requests library, not the external curl binary
(issue #8 follow-up: curl was absent from the runtime image → FileNotFoundError)."""

from __future__ import annotations

from types import SimpleNamespace

import ocsp_tester.monitor as monitor_mod
from ocsp_tester.monitor import OCSPMonitor


def _monitor():
    return OCSPMonitor(log_callback=lambda *_: None)


def test_post_helper_success_and_writes_output(tmp_path, monkeypatch):
    captured = {}

    def fake_post(url, data=None, headers=None, timeout=None):
        captured.update(url=url, data=data, headers=headers, timeout=timeout)
        return SimpleNamespace(status_code=200, content=b"resp-bytes")

    monkeypatch.setattr(monitor_mod.requests, "post", fake_post)
    out_file = tmp_path / "r.bin"
    res = _monitor()._post_ocsp_via_requests(
        "http://8.8.8.8/ocsp", data=b"req", output_file=str(out_file), timeout=10
    )
    # Mimics the old `curl -w '%{http_code}' -s -o file` result contract.
    assert res.returncode == 0
    assert res.stdout == "200"
    assert res.content == b"resp-bytes"
    assert out_file.read_bytes() == b"resp-bytes"
    assert captured["headers"]["Content-Type"] == "application/ocsp-request"


def test_post_helper_reads_data_file(tmp_path, monkeypatch):
    captured = {}

    def fake_post(url, data=None, headers=None, timeout=None):
        captured["data"] = data
        return SimpleNamespace(status_code=200, content=b"")

    monkeypatch.setattr(monitor_mod.requests, "post", fake_post)
    req = tmp_path / "req.der"
    req.write_bytes(b"DER-REQUEST")
    res = _monitor()._post_ocsp_via_requests("http://x/ocsp", data_file=str(req))
    assert res.returncode == 0
    assert captured["data"] == b"DER-REQUEST"


def test_post_helper_reports_errors_instead_of_raising(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("no network")

    monkeypatch.setattr(monitor_mod.requests, "post", boom)
    res = _monitor()._post_ocsp_via_requests("http://x/ocsp", data=b"x")
    # No FileNotFoundError, no propagation — a curl-less, graceful failure.
    assert res.returncode == 1
    assert "no network" in res.stderr


def test_no_curl_subprocess_in_engine():
    """The engine must not shell out to the curl binary anywhere."""
    import pathlib

    src = pathlib.Path(monitor_mod.__file__).read_text(encoding="utf-8")
    assert '"curl"' not in src  # a curl-hint *string* in diagnostics is fine; argv is not
