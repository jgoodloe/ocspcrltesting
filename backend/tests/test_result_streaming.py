"""Per-test result streaming (issue #1): the engine invokes an on_result
callback as each result is produced, and the worker emits them one at a time
instead of in per-category batches."""

from __future__ import annotations

import json

from ocsp_tester.models import ResultSink, TestCaseResult, TestStatus, result_sink
from ocsp_tester.tests_ikev2 import run_ikev2_tests


def _mk(name: str) -> TestCaseResult:
    r = TestCaseResult(id=name, category="X", name=name, status=TestStatus.PASS)
    r.end()
    return r


def test_result_sink_streams_and_is_a_list():
    seen = []
    sink = result_sink(seen.append)
    assert isinstance(sink, ResultSink)
    a, b = _mk("a"), _mk("b")
    sink.append(a)
    sink.append(b)
    assert seen == [a, b]          # callback fired per append, in order
    assert list(sink) == [a, b]    # still behaves as an ordinary list


def test_result_sink_without_callback_is_plain_list():
    sink = result_sink()
    sink.append(_mk("x"))
    assert len(sink) == 1  # no callback, no error


def test_engine_module_streams_each_result():
    """A network-free category (ikev2, all SKIP) streams every result via
    on_result, and the streamed items match the returned list exactly."""
    streamed = []
    returned = run_ikev2_tests(on_result=streamed.append)
    assert len(returned) == 4
    assert [r.name for r in streamed] == [r.name for r in returned]


def test_executor_emits_per_test_not_per_category(tmp_path, monkeypatch, cert_fixtures):
    from backend.app.worker import diagnostics, executor as ex, netguard

    # Keep the test offline: no global net-guard / diagnostics patching.
    monkeypatch.setattr(netguard, "install", lambda *a, **k: None)
    monkeypatch.setattr(diagnostics, "install", lambda *a, **k: None)

    def fake_protocol(ocsp_url, issuer, leaf, on_result=None):
        out = []
        for name in ("proto-1", "proto-2", "proto-3"):
            r = TestCaseResult(id=name, category="Protocol", name=name, status=TestStatus.PASS)
            r.end()
            out.append(r)
            if on_result is not None:
                on_result(r)  # stream as produced
        return out

    monkeypatch.setattr(ex, "run_protocol_tests", fake_protocol)

    issuer_path = tmp_path / "issuer.pem"
    issuer_path.write_bytes(cert_fixtures["ca_pem"])
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "job.json").write_text(
        json.dumps(
            {
                "run_id": "r1",
                "config": {"ocsp_url": "http://8.8.8.8/ocsp", "categories": {"protocol": True}},
                "files": {"issuer_cert": str(issuer_path)},
                "policy": {"allow_private": True},
            }
        ),
        encoding="utf-8",
    )

    events = []
    ex.RunExecutor(run_dir, lambda t, p: events.append((t, p))).run()

    result_names = [p["result"]["name"] for (t, p) in events if t == "result"]
    # Each test emitted exactly once (no per-category re-emit / duplication).
    assert result_names == ["proto-1", "proto-2", "proto-3"]
    assert any(t == "done" and p.get("status") == "completed" for (t, p) in events)
