"""Test run executor — runs inside the per-run worker subprocess.

Reads the job manifest written by the API layer, executes the selected
engine test categories sequentially, and emits JSONL events (log, progress,
result, done/fatal) that the parent process persists and streams to clients.
"""

from __future__ import annotations

import json
import statistics
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional

from ocsp_tester import ocsp_client, selection
from ocsp_tester.models import TestCaseResult, TestStatus
from ocsp_tester.runner import _load_cert
from ocsp_tester.tests_crl import run_crl_tests
from ocsp_tester.tests_crl_comprehensive import run_crl_tests as run_crl_comprehensive_tests
from ocsp_tester.tests_federal import run_federal_tests
from ocsp_tester.tests_ikev2 import run_ikev2_tests
from ocsp_tester.tests_path_validation import run_path_validation_tests
from ocsp_tester.tests_performance import run_perf_tests
from ocsp_tester.tests_protocol import run_protocol_tests
from ocsp_tester.tests_security import run_security_tests
from ocsp_tester.tests_status import run_status_tests

from ..ssrf import BlockedTargetError, NetworkPolicy, validate_url
from . import diagnostics, netguard
from .analysis import enrich_result
from .loglevels import split_level_prefix

Emit = Callable[[str, Dict[str, Any]], None]

CATEGORY_LABELS = {
    "protocol": "OCSP protocol tests",
    "status": "Certificate status tests",
    "security": "Security & error handling tests (OCSP)",
    "performance": "Performance tests (OCSP)",
    "crl": "CRL tests",
    "ikev2": "IKEv2 tests",
    "federal": "Federal PKI / Federal Bridge tests",
    "path_validation": "Certificate path validation tests",
}

CATEGORY_ORDER = ["protocol", "status", "crl", "path_validation", "ikev2", "federal", "performance", "security"]


class RunCancelled(Exception):
    pass


def serialize_result(r: TestCaseResult) -> Dict[str, Any]:
    return {
        "id": r.id,
        "category": r.category,
        "name": r.name,
        "status": r.status.value,
        "message": r.message,
        "details": _json_safe(r.details),
        "started_at": r.started_at.isoformat() + ("" if r.started_at.tzinfo else "Z"),
        "ended_at": (r.ended_at.isoformat() + ("" if r.ended_at.tzinfo else "Z")) if r.ended_at else None,
        "duration_ms": r.duration_ms,
    }


def _json_safe(obj: Any) -> Any:
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        if isinstance(obj, dict):
            return {str(k): _json_safe(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_json_safe(v) for v in obj]
        return str(obj)


class RunExecutor:
    def __init__(self, run_dir: Path, emit: Emit):
        self.run_dir = run_dir
        self.emit = emit
        manifest = json.loads((run_dir / "job.json").read_text(encoding="utf-8"))
        self.run_id: str = manifest["run_id"]
        self.config: Dict[str, Any] = manifest["config"]
        self.files: Dict[str, Optional[str]] = manifest.get("files", {})
        self.policy = NetworkPolicy(**manifest["policy"])
        self.latencies: List[int] = []

    # ---- helpers -------------------------------------------------------

    def log(self, level: str, message: str) -> None:
        # Defensive scrub: never allow key material into the log stream.
        if "PRIVATE KEY" in message:
            message = "[REDACTED: private key material]"
        self.emit("log", {"level": level, "message": message})

    def _engine_log(self, message: str) -> None:
        level, text = split_level_prefix(message.rstrip("\n"))
        self.log(level, text)

    def _check_cancel(self) -> None:
        if (self.run_dir / "cancel").exists():
            raise RunCancelled()

    def _collect_latencies(self, result: Dict[str, Any]) -> None:
        details = result.get("details", {})
        for key in ("latency_ms", "a_latency_ms", "b_latency_ms"):
            value = details.get(key)
            if isinstance(value, (int, float)):
                self.latencies.append(int(value))
        for value in details.get("latencies_ms", []) or []:
            if isinstance(value, (int, float)):
                self.latencies.append(int(value))

    def _emit_results(self, results: List[TestCaseResult]) -> None:
        for r in results:
            payload = enrich_result(serialize_result(r), self.config)
            self._collect_latencies(payload)
            self.emit("result", {"result": payload})

    def _attach_diagnostics(self, results: List[TestCaseResult], records: List[Dict[str, Any]]) -> None:
        """Attach recorded HTTP exchanges / commands to the test result whose
        execution window contains them (tests run sequentially, so start-time
        containment is unambiguous)."""
        if not records:
            return
        for r in results:
            end = r.ended_at or datetime.utcnow()
            matched = [
                rec for rec in records
                if rec.get("_started") is not None and r.started_at <= rec["_started"] <= end
            ]
            if not matched:
                continue
            http = [{k: v for k, v in rec.items() if k != "_started"} for rec in matched if rec.get("kind") == "http"]
            commands = [
                {k: v for k, v in rec.items() if k != "_started"} for rec in matched if rec.get("kind") == "command"
            ]
            diag: Dict[str, Any] = {}
            if http:
                diag["http"] = http[:25]
            if commands:
                diag["commands"] = commands[:25]
            if diag:
                r.details["diagnostics"] = diag

    def _error_result(self, category: str, name: str, message: str) -> TestCaseResult:
        r = TestCaseResult(id=str(uuid.uuid4()), category=category, name=name, status=TestStatus.ERROR, message=message)
        r.end()
        return r

    def latency_summary(self) -> Dict[str, Any]:
        if not self.latencies:
            return {"samples": 0}
        return {
            "median_ms": int(statistics.median(self.latencies)),
            "min_ms": min(self.latencies),
            "max_ms": max(self.latencies),
            "samples": len(self.latencies),
        }

    # ---- category runners ---------------------------------------------

    def _engine_config(self) -> SimpleNamespace:
        return SimpleNamespace(
            max_age_hours=self.config.get("max_age_hours", 24),
            test_cryptographic_preferences=True,
            test_non_issued_certificates=True,
        )

    def run(self) -> None:
        cfg = self.config
        issuer_path = self.files.get("issuer_cert")
        if not issuer_path:
            raise RuntimeError("Issuer certificate missing from job manifest")

        # Apply user-selected request options to all engine traffic.
        ocsp_client.RUNTIME.timeout = int(cfg.get("timeout_seconds", 10))
        method = cfg.get("request_method", "auto")
        ocsp_client.RUNTIME.method = method.upper() if method in ("get", "post") else None
        ocsp_client.RUNTIME.include_nonce = bool(cfg.get("nonce_enabled", True))
        ocsp_client.RUNTIME.nonce_len = int(cfg.get("nonce_length", 32))

        netguard.install(self.policy, self.log)
        # Record every outbound HTTP exchange and external command for
        # troubleshooting; layered after netguard so records reflect policy.
        diagnostics.install(self.log)

        ocsp_url = cfg["ocsp_url"]
        self.log("INFO", f"Run {self.run_id} starting against {ocsp_url}")

        # Pre-flight: fail fast (as a normal ERROR result) if targets violate policy.
        setup_results: List[TestCaseResult] = []
        try:
            validate_url(ocsp_url, self.policy)
            for crl_url in cfg.get("crl_urls", []):
                validate_url(crl_url, self.policy)
        except BlockedTargetError as exc:
            self.log("ERROR", f"[NETGUARD] {exc}")
            setup_results.append(self._error_result("Setup", "Outbound target policy check", str(exc)))
            self._emit_results(setup_results)
            self.emit("done", {"status": "failed", "error": str(exc), "latency": self.latency_summary()})
            return

        issuer = _load_cert(issuer_path)
        good = _load_cert(self.files["good_cert"]) if self.files.get("good_cert") else None
        revoked = _load_cert(self.files["revoked_cert"]) if self.files.get("revoked_cert") else None
        unknown_ca = _load_cert(self.files["unknown_ca_cert"]) if self.files.get("unknown_ca_cert") else None
        sample = good or revoked or issuer

        enabled = [k for k in CATEGORY_ORDER if cfg.get("categories", {}).get(k)]
        total = len(enabled)
        self.log("INFO", f"Enabled categories: {', '.join(CATEGORY_LABELS[k] for k in enabled) or 'none'}")

        # Fine-grained selection resolved by the API at submission time:
        # {category: [test name, ...]}; a missing category runs everything.
        selection_map = cfg.get("resolved_test_selection")
        if not isinstance(selection_map, dict):
            selection_map = None
        if selection_map:
            self.log("INFO", "Fine-grained test selection is active for this run")

        engine_cfg = self._engine_config()
        crl_urls: List[str] = cfg.get("crl_urls", [])

        runners: Dict[str, Callable[[], List[TestCaseResult]]] = {
            "protocol": lambda: run_protocol_tests(ocsp_url, issuer, sample),
            "status": lambda: run_status_tests(ocsp_url, issuer, good, revoked, unknown_ca),
            "security": lambda: run_security_tests(
                ocsp_url,
                issuer,
                good or sample,
                self.files.get("client_cert"),
                self.files.get("client_key"),
                engine_cfg,
                log_callback=self._engine_log,
            ),
            "performance": lambda: run_perf_tests(
                ocsp_url,
                issuer,
                sample,
                int(cfg.get("latency_samples", 5)),
                bool(cfg.get("enable_load_test", False)),
                int(cfg.get("load_concurrency", 5)),
                int(cfg.get("load_requests", 50)),
            ),
            "crl": lambda: (
                run_crl_tests(ocsp_url, issuer, good, revoked)
                + run_crl_comprehensive_tests(
                    ocsp_url, issuer, good, revoked, crl_urls[0] if crl_urls else None
                )
                + self._explicit_crl_tests(crl_urls)
            ),
            "ikev2": run_ikev2_tests,
            "federal": lambda: run_federal_tests(
                ocsp_url,
                issuer_path,
                self.files.get("good_cert") or self.files.get("revoked_cert"),
                config=engine_cfg,
                log_callback=self._engine_log,
            ),
            "path_validation": lambda: run_path_validation_tests(
                {
                    "ocsp_url": ocsp_url,
                    "issuer_path": issuer_path,
                    "good_cert_path": self.files.get("good_cert"),
                    "revoked_cert_path": self.files.get("revoked_cert"),
                    "unknown_ca_cert_path": self.files.get("unknown_ca_cert"),
                    "crl_override_url": crl_urls[0] if crl_urls else None,
                    "client_cert_path": self.files.get("client_cert"),
                    "client_key_path": self.files.get("client_key"),
                    "trust_anchor_path": self.files.get("trust_anchor"),
                    "trust_anchor_type": cfg.get("trust_anchor_type", "root"),
                    "require_explicit_policy": cfg.get("require_explicit_policy", False),
                    "inhibit_policy_mapping": cfg.get("inhibit_policy_mapping", False),
                }
            ),
        }

        done = 0
        for key in enabled:
            self._check_cancel()
            label = CATEGORY_LABELS[key]
            self.emit(
                "progress",
                {
                    "current_activity": f"Running {label}",
                    "categories_done": done,
                    "categories_total": total,
                    "percent": int(done * 100 / total) if total else 100,
                },
            )
            self.log("INFO", f"=== {label} ===")
            selected = None
            if selection_map is not None and key in selection_map:
                selected = [str(n) for n in selection_map[key]]
                self.log("INFO", f"{label}: restricted to {len(selected)} selected test(s)")
            records_before = len(diagnostics.records())
            selection.set_active(selected)
            try:
                results = runners[key]()
            except RunCancelled:
                raise
            except Exception as exc:  # keep the run going; surface as ERROR result
                self.log("ERROR", f"{label} crashed: {exc}")
                self.log("DEBUG", traceback.format_exc())
                results = [self._error_result(CATEGORY_LABELS[key].split(" tests")[0], f"Run {label}", str(exc))]
            finally:
                selection.set_active(None)
            if selected is not None:
                # Safety net in case an engine module misses a guard.
                selected_set = set(selected)
                results = [r for r in results if selection.matches(r.name, selected_set)]
            self._attach_diagnostics(results, diagnostics.records()[records_before:])
            self._emit_results(results)
            done += 1
            self.emit(
                "progress",
                {
                    "current_activity": f"Finished {label}",
                    "categories_done": done,
                    "categories_total": total,
                    "percent": int(done * 100 / total) if total else 100,
                },
            )

        self.emit("done", {"status": "completed", "latency": self.latency_summary()})
        self.log("INFO", "Run complete")

    def _explicit_crl_tests(self, crl_urls: List[str]) -> List[TestCaseResult]:
        """Fetch/parse checks for each explicitly supplied CRL URL."""
        import requests
        from cryptography import x509 as cx509

        results: List[TestCaseResult] = []
        for url in crl_urls:
            name = f"Fetch and parse CRL: {url}"
            if not selection.should_run(name):
                continue
            r = TestCaseResult(id=str(uuid.uuid4()), category="CRL", name=name, status=TestStatus.ERROR)
            try:
                resp = requests.get(url, timeout=self.policy.max_timeout_seconds)
                resp.raise_for_status()
                data = resp.content
                try:
                    crl = cx509.load_der_x509_crl(data)
                except Exception:
                    crl = cx509.load_pem_x509_crl(data)
                now = datetime.now(timezone.utc)
                next_update = getattr(crl, "next_update_utc", None)
                revoked_count = len(list(crl))
                current = next_update is None or next_update > now
                r.status = TestStatus.PASS if current else TestStatus.WARN
                r.message = (
                    f"CRL fetched ({len(data)} bytes), issuer={crl.issuer.rfc4514_string()}, "
                    f"{revoked_count} revoked entries"
                    + ("" if current else " — CRL nextUpdate has passed")
                )
                r.details.update(
                    {
                        "crl_url": url,
                        "size_bytes": len(data),
                        "issuer": crl.issuer.rfc4514_string(),
                        "revoked_count": revoked_count,
                        "last_update": getattr(crl, "last_update_utc", None),
                        "next_update": next_update,
                        "rfc_refs": ["RFC 5280 §5 (CRL profile)"],
                    }
                )
            except BlockedTargetError as exc:
                r.status = TestStatus.ERROR
                r.message = f"Blocked by network policy: {exc.reason}"
            except Exception as exc:
                r.status = TestStatus.FAIL
                r.message = f"CRL fetch/parse failed: {exc}"
            r.end()
            results.append(r)
        return results
