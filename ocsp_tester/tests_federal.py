"""Federal PKI / Federal Bridge test category.

Wraps the Federal-PKI-specific capabilities that already exist in
``OCSPMonitor`` (federal environment detection, DHS CA4 batch response
handling, OCSP signer trust-chain verification, delegated responder EKU
validation, response validity interval checks) into standard
``TestCaseResult`` objects so they can run as a first-class test category.
"""

import os
import subprocess
import tempfile
import uuid
from typing import Any, Callable, List, Optional

from .models import TestCaseResult, TestStatus
from .monitor import OCSPMonitor


def _new_result(name: str) -> TestCaseResult:
    return TestCaseResult(
        id=str(uuid.uuid4()),
        category="Federal PKI",
        name=name,
        status=TestStatus.ERROR,
    )


def _fetch_ocsp_response_text(
    cert_path: str, issuer_path: str, ocsp_url: str, timeout: int = 30
) -> str:
    """Fetch an OCSP response as OpenSSL text output (the format the
    OCSPMonitor federal helpers parse)."""
    cmd = [
        "openssl", "ocsp",
        "-issuer", issuer_path,
        "-cert", cert_path,
        "-url", ocsp_url,
        "-resp_text",
        "-noverify",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return (proc.stdout or "") + (proc.stderr or "")


def run_federal_tests(
    ocsp_url: str,
    issuer_path: str,
    cert_path: Optional[str],
    responder_cert_path: Optional[str] = None,
    config: Optional[Any] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> List[TestCaseResult]:
    results: List[TestCaseResult] = []
    log = log_callback or (lambda _msg: None)
    monitor = OCSPMonitor(log_callback=log, config=config)

    sample_cert_path = cert_path or issuer_path

    # Shared OCSP response text used by the text-analysis tests below.
    response_text = ""
    fetch_error: Optional[str] = None
    try:
        response_text = _fetch_ocsp_response_text(sample_cert_path, issuer_path, ocsp_url)
    except Exception as exc:
        fetch_error = str(exc)

    # 1. Federal PKI environment detection
    r = _new_result("Federal PKI environment detection")
    try:
        info = monitor._detect_federal_pki_environment(response_text, ocsp_url)
        r.status = TestStatus.PASS
        if info.get("is_federal_pki"):
            r.message = (
                f"Federal PKI environment detected: agency={info.get('agency')}"
                + (f", CA={info.get('ca_name')}" if info.get("ca_name") else "")
            )
        else:
            r.message = "No Federal PKI environment indicators detected"
        r.details.update({"federal_pki": info, "fetch_error": fetch_error})
    except Exception as exc:
        r.message = f"Federal PKI detection failed: {exc}"
    r.end()
    results.append(r)

    # 2. Batch OCSP response handling (DHS CA4 / DoD style responders)
    r = _new_result("Batch OCSP response handling (DHS CA4 style)")
    try:
        batch = monitor._detect_batch_ocsp_response(response_text)
        if not batch:
            r.status = TestStatus.SKIP
            r.message = "Responder returned a single-certificate response (no batch handling required)"
        else:
            r.status = TestStatus.PASS
            r.message = f"Batch response detected with {len(batch)} certificate entries"
            target_serial = None
            try:
                serial_cmd = ["openssl", "x509", "-in", sample_cert_path, "-noout", "-serial"]
                proc = subprocess.run(serial_cmd, capture_output=True, text=True, timeout=15)
                if proc.returncode == 0 and "=" in proc.stdout:
                    target_serial = proc.stdout.strip().split("=", 1)[1]
            except Exception:
                pass
            if target_serial:
                parsed = monitor._parse_batch_ocsp_response(response_text, target_serial, batch)
                r.details.update({"target_serial": target_serial, "matched_entry": parsed})
            r.details.update({"batch_entries": batch})
    except Exception as exc:
        r.message = f"Batch response analysis failed: {exc}"
    r.end()
    results.append(r)

    # 3. OCSP signer signature verification with trust chain building
    r = _new_result("OCSP signer signature verification (trust chain)")
    try:
        verified = monitor.verify_ocsp_signature(sample_cert_path, issuer_path, ocsp_url)
        r.status = TestStatus.PASS if verified else TestStatus.FAIL
        r.message = (
            "OCSP response signature verified against trust chain"
            if verified
            else "OCSP response signature could not be verified against the provided trust material"
        )
        r.details.update({
            "verified": verified,
            "rfc_refs": ["RFC 6960 §3.2 (response signature acceptance requirements)"],
        })
    except Exception as exc:
        r.message = f"Signature verification failed: {exc}"
    r.end()
    results.append(r)

    # 4. Delegated responder certificate EKU (id-kp-OCSPSigning)
    r = _new_result("Delegated responder EKU (id-kp-OCSPSigning)")
    temp_signer_path: Optional[str] = None
    try:
        signer_path = responder_cert_path
        if not signer_path and response_text:
            extracted = monitor._extract_ocsp_signer_certificate(response_text)
            if extracted:
                if os.path.exists(extracted):
                    signer_path = extracted
                elif "BEGIN CERTIFICATE" in extracted:
                    fd, temp_signer_path = tempfile.mkstemp(suffix=".pem", prefix="ocsp_signer_")
                    with os.fdopen(fd, "w") as f:
                        f.write(extracted)
                    signer_path = temp_signer_path
        if not signer_path:
            r.status = TestStatus.SKIP
            r.message = (
                "No delegated responder certificate available (response may be "
                "CA-signed rather than delegated)"
            )
        else:
            validation = monitor.validate_ca_designated_responder(signer_path, issuer_path)
            has_eku = validation.get("has_ocsp_signing_eku", False)
            is_valid = validation.get("is_valid_designated_responder", False)
            if is_valid:
                r.status = TestStatus.PASS
                r.message = "Delegated responder certificate satisfies RFC 6960 designated responder requirements"
            elif has_eku:
                r.status = TestStatus.WARN
                r.message = "Responder has id-kp-OCSPSigning EKU but other designated-responder checks failed"
            else:
                r.status = TestStatus.FAIL
                r.message = "Delegated responder certificate missing id-kp-OCSPSigning EKU (RFC 6960 §4.2.2.2)"
            r.details.update({
                "validation": validation,
                "rfc_refs": ["RFC 6960 §4.2.2.2 (Authorized Responders)"],
            })
    except Exception as exc:
        r.message = f"Delegated responder validation failed: {exc}"
    finally:
        if temp_signer_path:
            try:
                os.remove(temp_signer_path)
            except OSError:
                pass
    r.end()
    results.append(r)

    # 5. Response validity interval per Federal PKI operational expectations
    r = _new_result("Response validity interval (freshness)")
    try:
        max_age_hours = getattr(config, "max_age_hours", 24) if config else 24
        interval = monitor.validate_response_validity_interval(response_text, max_age_hours=max_age_hours)
        valid = interval.get("interval_valid", interval.get("is_valid", False))
        warnings = interval.get("security_warnings", []) or interval.get("warnings", [])
        if valid and not warnings:
            r.status = TestStatus.PASS
            r.message = "thisUpdate/nextUpdate interval is present, plausible and current"
        elif valid and warnings:
            r.status = TestStatus.WARN
            r.message = f"Interval valid but with warnings: {'; '.join(str(w) for w in warnings[:3])}"
        else:
            r.status = TestStatus.FAIL
            r.message = "Response validity interval failed RFC 6960 freshness checks"
        r.details.update({
            "interval": interval,
            "max_age_hours": max_age_hours,
            "rfc_refs": ["RFC 6960 §4.2.2.1 (Time)", "RFC 5019 §4 (small-profile freshness)"],
        })
    except Exception as exc:
        r.message = f"Validity interval analysis failed: {exc}"
    r.end()
    results.append(r)

    return results
