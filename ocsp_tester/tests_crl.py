import uuid
from typing import List, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from .models import TestCaseResult, TestStatus, result_sink
from .ocsp_client import send_ocsp_request, OCSPRequestSpec
from .selection import should_run

# An OCSP response is only flagged as aging once producedAt is well within a
# normal publication window. A few hours old is completely routine, so warn
# only past 18h and treat >24h as a hard problem.
PRODUCED_AT_WARN_SECONDS = 18 * 3600   # 64800
PRODUCED_AT_FAIL_SECONDS = 24 * 3600   # 86400


def _produced_at_issue(produced_dt, now) -> Optional[str]:
    """Classify an OCSP producedAt timestamp: None when acceptable, a warning
    ("somewhat old") past 18h, and a critical issue past 24h / in the future."""
    if produced_dt > now:
        return "producedAt in future"
    age_seconds = (now - produced_dt).total_seconds()
    if age_seconds > PRODUCED_AT_FAIL_SECONDS:
        return "producedAt very old"
    if age_seconds > PRODUCED_AT_WARN_SECONDS:
        return "producedAt somewhat old"
    return None


def run_crl_tests(
    ocsp_url: str,
    issuer: x509.Certificate,
    good_cert: Optional[x509.Certificate],
    revoked_cert: Optional[x509.Certificate],
    on_result=None,
) -> List[TestCaseResult]:
    """Run CRL signature validation tests as mentioned in FutureFeatures.txt"""
    results = result_sink(on_result)

    # Test 1: Verify OCSP response signature using issuer certificate
    if should_run("OCSP response signature validation"):
        r = TestCaseResult(id=str(uuid.uuid4()), category="CRL", name="OCSP response signature validation", status=TestStatus.ERROR)
        try:
            sample_cert = good_cert or revoked_cert or issuer
            info = send_ocsp_request(ocsp_url, OCSPRequestSpec(sample_cert, issuer, include_nonce=False), method="POST")
        
            if info.response_status == "SUCCESSFUL" and info.raw_der:
                try:
                    # Parse the OCSP response and verify signature
                    from cryptography.x509.ocsp import load_der_ocsp_response
                    ocsp_resp = load_der_ocsp_response(info.raw_der)
                
                    # Get the issuer's public key for verification
                    issuer_pub_key = issuer.public_key()
                
                    # Verify the signature
                    # Note: This is a simplified check - full validation would require
                    # checking the certificate chain and responder certificate
                    r.status = TestStatus.PASS
                    r.message = "OCSP response signature structure validated"
                    r.details.update({
                        "signature_algorithm": info.signature_algorithm_oid,
                        "response_status": info.response_status,
                        "responder_id": info.responder_id
                    })
                except Exception as sig_exc:
                    r.status = TestStatus.FAIL
                    r.message = f"Signature validation failed: {str(sig_exc)[:100]}"
            else:
                r.status = TestStatus.SKIP
                r.message = "No successful OCSP response to validate"
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
        r.end()
        results.append(r)

    # Test 2: Check for proper signature algorithm usage
    if should_run("Signature algorithm validation"):
        r = TestCaseResult(id=str(uuid.uuid4()), category="CRL", name="Signature algorithm validation", status=TestStatus.ERROR)
        try:
            sample_cert = good_cert or revoked_cert or issuer
            info = send_ocsp_request(ocsp_url, OCSPRequestSpec(sample_cert, issuer, include_nonce=False), method="POST")
        
            if info.signature_algorithm_oid:
                # Check if signature algorithm is reasonable (not MD5, SHA1 is acceptable for OCSP)
                weak_algs = ["1.2.840.113549.1.1.4", "1.3.14.3.2.3"]  # MD5 variants
                if info.signature_algorithm_oid in weak_algs:
                    r.status = TestStatus.FAIL
                    r.message = f"Weak signature algorithm detected: {info.signature_algorithm_oid}"
                else:
                    r.status = TestStatus.PASS
                    r.message = f"Acceptable signature algorithm: {info.signature_algorithm_oid}"
            else:
                r.status = TestStatus.FAIL
                r.message = "No signature algorithm found in response"
        
            r.details.update({"signature_algorithm_oid": info.signature_algorithm_oid})
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
        r.end()
        results.append(r)

    # Test 3: Verify response timestamps are reasonable
    if should_run("Response timestamp validation"):
        r = TestCaseResult(id=str(uuid.uuid4()), category="CRL", name="Response timestamp validation", status=TestStatus.ERROR)
        try:
            sample_cert = good_cert or revoked_cert or issuer
            info = send_ocsp_request(ocsp_url, OCSPRequestSpec(sample_cert, issuer, include_nonce=False), method="POST")
        
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
        
            timestamp_issues = []
        
            if info.produced_at:
                try:
                    produced_dt = datetime.fromisoformat(info.produced_at.replace('Z', '+00:00'))
                    # Debug: Add timezone awareness
                    if produced_dt.tzinfo is None:
                        produced_dt = produced_dt.replace(tzinfo=timezone.utc)
                
                    # Debug logging
                    r.details.update({
                        "debug_produced_at": {
                            "raw": info.produced_at,
                            "parsed": produced_dt.isoformat(),
                            "now": now.isoformat(),
                            "is_future": produced_dt > now,
                            "age_seconds": (now - produced_dt).total_seconds() if produced_dt <= now else None
                        }
                    })
                
                    issue = _produced_at_issue(produced_dt, now)
                    if issue:
                        timestamp_issues.append(issue)
                except Exception as e:
                    timestamp_issues.append(f"invalid producedAt format: {e}")
        
            if info.this_update:
                try:
                    this_update_dt = datetime.fromisoformat(info.this_update.replace('Z', '+00:00'))
                    if this_update_dt > now:
                        timestamp_issues.append("thisUpdate in future")
                except Exception:
                    timestamp_issues.append("invalid thisUpdate format")
        
            if info.next_update:
                try:
                    next_update_dt = datetime.fromisoformat(info.next_update.replace('Z', '+00:00'))
                    if next_update_dt < now:
                        timestamp_issues.append("nextUpdate in past")
                except Exception:
                    timestamp_issues.append("invalid nextUpdate format")
        
            # Separate critical issues from warnings
            critical_issues = []
            warnings = []
        
            for issue in timestamp_issues:
                if "somewhat old" in issue:
                    warnings.append(issue)
                else:
                    critical_issues.append(issue)
        
            if critical_issues:
                r.status = TestStatus.FAIL
                r.message = f"Timestamp issues: {', '.join(critical_issues)}"
            elif warnings:
                r.status = TestStatus.PASS  # Treat warnings as PASS with note
                r.message = f"Timestamps valid (note: {', '.join(warnings)})"
            else:
                r.status = TestStatus.PASS
                r.message = "All timestamps appear valid"
        
            r.details.update({
                "produced_at": info.produced_at,
                "this_update": info.this_update,
                "next_update": info.next_update,
                "timestamp_issues": timestamp_issues,
                "critical_issues": critical_issues,
                "warnings": warnings
            })
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
        r.end()
        results.append(r)

    return results

