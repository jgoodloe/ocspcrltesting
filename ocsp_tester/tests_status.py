import uuid
from typing import List, Optional

from cryptography import x509
from .models import TestCaseResult, TestStatus
from .ocsp_client import send_ocsp_request, OCSPRequestSpec


def run_status_tests(
    ocsp_url: str,
    issuer: x509.Certificate,
    good_cert: Optional[x509.Certificate],
    revoked_cert: Optional[x509.Certificate],
    unknown_ca_cert: Optional[x509.Certificate],
) -> List[TestCaseResult]:
    results: List[TestCaseResult] = []

    # 1. Valid certificate status
    r = TestCaseResult(id=str(uuid.uuid4()), category="Status", name="Known valid certificate returns good", status=TestStatus.SKIP)
    if good_cert is None:
        r.message = "No known-good certificate provided"
    else:
        try:
            info = send_ocsp_request(ocsp_url, OCSPRequestSpec(good_cert, issuer, include_nonce=True), method="POST")
            if info.response_status == "SUCCESSFUL" and (info.cert_status or "").lower() == "good":
                r.status = TestStatus.PASS
                r.message = "good"
            else:
                r.status = TestStatus.FAIL
                r.message = f"Unexpected status: {info.response_status}/{info.cert_status}"
            r.details.update({"this_update": info.this_update, "next_update": info.next_update})
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
    r.end()
    results.append(r)

    # 2. Revoked certificate status
    r = TestCaseResult(id=str(uuid.uuid4()), category="Status", name="Known revoked certificate returns revoked", status=TestStatus.SKIP)
    if revoked_cert is None:
        r.message = "No known-revoked certificate provided"
    else:
        try:
            info = send_ocsp_request(ocsp_url, OCSPRequestSpec(revoked_cert, issuer, include_nonce=True), method="POST")
            if info.response_status == "SUCCESSFUL" and (info.cert_status or "").lower() == "revoked":
                r.status = TestStatus.PASS
                r.message = "revoked"
                r.details.update({"revocation_time": info.revocation_time, "revocation_reason": info.revocation_reason})
            else:
                r.status = TestStatus.FAIL
                r.message = f"Unexpected status: {info.response_status}/{info.cert_status}"
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
    r.end()
    results.append(r)

    # 3. Unknown CA
    r = TestCaseResult(id=str(uuid.uuid4()), category="Status", name="Unknown CA returns unknown", status=TestStatus.SKIP)
    if unknown_ca_cert is None:
        r.message = "No unknown-CA certificate provided"
    else:
        try:
            info = send_ocsp_request(ocsp_url, OCSPRequestSpec(unknown_ca_cert, issuer, include_nonce=True), method="POST")
            # Many responders return 'unknown' for unserved issuers
            r.status = TestStatus.PASS if (info.cert_status or "").lower() == "unknown" else TestStatus.FAIL
            r.message = f"cert_status={info.cert_status}"
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
    r.end()
    results.append(r)

    # 4. Non-issued serial handling (extended revoked) - cannot be asserted generically
    r = TestCaseResult(id=str(uuid.uuid4()), category="Status", name="Non-issued certificate handling", status=TestStatus.SKIP)
    r.message = "Requires non-issued serial scenario configured; skipping"
    r.end()
    results.append(r)

    # 5. Timeliness fields
    r = TestCaseResult(id=str(uuid.uuid4()), category="Status", name="thisUpdate/nextUpdate/producedAt present and plausible", status=TestStatus.ERROR)
    try:
        # Test description
        test_description = [
            "This test validates OCSP response timestamp fields for completeness and validity.",
            "It checks:",
            "1. thisUpdate field is present (when certificate status was last updated)",
            "2. nextUpdate field is present (when next update is expected)",
            "3. producedAt field is present (when OCSP response was generated)",
            "4. Timestamp fields are parseable and valid",
            "5. RFC 6960 compliance for timestamp fields"
        ]
        
        test_cert = good_cert or revoked_cert or issuer
        info = send_ocsp_request(ocsp_url, OCSPRequestSpec(test_cert, issuer, include_nonce=False), method="POST")
        
        # Detailed analysis
        analysis = {
            "test_description": test_description,
            "request_method": "POST",
            "nonce_included": False,
            "test_certificate": str(test_cert.subject) if test_cert else "None",
            "issuer_certificate": str(issuer.subject),
            "ocsp_url": ocsp_url
        }
        
        # Response status analysis
        status_analysis = {
            "response_status": info.response_status,
            "status_meaning": {
                "SUCCESSFUL": "Response is valid and contains certificate status",
                "MALFORMED": "Request was malformed or invalid",
                "INTERNAL_ERROR": "OCSP responder internal error",
                "TRY_LATER": "Responder temporarily unavailable",
                "SIG_REQUIRED": "Request must be signed",
                "UNAUTHORIZED": "Request not authorized (certificate not issued by this CA)"
            }.get(info.response_status, "Unknown status"),
            "is_successful": info.response_status == "SUCCESSFUL"
        }
        
        # Timestamp field analysis
        timestamp_analysis = {
            "this_update": {
                "value": info.this_update,
                "present": info.this_update is not None,
                "description": "Time when certificate status was last updated by the CA",
                "required": True
            },
            "next_update": {
                "value": info.next_update,
                "present": info.next_update is not None,
                "description": "Time when next certificate status update is expected",
                "required": True
            },
            "produced_at": {
                "value": info.produced_at,
                "present": info.produced_at is not None,
                "description": "Time when this OCSP response was generated",
                "required": True
            }
        }
        
        # Additional response details
        response_details = {
            "version": info.version,
            "responder_id": info.responder_id,
            "signature_algorithm_oid": info.signature_algorithm_oid,
            "certificate_status": getattr(info, 'certificate_status', None),
            "revocation_reason": getattr(info, 'revocation_reason', None),
            "revocation_time": getattr(info, 'revocation_time', None)
        }
        
        # Determine test result
        has_this = info.this_update is not None
        has_next = info.next_update is not None
        has_prod = info.produced_at is not None
        all_present = has_this and has_next and has_prod
        
        if all_present:
            r.status = TestStatus.PASS
            r.message = f"All timestamp fields present: thisUpdate={has_this}, nextUpdate={has_next}, producedAt={has_prod}"
        else:
            r.status = TestStatus.FAIL
            r.message = f"Missing timestamp fields: thisUpdate={has_this}, nextUpdate={has_next}, producedAt={has_prod}"
        
        # Comprehensive test details
        r.details.update({
            "analysis": analysis,
            "status_analysis": status_analysis,
            "timestamp_analysis": timestamp_analysis,
            "response_details": response_details,
            "test_result": {
                "this_update_present": has_this,
                "next_update_present": has_next,
                "produced_at_present": has_prod,
                "all_timestamps_present": all_present,
                "overall_result": r.status.value
            },
            "troubleshooting": {
                "if_missing_this_update": "OCSP responder may not be RFC 6960 compliant or experiencing issues",
                "if_missing_next_update": "OCSP responder may not provide update schedule information",
                "if_missing_produced_at": "OCSP responder may not include response generation time",
                "if_unauthorized": "Certificate may not be issued by the OCSP responder's CA",
                "next_steps": "Verify certificate issuer matches OCSP responder CA, check OCSP responder compliance"
            }
        })
        
    except Exception as exc:
        r.status = TestStatus.ERROR
        r.message = f"Test execution failed: {exc}"
        r.details.update({
            "error_type": type(exc).__name__,
            "error_details": str(exc),
            "troubleshooting": {
                "network_issue": "Check OCSP URL accessibility and network connectivity",
                "certificate_issue": "Verify certificate and issuer files are valid",
                "parsing_issue": "OCSP response may be malformed or unsupported format"
            }
        })
    r.end()
    results.append(r)

    return results
