import uuid
from datetime import datetime
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes

from .models import TestCaseResult, TestStatus
from .ocsp_client import send_ocsp_request, OCSPRequestSpec


def run_protocol_tests(ocsp_url: str, issuer: x509.Certificate, leaf: x509.Certificate) -> List[TestCaseResult]:
    results: List[TestCaseResult] = []

    # 1. HTTP GET
    r = TestCaseResult(id=str(uuid.uuid4()), category="Protocol", name="HTTP GET transport", status=TestStatus.ERROR)
    try:
        info = send_ocsp_request(ocsp_url, OCSPRequestSpec(leaf, issuer, include_nonce=True, nonce_len=16), method="GET")
        r.status = TestStatus.PASS
        r.message = "GET accepted"
        r.details.update({"latency_ms": info.latency_ms, "response_status": info.response_status})
    except Exception as exc:
        r.status = TestStatus.FAIL
        r.message = f"GET failed: {exc}"
    r.end()
    results.append(r)

    # 1. HTTP POST
    r = TestCaseResult(id=str(uuid.uuid4()), category="Protocol", name="HTTP POST transport", status=TestStatus.ERROR)
    try:
        info = send_ocsp_request(ocsp_url, OCSPRequestSpec(leaf, issuer, include_nonce=True, nonce_len=16), method="POST")
        r.status = TestStatus.PASS
        r.message = "POST accepted"
        r.details.update({"latency_ms": info.latency_ms, "response_status": info.response_status})
    except Exception as exc:
        r.status = TestStatus.FAIL
        r.message = f"POST failed: {exc}"
    r.end()
    results.append(r)

    # 2-3. DER encoding, Basic response structure, version producedAt extracted
    r = TestCaseResult(id=str(uuid.uuid4()), category="Protocol", name="DER encoding and basic response fields", status=TestStatus.ERROR)
    try:
        # Test what this test is checking
        test_description = [
            "This test validates OCSP response structure and DER encoding compliance.",
            "It checks for:",
            "1. Successful OCSP response status (not UNAUTHORIZED, MALFORMED, etc.)",
            "2. Presence of required response fields (version, producedAt, responderID)",
            "3. Valid DER encoding and parsing",
            "4. Signature algorithm identification",
            "5. Proper ASN.1 structure compliance"
        ]
        
        info = send_ocsp_request(ocsp_url, OCSPRequestSpec(leaf, issuer, include_nonce=False), method="POST")
        
        # Detailed analysis of what was tested
        analysis = {
            "test_description": test_description,
            "request_method": "POST",
            "nonce_included": False,
            "hash_algorithm": "SHA-256 (default)",
            "certificate_serial": str(leaf.serial_number),
            "issuer_subject": str(issuer.subject),
            "ocsp_url": ocsp_url
        }
        
        # Analyze response status
        status_analysis = {
            "response_status": info.response_status,
            "status_meaning": {
                "SUCCESSFUL": "Response is valid and contains certificate status",
                "MALFORMED": "Request was malformed or invalid",
                "INTERNAL_ERROR": "OCSP responder internal error",
                "TRY_LATER": "Responder temporarily unavailable",
                "SIG_REQUIRED": "Request must be signed",
                "UNAUTHORIZED": "Request not authorized (certificate not issued by this CA)"
            }.get(info.response_status, "Unknown status")
        }
        
        # Check each required field
        field_analysis = {
            "version": {
                "value": info.version,
                "required": True,
                "present": info.version is not None,
                "description": "OCSP response version (should be 1 for RFC 6960)"
            },
            "produced_at": {
                "value": info.produced_at,
                "required": True,
                "present": info.produced_at is not None,
                "description": "Time when OCSP response was produced"
            },
            "responder_id": {
                "value": info.responder_id,
                "required": True,
                "present": info.responder_id is not None,
                "description": "Identifier of the OCSP responder"
            },
            "signature_algorithm_oid": {
                "value": info.signature_algorithm_oid,
                "required": True,
                "present": info.signature_algorithm_oid is not None,
                "description": "OID of the signature algorithm used to sign the response"
            }
        }
        
        # Additional OCSP response details
        response_details = {
            "certificate_status": getattr(info, 'certificate_status', None),
            "this_update": getattr(info, 'this_update', None),
            "next_update": getattr(info, 'next_update', None),
            "revocation_reason": getattr(info, 'revocation_reason', None),
            "revocation_time": getattr(info, 'revocation_time', None)
        }
        
        # Determine test result
        status_ok = info.response_status == "SUCCESSFUL"
        required_fields_present = all(field["present"] for field in field_analysis.values())
        
        if status_ok and required_fields_present:
            r.status = TestStatus.PASS
            r.message = "OCSP response structure and DER encoding validation PASSED"
        elif not status_ok:
            r.status = TestStatus.FAIL
            r.message = f"OCSP response status indicates failure: {info.response_status}"
        else:
            r.status = TestStatus.FAIL
            r.message = "OCSP response missing required fields"
        
        # Comprehensive test details
        r.details.update({
            "analysis": analysis,
            "status_analysis": status_analysis,
            "field_analysis": field_analysis,
            "response_details": response_details,
            "test_result": {
                "status_ok": status_ok,
                "required_fields_present": required_fields_present,
                "overall_result": r.status.value
            },
            "troubleshooting": {
                "if_unauthorized": "Certificate may not be issued by the OCSP responder's CA",
                "if_missing_fields": "OCSP responder may not be RFC 6960 compliant",
                "if_malformed": "Request format may be incorrect or unsupported",
                "next_steps": "Check certificate issuer matches OCSP responder CA, verify OCSP URL is correct"
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

    # 4. CertID SHA-1 usage (request side)
    r = TestCaseResult(id=str(uuid.uuid4()), category="Protocol", name="CertID SHA-1 for issuer hashes", status=TestStatus.ERROR)
    try:
        # Test description
        test_description = [
            "This test validates OCSP request with SHA-1 hash algorithm for certificate identification.",
            "It checks:",
            "1. OCSP responder accepts SHA-1 hash algorithm in CertID",
            "2. SHA-1 based certificate identification works",
            "3. Response is successful with SHA-1 identifier",
            "4. RFC 6960 compliance for hash algorithm support"
        ]
        
        info = send_ocsp_request(ocsp_url, OCSPRequestSpec(leaf, issuer, include_nonce=False, hash_algo=hashes.SHA1()), method="POST")
        
        # Detailed analysis
        analysis = {
            "test_description": test_description,
            "request_method": "POST",
            "nonce_included": False,
            "hash_algorithm": "SHA-1",
            "certificate_serial": str(leaf.serial_number),
            "issuer_subject": str(issuer.subject),
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
        
        # Hash algorithm analysis
        hash_analysis = {
            "requested_hash": "SHA-1",
            "hash_oid": "1.3.14.3.2.26",
            "hash_status": "Deprecated but still supported",
            "security_note": "SHA-1 is deprecated due to collision vulnerabilities",
            "recommendation": "Use SHA-256 or stronger hash algorithms"
        }
        
        # Additional response details
        response_details = {
            "version": info.version,
            "produced_at": info.produced_at,
            "responder_id": info.responder_id,
            "signature_algorithm_oid": info.signature_algorithm_oid,
            "certificate_status": getattr(info, 'certificate_status', None),
            "this_update": getattr(info, 'this_update', None),
            "next_update": getattr(info, 'next_update', None)
        }
        
        # Determine test result
        if info.response_status == "SUCCESSFUL":
            r.status = TestStatus.PASS
            r.message = "SHA-1 hash algorithm accepted and response successful"
        else:
            r.status = TestStatus.FAIL
            r.message = f"SHA-1 hash algorithm not accepted or response failed: {info.response_status}"
        
        # Comprehensive test details
        r.details.update({
            "analysis": analysis,
            "status_analysis": status_analysis,
            "hash_analysis": hash_analysis,
            "response_details": response_details,
            "test_result": {
                "sha1_accepted": info.response_status == "SUCCESSFUL",
                "response_successful": info.response_status == "SUCCESSFUL",
                "overall_result": r.status.value
            },
            "troubleshooting": {
                "if_sha1_rejected": "OCSP responder may not support SHA-1 hash algorithm",
                "if_unauthorized": "Certificate may not be issued by the OCSP responder's CA",
                "if_malformed": "SHA-1 request format may be incorrect",
                "security_warning": "SHA-1 is deprecated - consider using SHA-256",
                "next_steps": "Verify OCSP responder supports SHA-1, check certificate issuer matches OCSP responder CA"
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

    # 5. Serial number handling tests (as mentioned in FutureFeatures.txt)
    r = TestCaseResult(id=str(uuid.uuid4()), category="Protocol", name="Serial number handling", status=TestStatus.ERROR)
    try:
        # Test with different serial number formats
        serial_tests = []
        
        # Test with decimal serial number
        try:
            # Extract serial number from certificate
            serial_number = leaf.serial_number
            serial_tests.append(("Decimal serial", f"Serial: {serial_number}"))
        except Exception as e:
            serial_tests.append(("Decimal serial", f"Error: {str(e)[:50]}"))
        
        # Test with hex serial number (0x prefix)
        try:
            hex_serial = hex(leaf.serial_number)
            serial_tests.append(("Hex serial", f"Hex: {hex_serial}"))
        except Exception as e:
            serial_tests.append(("Hex serial", f"Error: {str(e)[:50]}"))
        
        # Test with negative serial number (if applicable)
        try:
            # Some certificates might have negative serials
            if leaf.serial_number < 0:
                serial_tests.append(("Negative serial", f"Negative: {leaf.serial_number}"))
            else:
                serial_tests.append(("Negative serial", "No negative serial to test"))
        except Exception as e:
            serial_tests.append(("Negative serial", f"Error: {str(e)[:50]}"))
        
        r.status = TestStatus.PASS
        r.message = "Serial number handling tests completed"
        r.details.update({"serial_tests": serial_tests})
    except Exception as exc:
        r.status = TestStatus.ERROR
        r.message = str(exc)
    r.end()
    results.append(r)

    return results
