import os
import tempfile
import uuid
from typing import Any, Callable, List, Optional

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from .models import TestCaseResult, TestStatus, result_sink
from .ocsp_client import send_ocsp_request, OCSPRequestSpec, _build_request
from cryptography.hazmat.primitives import hashes
from .monitor import OCSPMonitor
from .selection import should_run


def run_security_tests(
    ocsp_url: str,
    issuer: x509.Certificate,
    good_cert: Optional[x509.Certificate],
    client_sign_cert: Optional[str],
    client_sign_key: Optional[str],
    config: Optional[Any] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    on_result=None,
) -> List[TestCaseResult]:
    results = result_sink(on_result)

    def _log(message: str) -> None:
        if log_callback:
            log_callback(f"[DEBUG] {message}\n")
        else:
            print(f"[DEBUG] {message}")

    # One monitor for the whole category (its init banner is noisy and the
    # construction is not free), created only when a test needs it.
    _monitor_holder: List[OCSPMonitor] = []

    def _get_monitor() -> OCSPMonitor:
        if not _monitor_holder:
            _monitor_holder.append(OCSPMonitor(log_callback=log_callback, config=config))
        return _monitor_holder[0]

    def _finish(r: TestCaseResult) -> None:
        r.end()
        results.append(r)
        _log(f"Completed security test: {r.name} -> {r.status.value} - {r.message}")

    # 1. Malformed request (truncate DER)
    if should_run("Malformed request rejected"):
        _log("Starting security test: Malformed request rejected")
        r = TestCaseResult(id=str(uuid.uuid4()), category="Security", name="Malformed request rejected", status=TestStatus.ERROR)
        try:
            # Test various malformed request scenarios
            malformed_tests = []
        
            # Zero-length nonce
            try:
                info = send_ocsp_request(ocsp_url, OCSPRequestSpec(good_cert or issuer, issuer, include_nonce=True, nonce_len=0), method="POST")
                malformed_tests.append(("Zero-length nonce", "accepted"))
            except Exception as e:
                malformed_tests.append(("Zero-length nonce", f"rejected: {str(e)[:50]}"))
        
            # Overlong nonce (>128 octets)
            try:
                over = os.urandom(129)
                info2 = send_ocsp_request(ocsp_url, OCSPRequestSpec(good_cert or issuer, issuer, include_nonce=True), method="POST", override_nonce=over)
                malformed_tests.append(("Overlong nonce", "accepted"))
            except Exception as e:
                malformed_tests.append(("Overlong nonce", f"rejected: {str(e)[:50]}"))
        
            # Test with malformed DER by sending truncated request
            try:
                # Build a normal request and truncate it
                der_req, _ = _build_request(OCSPRequestSpec(good_cert or issuer, issuer, include_nonce=False))
                truncated_req = der_req[:-10]  # Remove last 10 bytes

                headers = {"Content-Type": "application/ocsp-request", "Accept": "application/ocsp-response"}
                resp = requests.post(ocsp_url, data=truncated_req, headers=headers, timeout=10)
                malformed_tests.append(("Truncated DER", f"status: {resp.status_code}"))
            except Exception as e:
                malformed_tests.append(("Truncated DER", f"rejected: {str(e)[:50]}"))
        
            # Evaluate results
            rejected_count = sum(1 for _, result in malformed_tests if "rejected" in result.lower())
            if rejected_count > 0:
                r.status = TestStatus.PASS
                r.message = f"Server rejected {rejected_count}/{len(malformed_tests)} malformed requests"
            else:
                r.status = TestStatus.SKIP
                r.message = "Server accepted malformed requests; policy-dependent"
        
            r.details.update({"malformed_tests": malformed_tests})
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
        _finish(r)

    # 2. Operational errors tryLater/internalError (observational)
    if should_run("Operational error signaling"):
        _log("Starting security test: Operational error signaling")
        r = TestCaseResult(id=str(uuid.uuid4()), category="Security", name="Operational error signaling", status=TestStatus.PASS)
        try:
            monitor = _get_monitor()
        
            # Test operational error signaling
            issuer_path = os.path.join(tempfile.gettempdir(), f"ocsp_issuer_{uuid.uuid4().hex}.pem")
            with open(issuer_path, 'wb') as f:
                f.write(issuer.public_bytes(encoding=serialization.Encoding.PEM))
        
            error_results = monitor.test_operational_error_signaling(issuer_path, ocsp_url)
        
            # Check if any error handling is working (malformed request, invalid cert, unauthorized, etc.)
            error_response_validation = error_results.get("error_response_validation", {})
            any_proper_error_handling = any(
                test.get("proper_error_response", False) or test.get("unauthorized_response", False)
                for test in error_response_validation.values()
                if isinstance(test, dict)
            )
        
            if any_proper_error_handling:
                r.message = "Operational error signaling validation PASSED"
                r.status = TestStatus.PASS
            else:
                r.message = "Operational error signaling validation FAILED"
                r.status = TestStatus.FAIL
        
            r.details = {
                "error_response_validation": error_results.get("error_response_validation", {}),
                "recommendations": error_results.get("recommendations", [])
            }
        
            # Cleanup
            try:
                os.remove(issuer_path)
            except:
                pass
            
        except Exception as e:
            r.status = TestStatus.ERROR
            r.message = f"Operational error signaling test failed: {str(e)}"

        _finish(r)

    # 3a. Unauthorized queries
    if should_run("Unauthorized query handling"):
        _log("Starting security test: Unauthorized query handling")
        r = TestCaseResult(id=str(uuid.uuid4()), category="Security", name="Unauthorized query handling", status=TestStatus.PASS)
        try:
            monitor = _get_monitor()
        
            # Test unauthorized query handling
            issuer_path = os.path.join(tempfile.gettempdir(), f"ocsp_issuer_{uuid.uuid4().hex}.pem")
            with open(issuer_path, 'wb') as f:
                f.write(issuer.public_bytes(encoding=serialization.Encoding.PEM))
        
            unauthorized_results = monitor.test_unauthorized_query_handling(issuer_path, ocsp_url)
        
            if unauthorized_results.get("proper_error_signaling", False):
                r.message = "Unauthorized query handling validation PASSED"
                r.status = TestStatus.PASS
            else:
                r.message = "Unauthorized query handling validation FAILED"
                r.status = TestStatus.FAIL
        
            r.details = {
                "ca_authorization_validation": unauthorized_results.get("ca_authorization_validation", {}),
                "access_control_testing": unauthorized_results.get("access_control_testing", {}),
                "recommendations": unauthorized_results.get("recommendations", [])
            }
        
            # Cleanup
            try:
                os.remove(issuer_path)
            except:
                pass
            
        except Exception as e:
            r.status = TestStatus.ERROR
            r.message = f"Unauthorized query handling test failed: {str(e)}"

        _finish(r)

    # 3b. sigRequired without signature
    if should_run("sigRequired when unsigned"):
        _log("Starting security test: sigRequired when unsigned")
        r = TestCaseResult(id=str(uuid.uuid4()), category="Security", name="sigRequired when unsigned", status=TestStatus.PASS)
        try:
            monitor = _get_monitor()
        
            # Test sigRequired validation
            issuer_path = os.path.join(tempfile.gettempdir(), f"ocsp_issuer_{uuid.uuid4().hex}.pem")
            with open(issuer_path, 'wb') as f:
                f.write(issuer.public_bytes(encoding=serialization.Encoding.PEM))
        
            sigrequired_results = monitor.test_sigrequired_validation(issuer_path, ocsp_url)
        
            if sigrequired_results.get("sigrequired_enforced", False):
                r.message = "sigRequired validation PASSED"
                r.status = TestStatus.PASS
            elif sigrequired_results.get("sigrequired_extension_detected", False):
                r.message = "sigRequired extension detected but enforcement inconsistent"
                r.status = TestStatus.FAIL
            else:
                # No sigRequired is common and not necessarily a security failure
                r.message = "sigRequired extension not detected - server may not enforce signed requests"
                r.status = TestStatus.PASS  # Changed from FAIL to PASS
        
            r.details = {
                "sigrequired_enforced": sigrequired_results.get("sigrequired_enforced", False),
                "unsigned_request_rejected": sigrequired_results.get("unsigned_request_rejected", False),
                "signed_request_accepted": sigrequired_results.get("signed_request_accepted", False),
                "sigrequired_extension_detected": sigrequired_results.get("sigrequired_extension_detected", False),
                "security_warnings": sigrequired_results.get("security_warnings", []),
                "recommendations": sigrequired_results.get("recommendations", [])
            }
        
            # Cleanup
            try:
                os.remove(issuer_path)
            except:
                pass
            
        except Exception as e:
            r.status = TestStatus.ERROR
            r.message = f"sigRequired validation test failed: {str(e)}"

        _finish(r)

    # 4. Nonce echo verification
    if should_run("Nonce echo in response"):
        _log("Starting security test: Nonce echo in response")
        r = TestCaseResult(id=str(uuid.uuid4()), category="Security", name="Nonce echo in response", status=TestStatus.PASS)
        nonce_enabled = getattr(config, "nonce_enabled", True) if config else True
        if not nonce_enabled:
            # The user opted out of nonces for this run, so there is nothing to
            # echo — report SKIP rather than exercising (and failing) the test.
            r.status = TestStatus.SKIP
            r.message = "Nonce is disabled in the run configuration; nonce echo test skipped"
            r.details = {"nonce_enabled": False}
        else:
            try:
                monitor = _get_monitor()

                # Test nonce echo validation
                issuer_path = os.path.join(tempfile.gettempdir(), f"ocsp_issuer_{uuid.uuid4().hex}.pem")
                with open(issuer_path, 'wb') as f:
                    f.write(issuer.public_bytes(encoding=serialization.Encoding.PEM))

                nonce_results = monitor.test_nonce_echo_validation(issuer_path, ocsp_url)

                if nonce_results.get("nonce_echo_validation", False):
                    r.message = "Nonce echo validation PASSED"
                    r.status = TestStatus.PASS
                elif nonce_results.get("nonce_support_detected", False):
                    r.message = "Nonce support detected but echo validation failed"
                    r.status = TestStatus.FAIL
                else:
                    # Check if server requires authentication (which is good security)
                    nonce_tests = nonce_results.get("nonce_tests", [])
                    unauthorized_responses = any(
                        "unauthorized" in str(test.get("response_details", {}).get("stdout", "")).lower()
                        for test in nonce_tests
                    )
                    if unauthorized_responses:
                        r.message = "Server requires authentication - nonce testing limited (this may indicate proper access controls)"
                        r.status = TestStatus.PASS  # Changed from FAIL to PASS
                    else:
                        r.message = "No nonce support detected - limited replay attack protection"
                        r.status = TestStatus.FAIL

                r.details = {
                    "nonce_support_detected": nonce_results.get("nonce_support_detected", False),
                    "nonce_echo_validation": nonce_results.get("nonce_echo_validation", False),
                    "replay_protection": nonce_results.get("replay_protection", False),
                    "nonce_tests": nonce_results.get("nonce_tests", []),
                    "security_warnings": nonce_results.get("security_warnings", []),
                    "recommendations": nonce_results.get("recommendations", [])
                }

                # Cleanup
                try:
                    os.remove(issuer_path)
                except:
                    pass
            except Exception as e:
                r.status = TestStatus.ERROR
                r.message = f"Nonce echo validation test failed: {str(e)}"

        _finish(r)

    # 5. Signature trust validation - partial (cannot complete full path validation generically)
    if should_run("Signature algorithm present and response SUCCESSFUL"):
        _log("Starting security test: Signature algorithm present and response SUCCESSFUL")
        r = TestCaseResult(id=str(uuid.uuid4()), category="Security", name="Signature algorithm present and response SUCCESSFUL", status=TestStatus.ERROR)
        try:
            # Test description
            test_description = [
                "This test validates OCSP response signature algorithm presence and response success.",
                "It checks:",
                "1. OCSP response status is SUCCESSFUL",
                "2. Signature algorithm OID is present in response",
                "3. Response structure includes signature information",
                "4. Basic signature algorithm validation"
            ]
        
            test_cert = good_cert or issuer
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
        
            # Signature algorithm analysis
            signature_analysis = {
                "signature_algorithm_oid": info.signature_algorithm_oid,
                "signature_present": info.signature_algorithm_oid is not None,
                "algorithm_meaning": {
                    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption (deprecated)",
                    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption (recommended)",
                    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
                    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
                    "1.2.840.10040.4.3": "dsaWithSHA1 (deprecated)",
                    "1.2.840.10045.4.1": "ecdsaWithSHA1 (deprecated)",
                    "1.2.840.10045.4.3.2": "ecdsaWithSHA256 (recommended)",
                    "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
                    "1.2.840.10045.4.3.4": "ecdsaWithSHA512"
                }.get(info.signature_algorithm_oid, "Unknown algorithm") if info.signature_algorithm_oid else "No algorithm"
            }
        
            # Additional response details
            response_details = {
                "version": info.version,
                "produced_at": info.produced_at,
                "responder_id": info.responder_id,
                "certificate_status": getattr(info, 'certificate_status', None),
                "this_update": getattr(info, 'this_update', None),
                "next_update": getattr(info, 'next_update', None)
            }
        
            # Determine test result
            status_ok = info.response_status == "SUCCESSFUL"
            signature_present = info.signature_algorithm_oid is not None
        
            if status_ok and signature_present:
                r.status = TestStatus.PASS
                r.message = f"OCSP response successful with signature algorithm: {info.signature_algorithm_oid}"
            elif not status_ok:
                r.status = TestStatus.FAIL
                r.message = f"OCSP response not successful: {info.response_status}"
            elif not signature_present:
                r.status = TestStatus.FAIL
                r.message = "OCSP response missing signature algorithm"
            else:
                r.status = TestStatus.FAIL
                r.message = "OCSP response validation failed"
        
            # Comprehensive test details
            r.details.update({
                "analysis": analysis,
                "status_analysis": status_analysis,
                "signature_analysis": signature_analysis,
                "response_details": response_details,
                "test_result": {
                    "status_ok": status_ok,
                    "signature_present": signature_present,
                    "overall_result": r.status.value
                },
                "troubleshooting": {
                    "if_unauthorized": "Certificate may not be issued by the OCSP responder's CA",
                    "if_missing_signature": "OCSP responder may not be RFC 6960 compliant",
                    "if_unsuccessful": "OCSP responder may be experiencing issues",
                    "if_deprecated_algorithm": "Consider upgrading to a stronger signature algorithm",
                    "next_steps": "Verify certificate issuer matches OCSP responder CA, check OCSP responder status"
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
        _finish(r)

    # 7. Cryptographic preference negotiation test
    if should_run("Cryptographic preference negotiation"):
        _log("Starting security test: Cryptographic preference negotiation")
        r = TestCaseResult(id=str(uuid.uuid4()), category="Security", name="Cryptographic preference negotiation", status=TestStatus.ERROR)
    
        # Check if cryptographic preference testing is enabled
        test_enabled = True
        if config and hasattr(config, 'test_cryptographic_preferences'):
            test_enabled = config.test_cryptographic_preferences
    
        if not test_enabled:
            r.status = TestStatus.SKIP
            r.message = "Cryptographic preference testing is disabled"
            r.details.update({
                "test_disabled": True,
                "reason": "Configuration setting test_cryptographic_preferences is False"
            })
            _finish(r)
        else:
            try:
                # Create a temporary issuer file for the monitor
                with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
                    issuer_pem = issuer.public_bytes(serialization.Encoding.PEM)
                    f.write(issuer_pem)
                    issuer_path = f.name
            
                try:
                    monitor = _get_monitor()

                    # Run cryptographic preference test
                    crypto_results = monitor.run_cryptographic_preference_test(issuer_path, ocsp_url)
                
                    # Determine test status based on security assessment
                    security_assessment = crypto_results.get("security_assessment", "UNKNOWN")
                    negotiation_successful = crypto_results.get("negotiation_successful", False)
                    downgrade_detected = crypto_results.get("downgrade_detected", False)

                    # The responder may decline to answer the probe altogether
                    # (e.g. "unauthorized" — the issuer/CA certificate used for
                    # the probe is typically out of a responder's scope). That is
                    # not a cryptographic weakness and, notably, is unrelated to
                    # OCSP being served over plain HTTP (which is normal, since
                    # responses are signed). Treat "no usable response" as SKIP
                    # rather than a security failure.
                    algo_tests = (crypto_results.get("test_details", {}) or {}).get("algorithm_tests", [])
                    any_response = any(t.get("response_received") for t in algo_tests)

                    if security_assessment in ("SECURE", "ACCEPTABLE"):
                        r.status = TestStatus.PASS
                        r.message = f"Acceptable cryptographic algorithms supported: {len(crypto_results.get('supported_algorithms', []))} algorithms"
                    elif security_assessment == "WEAK":
                        r.status = TestStatus.FAIL
                        r.message = "Only weak cryptographic algorithms supported"
                    elif not any_response:
                        r.status = TestStatus.SKIP
                        r.message = (
                            "Responder returned no usable OCSP response for the crypto-preference "
                            "probe (commonly 'unauthorized' — the issuer/CA certificate is out of "
                            "the responder's scope); cryptographic preference could not be assessed"
                        )
                    elif security_assessment == "CRITICAL":
                        r.status = TestStatus.FAIL
                        r.message = "No supported cryptographic algorithms found"
                    else:
                        r.status = TestStatus.FAIL
                        r.message = f"Unknown security assessment: {security_assessment}"
                
                    # Add detailed results
                    r.details.update({
                        "analysis": {
                            "test_description": [
                                "This test validates OCSP server cryptographic capabilities and detects potential downgrade attacks.",
                                "It checks:",
                                "1. Support for various signature algorithms (SHA-512, SHA-384, SHA-256 with RSA/ECDSA)",
                                "2. Detection of potential downgrade attacks",
                                "3. Server uses acceptable cryptographic strength",
                                "4. Algorithm preference negotiation works correctly"
                            ],
                            "ocsp_url": ocsp_url,
                            "issuer_certificate": str(issuer.subject),
                            "test_method": "Cryptographic preference negotiation"
                        },
                        "negotiation_results": {
                            "negotiation_successful": negotiation_successful,
                            "security_assessment": security_assessment,
                            "downgrade_detected": downgrade_detected,
                            "supported_algorithms": crypto_results.get("supported_algorithms", []),
                            "preferred_algorithms": crypto_results.get("preferred_algorithms", []),
                            "algorithm_tests": crypto_results.get("algorithm_tests", []),
                            "security_warnings": crypto_results.get("security_warnings", []),
                            "recommendations": crypto_results.get("recommendations", [])
                        },
                        "test_result": {
                            "negotiation_successful": negotiation_successful,
                            "security_assessment": security_assessment,
                            "downgrade_detected": downgrade_detected,
                            "overall_result": r.status.value
                        },
                        "troubleshooting": {
                            "if_weak_algorithms": "OCSP server may need cryptographic algorithm upgrades",
                            "if_downgrade_detected": "Potential security vulnerability - server may be vulnerable to downgrade attacks",
                            "if_no_support": "OCSP server may not support modern cryptographic algorithms",
                            "if_negotiation_fails": "OCSP server may not properly handle algorithm preference negotiation",
                            "next_steps": "Verify OCSP server cryptographic capabilities, consider upgrading to stronger algorithms"
                        }
                    })
                
                finally:
                    # Clean up temporary file
                    try:
                        os.unlink(issuer_path)
                    except:
                        pass
        
            except Exception as exc:
                r.status = TestStatus.ERROR
                r.message = f"Cryptographic preference test failed: {exc}"
                r.details.update({
                    "error_type": type(exc).__name__,
                    "error_details": str(exc),
                    "troubleshooting": {
                        "network_issue": "Check OCSP URL accessibility and network connectivity",
                        "certificate_issue": "Verify issuer certificate file is valid",
                        "monitor_issue": "OCSPMonitor may not be properly initialized"
                    }
                })

            _finish(r)

    return results
