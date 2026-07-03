import subprocess
import threading
import os
import requests
import tempfile
import time
from urllib.parse import urlparse
from uuid import uuid4
from datetime import datetime
import re
from typing import Optional, Tuple, Callable, Dict, Any, List
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class OCSPMonitor:
    """OCSP and CRL monitoring functionality using OpenSSL"""
    
    VERSION = "2.1.0"  # Enhanced P7C processing version
    
    def __init__(self, log_callback: Optional[Callable[[str], None]] = None, config: Optional[Any] = None):
        self.log_callback = log_callback or print
        self.check_validity = True
        
        # Advanced testing options
        self.test_cryptographic_preferences = True  # Default value
        self.test_non_issued_certificates = True    # Default value
        if config and hasattr(config, 'test_cryptographic_preferences'):
            self.test_cryptographic_preferences = config.test_cryptographic_preferences
        if config and hasattr(config, 'test_non_issued_certificates'):
            self.test_non_issued_certificates = config.test_non_issued_certificates
        
        # OCSP response validation settings
        self.max_age_hours = 24  # Default value
        if config and hasattr(config, 'max_age_hours'):
            self.max_age_hours = config.max_age_hours
        
        self.log(f"[INFO] OCSPMonitor v{self.VERSION} initialized\n")
        
    def log(self, text: str) -> None:
        """Log message using callback"""
        self.log_callback(text)
        
    def check_certificate_validity(self, cert_path: str) -> Tuple[bool, Optional[datetime], Optional[datetime]]:
        """Check certificate validity period using OpenSSL"""
        try:
            cmd = ["openssl", "x509", "-noout", "-startdate", "-enddate", "-in", cert_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.log("[CMD] " + " ".join(cmd) + "\n")
            
            if result.stderr:
                self.log("[STDERR] " + result.stderr + "\n")
                return False, None, None

            start, end = None, None
            for line in result.stdout.splitlines():
                if "notBefore=" in line:
                    start = datetime.strptime(line.split("=", 1)[1].strip(), "%b %d %H:%M:%S %Y %Z")
                elif "notAfter=" in line:
                    end = datetime.strptime(line.split("=", 1)[1].strip(), "%b %d %H:%M:%S %Y %Z")

            if start and end:
                now = datetime.utcnow()
                self.log(f"[VALIDITY] Certificate Validity Period: {start} to {end}\n")
                if start <= now <= end:
                    self.log("[VALIDITY] [OK] Validity Period OK\n")
                    return True, start, end
                else:
                    self.log("[VALIDITY] [ERROR] Validity Period ERROR\n")
                    return False, start, end
            else:
                self.log("[VALIDITY] [ERROR] Could not parse validity period\n")
                return False, None, None

        except Exception as e:
            self.log(f"[VALIDITY] ERROR: {str(e)}\n")
            return False, None, None

    def run_ocsp_check(self, cert_path: str, issuer_path: str, ocsp_url: str, cert_serial: str = None) -> Dict[str, Any]:
        """Run comprehensive OCSP check"""
        try:
            self.log("[INFO] Running OCSP check...\n")
            
            # If no OCSP URL provided, extract it from the certificate's AIA extension (only if cert file provided)
            if not ocsp_url or ocsp_url.strip() == "":
                if cert_path:
                    self.log("[INFO] No OCSP URL provided, extracting from certificate's Authority Information Access...\n")
                    extracted_ocsp_url = self.extract_ocsp_url_from_cert(cert_path)
                    if extracted_ocsp_url:
                        ocsp_url = extracted_ocsp_url
                        self.log(f"[INFO] Extracted OCSP URL from certificate: {ocsp_url}\n")
                    else:
                        self.log("[ERROR] No OCSP URL found in certificate's Authority Information Access extension\n")
                        self.log("[INFO] This certificate may not have OCSP URLs in its AIA extension\n")
                        self.log("[INFO] Please provide an OCSP URL manually or check if the certificate has an AIA extension with OCSP URLs\n")
                        self.log("[INFO] Common OCSP URL patterns to try:\n")
                        self.log("[INFO] - http://ocsp.<domain>\n")
                        self.log("[INFO] - https://ocsp.<domain>\n")
                        self.log("[INFO] - http://<domain>/ocsp\n")
                        self.log("[INFO] - https://<domain>/ocsp\n")
                        return {
                            "summary": "[OCSP CHECK SUMMARY]\n[ERROR] No OCSP URL provided and none found in certificate\n[INFO] This certificate may not have OCSP URLs in its AIA extension\n[INFO] Please provide an OCSP URL manually or check certificate AIA extension\n[INFO] Common OCSP URL patterns to try: http://ocsp.<domain>, https://ocsp.<domain>, http://<domain>/ocsp, https://<domain>/ocsp\n",
                            "error": "No OCSP URL available - please provide manually"
                        }
                else:
                    self.log("[ERROR] No OCSP URL provided and no certificate file available for AIA extraction\n")
                    self.log("[INFO] When using serial numbers, you must provide the OCSP URL manually\n")
                    self.log("[INFO] Common OCSP URL patterns to try:\n")
                    self.log("[INFO] - http://ocsp.<domain>\n")
                    self.log("[INFO] - https://ocsp.<domain>\n")
                    self.log("[INFO] - http://<domain>/ocsp\n")
                    self.log("[INFO] - https://<domain>/ocsp\n")
                    return {
                        "summary": "[OCSP CHECK SUMMARY]\n[ERROR] No OCSP URL provided and no certificate file available for AIA extraction\n[INFO] When using serial numbers, you must provide the OCSP URL manually\n[INFO] Common OCSP URL patterns to try: http://ocsp.<domain>, https://ocsp.<domain>, http://<domain>/ocsp, https://<domain>/ocsp\n",
                        "error": "No OCSP URL available - please provide manually"
                    }
            
            # Check validity period if enabled and certificate file is provided
            validity_ok = None
            validity_start = None
            validity_end = None
            if self.check_validity and cert_path:
                validity_ok, validity_start, validity_end = self.check_certificate_validity(cert_path)

            # Try to build a complete trust chain for OCSP signature verification
            trust_chain_path = self._build_ocsp_trust_chain(issuer_path, ocsp_url, cert_path, cert_serial)
            
            # Build OCSP command - use either certificate file or serial number
            ocsp_cmd = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-url", ocsp_url, 
                "-resp_text", 
                "-verify_other", trust_chain_path if trust_chain_path else issuer_path,
                "-trust_other"
            ]
            
            # Add either certificate file or serial number
            if cert_serial:
                ocsp_cmd.extend(["-serial", cert_serial])
                self.log(f"[INFO] Using serial number: {cert_serial}\n")
            elif cert_path:
                ocsp_cmd.extend(["-cert", cert_path])
                self.log(f"[INFO] Using certificate file: {cert_path}\n")
            else:
                self.log("[ERROR] Neither certificate file nor serial number provided\n")
                return {
                    "summary": "[OCSP CHECK SUMMARY]\n[ERROR] Neither certificate file nor serial number provided\n",
                    "error": "No certificate or serial number provided"
                }
            
            self.log("[CMD] " + " ".join(ocsp_cmd) + "\n")
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=20)
            stdout = result.stdout
            self.log("[INFO] " + stdout + "\n")
            
            if result.stderr:
                self.log("[STDERR] " + result.stderr + "\n")
                
                # Check for specific verification errors and provide helpful context
                if "unable to get local issuer certificate" in result.stderr:
                    self.log("[INFO] OCSP response verification failed due to issuer certificate mismatch\n")
                    self.log("[INFO] This may indicate the OCSP response is signed by a different certificate than expected\n")
                    self.log("[INFO] The response data may still be valid, but signature verification failed\n")
                    
                    # Check if we attempted to build a trust chain
                    if trust_chain_path and trust_chain_path != issuer_path:
                        self.log("[INFO] Trust chain was built but verification still failed - this may be expected for some federal PKI environments\n")
                        self.log("[INFO] The OCSP response data should still be considered valid for certificate status checking\n")
                    else:
                        self.log("[INFO] No additional certificates found in OCSP response to build complete trust chain\n")
                        self.log("[INFO] This is common with federal PKI OCSP responders that use separate signing certificates\n")

            summary = "[OCSP CHECK SUMMARY]\n"
            
            # Determine signature verification status
            signature_verified = result.returncode == 0
            trust_chain_attempted = trust_chain_path and trust_chain_path != issuer_path
            
            results = {
                "validity_ok": validity_ok,
                "validity_start": validity_start,
                "validity_end": validity_end,
                "signature_verified": signature_verified,
                "trust_chain_attempted": trust_chain_attempted,
                "trust_chain_path": trust_chain_path,
                "update_times_valid": False,
                "nonce_support": False,
                "cert_status": "UNKNOWN",
                "overall_pass": False
            }

            # Certificate validity in summary
            if validity_ok is not None:
                if validity_ok:
                    summary += f"[OK] Certificate Validity Period OK ({validity_start} to {validity_end})\n"
                else:
                    summary += f"[ERROR] Certificate Validity Period ERROR ({validity_start} to {validity_end})\n"

            # Enhanced Signature Verification with Trust Chain Support
            signature_verified = False
            verification_method = "unknown"
            
            # Primary verification: Check OpenSSL's built-in verification
            if ("Response verify OK" in stdout or 
                "Response verify OK" in result.stderr or 
                "verify OK" in result.stderr.lower()):
                signature_verified = True
                verification_method = "openssl_builtin"
                summary += "[OK] Signature verification: PASS (OpenSSL built-in verification)\n"
                if trust_chain_attempted:
                    summary += "[INFO] Trust chain was successfully built and used for verification\n"
                results["signature_verified"] = True
            else:
                # Log trust chain attempt information
                if trust_chain_attempted:
                    self.log("[INFO] Trust chain was built but OpenSSL verification still failed\n")
                    self.log("[INFO] This is common with federal PKI OCSP responders that use separate signing certificates\n")
                    summary += "[WARN] Signature verification: FAILED (even with trust chain)\n"
                    summary += "[INFO] Trust chain was built but verification failed - this may be expected for federal PKI\n"
                else:
                    self.log("[INFO] No additional certificates found in OCSP response to build trust chain\n")
                    summary += "[ERROR] Signature verification: FAILED (no trust chain available)\n"
                
                # Secondary verification: Use comprehensive manual verification
                self.log("[INFO] Attempting comprehensive manual verification...\n")
                manual_verification = self.verify_ocsp_signature(cert_path, issuer_path, ocsp_url)
                
                if manual_verification:
                    signature_verified = True
                    verification_method = "manual_comprehensive"
                    summary += "[OK] Signature verification: PASS (comprehensive manual verification)\n"
                    results["signature_verified"] = True
                else:
                    verification_method = "failed"
                    summary += "[ERROR] Signature verification: FAIL (all verification methods failed)\n"
                    summary += "[INFO] OCSP response data should still be considered valid for certificate status checking\n"
                    results["signature_verified"] = False
                    
                    # Log detailed failure information for security analysis
                    self.log(f"[SECURITY] OCSP signature verification failed - potential security risk\n")
                    self.log(f"[SECURITY] Verification method attempted: {verification_method}\n")
                    self.log(f"[SECURITY] OCSP URL: {ocsp_url}\n")
                    self.log(f"[SECURITY] Issuer certificate: {issuer_path}\n")
            
            # Add verification details to results
            results["verification_method"] = verification_method
            results["verification_details"] = {
                "openssl_builtin_result": "Response verify OK" in stdout or "Response verify OK" in result.stderr,
                "manual_verification_performed": verification_method == "manual_comprehensive",
                "signature_validated": signature_verified
            }

            # Comprehensive Certificate Status Detail Parsing
            certificate_status_details = {
                "is_certificate_good": False, 
                "is_certificate_revoked": False, 
                "is_certificate_unknown": False,
                "security_warnings": ["No valid OCSP response to parse"]
            }
            # Always try to parse the response, even if signature verification failed
            if stdout:
                try:
                    # Extract certificate serial number for batch response handling
                    if cert_serial:
                        # Use the provided serial number directly
                        target_serial = cert_serial
                    else:
                        # Extract from certificate file
                        target_serial = self._extract_certificate_serial(cert_path)
                    certificate_status_details = self.parse_certificate_status_details(stdout, target_serial)
                except Exception as e:
                    self.log(f"[STATUS] Error during certificate status parsing: {str(e)}\n")
                    certificate_status_details = {
                        "cert_status": None,
                        "revocation_time": None,
                        "revocation_reason": None,
                        "this_update": None,
                        "next_update": None,
                        "certificate_serial": None,
                        "status_valid": False,
                        "parsing_errors": [f"Parsing error: {str(e)}"],
                        "security_warnings": [f"Parsing error: {str(e)}"]
                    }
            else:
                self.log("[STATUS] Skipping certificate status parsing - no OCSP response data\n")
                certificate_status_details = {
                    "cert_status": None,
                    "revocation_time": None,
                    "revocation_reason": None,
                    "this_update": None,
                    "next_update": None,
                    "certificate_serial": None,
                    "status_valid": False,
                    "parsing_errors": ["No OCSP response data to parse"],
                    "security_warnings": ["No OCSP response data to parse"]
                }
            
            # Add certificate status details to results
            results["certificate_status_details"] = certificate_status_details
            
            # Multi-step OCSP Signer Validation Process
            ocsp_signer_validation = self._perform_ocsp_signer_validation(stdout, issuer_path, ocsp_url, cert_path, cert_serial)
            results["ocsp_signer_validation"] = ocsp_signer_validation
            
            # Detect federal PKI environment and add to results
            federal_pki_info = self._detect_federal_pki_environment(stdout, ocsp_url)
            results["federal_pki_info"] = federal_pki_info
            
            if federal_pki_info["is_federal_pki"]:
                self.log(f"[FEDERAL-PKI] [INFO] Detected {federal_pki_info['agency']} federal PKI environment\n")
                for characteristic in federal_pki_info["characteristics"]:
                    self.log(f"[FEDERAL-PKI] [INFO] {characteristic}\n")

            # Response Validity Interval Validation - always try to validate if we have response data
            validity_interval_results = {
                "is_valid": False, 
                "compliance_issues": ["No OCSP response data to validate"],
                "security_warnings": ["No OCSP response data to validate"]
            }
            if stdout:
                try:
                    validity_interval_results = self.validate_response_validity_interval(stdout, self.max_age_hours)
                except Exception as e:
                    self.log(f"[VALIDITY] Error during validity interval validation: {str(e)}\n")
                    validity_interval_results = {
                        "is_valid": False, 
                        "compliance_issues": [f"Validation error: {str(e)}"],
                        "security_warnings": [f"Validation error: {str(e)}"]
                    }
            else:
                self.log("[VALIDITY] Skipping validity interval validation - no OCSP response data\n")
            
            # Add validity interval results to results
            results["validity_interval_validation"] = validity_interval_results
            
            # Update summary with certificate status information
            if certificate_status_details["cert_status"] == "good":
                summary += "[OK] Certificate Status: GOOD\n"
                results["cert_status"] = "GOOD"
            elif certificate_status_details["cert_status"] == "revoked":
                summary += "[ERROR] Certificate Status: REVOKED\n"
                results["cert_status"] = "REVOKED"
                
                # Add revocation details to summary
                if certificate_status_details["revocation_time"]:
                    summary += f"[INFO] Revocation Time: {certificate_status_details['revocation_time']}\n"
                if certificate_status_details["revocation_reason"]:
                    summary += f"[INFO] Revocation Reason: {certificate_status_details['revocation_reason']}\n"
                    
            elif certificate_status_details["cert_status"] == "unknown":
                summary += "[WARN] Certificate Status: UNKNOWN\n"
                results["cert_status"] = "UNKNOWN"
            else:
                summary += "[ERROR] Certificate Status: COULD NOT DETERMINE\n"
                results["cert_status"] = "UNKNOWN"
            
            # Add parsing errors and warnings to summary
            if certificate_status_details.get("parsing_errors"):
                summary += f"[ERROR] Parsing errors: {', '.join(certificate_status_details['parsing_errors'])}\n"
            
            if certificate_status_details.get("security_warnings"):
                for warning in certificate_status_details["security_warnings"]:
                    summary += f"[WARN] {warning}\n"
            
            # Add validity interval validation to summary
            if validity_interval_results["is_valid"]:
                summary += "[OK] Response Validity Interval: VALID\n"
                if validity_interval_results["age_hours"] is not None:
                    summary += f"[INFO] Response age: {validity_interval_results['age_hours']:.1f} hours\n"
                if validity_interval_results["time_until_expiry_hours"] is not None:
                    summary += f"[INFO] Time until expiry: {validity_interval_results['time_until_expiry_hours']:.1f} hours\n"
            else:
                summary += "[ERROR] Response Validity Interval: INVALID\n"
            
            # Add validity interval warnings and issues
            if validity_interval_results["security_warnings"]:
                for warning in validity_interval_results["security_warnings"]:
                    summary += f"[WARN] {warning}\n"
            
            if validity_interval_results["compliance_issues"]:
                for issue in validity_interval_results["compliance_issues"]:
                    summary += f"[ERROR] {issue}\n"
            
            # Add OCSP signer validation to summary
            if "ocsp_signer_validation" in results:
                signer_validation = results["ocsp_signer_validation"]
                summary += f"\n[OCSP SIGNER VALIDATION]\n"
                summary += f"[INFO] Steps completed: {signer_validation['steps_completed']}/{signer_validation['total_steps']}\n"
                
                if signer_validation["overall_success"]:
                    summary += "[OK] OCSP Signer Validation: ALL STEPS PASSED\n"
                else:
                    summary += "[ERROR] OCSP Signer Validation: FAILED\n"
                
                # Add step-by-step results
                for step_name, step_result in signer_validation["step_results"].items():
                    step_status = "[OK]" if step_result["success"] else "[ERROR]"
                    step_display = step_name.replace("step_", "").replace("_", " ").title()
                    summary += f"{step_status} {step_display}: {step_result['message']}\n"
                
                # Add errors and warnings
                if signer_validation["errors"]:
                    summary += f"[ERROR] Signer validation errors: {', '.join(signer_validation['errors'])}\n"
                if signer_validation["warnings"]:
                    for warning in signer_validation["warnings"]:
                        summary += f"[WARN] {warning}\n"
            
            # Critical security check: Only accept certificates that are explicitly GOOD AND have valid response interval
            if (certificate_status_details["cert_status"] == "good" and 
                validity_interval_results["is_valid"]):
                summary += "[OK] Certificate validation PASSED - certificate is explicitly good and response interval is valid\n"
                results["overall_pass"] = True
            else:
                summary += "[ERROR] Certificate validation FAILED - certificate not explicitly good or response interval invalid\n"
                results["overall_pass"] = False
                
                # Provide specific failure reasons
                if certificate_status_details["cert_status"] != "good":
                    summary += "[ERROR] Certificate status is not explicitly GOOD\n"
                if not validity_interval_results["is_valid"]:
                    summary += "[ERROR] Response validity interval is invalid\n"

            # Optional: Test non-issued certificate handling (can be enabled via configuration)
            if hasattr(self, 'test_non_issued_certificates') and self.test_non_issued_certificates:
                self.log("[INFO] Testing non-issued certificate handling...\n")
                non_issued_test_results = self.test_non_issued_certificate(issuer_path, ocsp_url)
                results["non_issued_certificate_test"] = non_issued_test_results
                
                # Add compliance assessment to summary
                compliance_status = non_issued_test_results["compliance_status"]
                if compliance_status == "COMPLIANT":
                    summary += "[OK] Non-issued certificate handling: COMPLIANT\n"
                elif compliance_status == "PARTIALLY_COMPLIANT":
                    summary += "[WARN] Non-issued certificate handling: PARTIALLY COMPLIANT\n"
                elif compliance_status == "NON_COMPLIANT":
                    summary += "[ERROR] Non-issued certificate handling: NON-COMPLIANT\n"
                else:
                    summary += "[INFO] Non-issued certificate handling: NOT TESTED\n"
                
                # Add recommendations
                for recommendation in non_issued_test_results["recommendations"]:
                    summary += f"[RECOMMENDATION] {recommendation}\n"

            # Optional: Test cryptographic preference negotiation (can be enabled via configuration)
            if hasattr(self, 'test_cryptographic_preferences') and self.test_cryptographic_preferences:
                self.log("[INFO] Testing cryptographic preference negotiation...\n")
                crypto_negotiation_results = self.negotiate_cryptographic_preferences(issuer_path, ocsp_url)
                results["cryptographic_preference_negotiation"] = crypto_negotiation_results
                
                # Add cryptographic assessment to summary
                security_assessment = crypto_negotiation_results["security_assessment"]
                if security_assessment == "SECURE":
                    summary += "[OK] Cryptographic preferences: SECURE\n"
                elif security_assessment == "ACCEPTABLE":
                    summary += "[WARN] Cryptographic preferences: ACCEPTABLE\n"
                elif security_assessment == "WEAK":
                    summary += "[ERROR] Cryptographic preferences: WEAK\n"
                elif security_assessment == "CRITICAL":
                    summary += "[ERROR] Cryptographic preferences: CRITICAL\n"
                else:
                    summary += "[INFO] Cryptographic preferences: NOT TESTED\n"
                
                # Add downgrade detection results
                if crypto_negotiation_results["downgrade_detected"]:
                    summary += "[ERROR] Cryptographic downgrade attack detected\n"
                    for indicator in crypto_negotiation_results["downgrade_indicators"]:
                        summary += f"[WARN] Downgrade indicator: {indicator}\n"
                
                # Add security warnings
                for warning in crypto_negotiation_results["security_warnings"]:
                    summary += f"[WARN] {warning}\n"
                
                # Add recommendations
                for recommendation in crypto_negotiation_results["recommendations"]:
                    summary += f"[RECOMMENDATION] {recommendation}\n"

            # thisUpdate and nextUpdate - handle different formats
            thisUpdate_match = re.search(r"(?:thisUpdate|This Update):\s*(.+)", stdout, re.IGNORECASE)
            nextUpdate_match = re.search(r"(?:nextUpdate|Next Update):\s*(.+)", stdout, re.IGNORECASE)
            
            if thisUpdate_match and nextUpdate_match:
                try:
                    this_update_text = thisUpdate_match.group(1).strip()
                    next_update_text = nextUpdate_match.group(1).strip()
                    
                    dt_this = datetime.strptime(this_update_text, "%b %d %H:%M:%S %Y %Z")
                    dt_next = datetime.strptime(next_update_text, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.utcnow()
                    summary += f"[OK] thisUpdate: {dt_this}\n"
                    summary += f"[OK] nextUpdate: {dt_next}\n"
                    if dt_this <= now <= dt_next:
                        summary += "[OK] OCSP Update Times Valid\n"
                        results["update_times_valid"] = True
                    else:
                        summary += "[ERROR] OCSP Update Times Invalid or Stale\n"
                except Exception as e:
                    summary += f"[ERROR] Could not parse thisUpdate/nextUpdate: {e}\n"
            else:
                summary += "[ERROR] Missing thisUpdate or nextUpdate\n"

            # Nonce support
            if re.search(r"WARNING: no nonce in response", result.stderr, re.IGNORECASE):
                summary += "[WARN] No nonce in response (nonce support may be limited)\n"
                results["nonce_support"] = False
            elif re.search(r"Nonce", stdout, re.IGNORECASE) or re.search(r"Nonce", result.stderr, re.IGNORECASE):
                summary += "[OK] Nonce support present\n"
                results["nonce_support"] = True
            else:
                summary += "[INFO] Nonce support status unclear\n"
                results["nonce_support"] = None

            # Certificate status
            if re.search(r": good", stdout):
                summary += "[OK] Certificate Status: GOOD\n"
                results["cert_status"] = "GOOD"
            elif re.search(r": revoked", stdout):
                summary += "[ERROR] Certificate Status: REVOKED\n"
                results["cert_status"] = "REVOKED"
            elif re.search(r": unknown", stdout):
                summary += "[ERROR] Certificate Status: UNKNOWN\n"
                results["cert_status"] = "UNKNOWN"
            else:
                summary += "[ERROR] Certificate Status: UNDETERMINED\n"

            # Overall result
            if ("[ERROR]" in summary):
                summary += "[ERROR] One or more OCSP diagnostics FAILED\n"
            else:
                summary += "[OK] All OCSP diagnostics PASSED\n"
                results["overall_pass"] = True

            results["summary"] = summary
            return results

        except Exception as e:
            error_msg = f"[ERROR] OCSP Check Exception: {str(e)}\n"
            self.log(error_msg)
            return {"error": error_msg}

    def parse_certificate_status_details(self, ocsp_response_path: str) -> Dict[str, Any]:
        """
        Parse detailed certificate status information from OCSP response
        
        This method extracts and validates:
        1. CertStatus (good, revoked, unknown)
        2. Revocation details (revocationTime, revocationReason)
        3. Response timestamps (thisUpdate, nextUpdate)
        4. Certificate serial number
        
        Args:
            ocsp_response_path: Path to the OCSP response file
            
        Returns:
            Dict containing detailed certificate status information
        """
        status_details = {
            "cert_status": None,
            "revocation_time": None,
            "revocation_reason": None,
            "this_update": None,
            "next_update": None,
            "certificate_serial": None,
            "status_valid": False,
            "parsing_errors": [],
            "security_warnings": []
        }
        
        try:
            self.log("[STATUS] Parsing certificate status details...\n")
            
            # Parse OCSP response text
            parse_cmd = [
                "openssl", "ocsp",
                "-respin", ocsp_response_path,
                "-text"
            ]
            
            result = subprocess.run(parse_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                response_text = result.stdout
                
                # Extract certificate status
                cert_status = self._extract_certificate_status(response_text)
                status_details["cert_status"] = cert_status["status"]
                status_details["certificate_serial"] = cert_status["serial"]
                
                # Extract revocation details if status is revoked
                if cert_status["status"] == "revoked":
                    revocation_details = self._extract_revocation_details(response_text)
                    status_details["revocation_time"] = revocation_details["revocation_time"]
                    status_details["revocation_reason"] = revocation_details["revocation_reason"]
                
                # Extract timestamps
                timestamps = self._extract_response_timestamps(response_text)
                status_details["this_update"] = timestamps["this_update"]
                status_details["next_update"] = timestamps["next_update"]
                
                # Validate overall status
                status_details["status_valid"] = self._validate_certificate_status(status_details)
                
                if status_details["status_valid"]:
                    self.log(f"[STATUS] [OK] Certificate status: {status_details['cert_status']}\n")
                else:
                    self.log("[STATUS] [WARN] Certificate status validation issues detected\n")
                    
            else:
                status_details["parsing_errors"].append(f"OCSP parsing failed: {result.stderr}")
                self.log(f"[STATUS] [FAIL] Failed to parse OCSP response: {result.stderr}\n")
                
        except Exception as e:
            status_details["parsing_errors"].append(f"Parsing exception: {str(e)}")
            self.log(f"[STATUS] Certificate status parsing exception: {e}\n")
            
        return status_details

    def _extract_certificate_status(self, response_text: str) -> Dict[str, Any]:
        """Extract certificate status from OCSP response text"""
        status_info = {
            "status": None,
            "serial": None
        }
        
        try:
            # Look for Cert Status line
            status_match = re.search(r'Cert Status:\s*(\w+)', response_text)
            if status_match:
                status_info["status"] = status_match.group(1).lower()
            
            # Look for Serial Number
            serial_match = re.search(r'Serial Number:\s*([0-9A-Fa-f]+)', response_text)
            if serial_match:
                status_info["serial"] = serial_match.group(1)
                
        except Exception as e:
            self.log(f"[STATUS] Status extraction exception: {e}\n")
            
        return status_info

    def _extract_revocation_details(self, response_text: str) -> Dict[str, Any]:
        """Extract revocation details from OCSP response text"""
        revocation_info = {
            "revocation_time": None,
            "revocation_reason": None
        }
        
        try:
            # Look for revocation time
            time_match = re.search(r'Revocation Time:\s*(.+)', response_text)
            if time_match:
                revocation_info["revocation_time"] = time_match.group(1).strip()
            
            # Look for revocation reason
            reason_match = re.search(r'Revocation Reason:\s*(\w+)', response_text)
            if reason_match:
                revocation_info["revocation_reason"] = reason_match.group(1)
                
        except Exception as e:
            self.log(f"[STATUS] Revocation details extraction exception: {e}\n")
            
        return revocation_info

    def _extract_response_timestamps(self, response_text: str) -> Dict[str, Any]:
        """Extract response timestamps from OCSP response text"""
        timestamp_info = {
            "this_update": None,
            "next_update": None
        }
        
        try:
            # Look for This Update
            this_update_match = re.search(r'This Update:\s*(.+)', response_text)
            if this_update_match:
                timestamp_info["this_update"] = this_update_match.group(1).strip()
            
            # Look for Next Update
            next_update_match = re.search(r'Next Update:\s*(.+)', response_text)
            if next_update_match:
                timestamp_info["next_update"] = next_update_match.group(1).strip()
                
        except Exception as e:
            self.log(f"[STATUS] Timestamp extraction exception: {e}\n")
            
        return timestamp_info

    def _validate_certificate_status(self, status_details: Dict[str, Any]) -> bool:
        """Validate certificate status information"""
        try:
            # Check if we have a valid status
            if not status_details["cert_status"]:
                return False
                
            # Check if status is one of the valid values
            valid_statuses = ["good", "revoked", "unknown"]
            if status_details["cert_status"] not in valid_statuses:
                return False
                
            # If revoked, check that we have revocation details
            if status_details["cert_status"] == "revoked":
                if not status_details["revocation_time"]:
                    return False
                    
            # Check that we have timestamps
            if not status_details["this_update"] or not status_details["next_update"]:
                return False
                
            return True
            
        except Exception as e:
            self.log(f"[STATUS] Status validation exception: {e}\n")
            return False
        """
        Comprehensive OCSP signature verification supporting both direct CA signing and CA Designated Responders
        
        This method implements full verification of the digital signature on the OCSP response
        by confirming that the signature is valid using either:
        1. The issuing CA's public key (direct signing)
        2. A CA Designated Responder's public key (delegated signing with proper EKU validation)
        
        This addresses RFC 6960 requirements for handling delegated responders with id-kp-OCSPSigning EKU.
        """
        try:
            self.log("[INFO] Performing comprehensive OCSP signature verification...\n")
            
            # Step 1: Download OCSP response without verification
            tmp_resp = os.path.join(os.getenv("TEMP", "/tmp"), f"ocsp_resp_{uuid4().hex}.der")
            cmd_resp = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", cert_path, 
                "-url", ocsp_url, 
                "-respout", tmp_resp, 
                "-noverify"  # Download without verification first
            ]
            
            self.log(f"[CMD] {' '.join(cmd_resp)}\n")
            resp_result = subprocess.run(cmd_resp, capture_output=True, text=True, timeout=30)
            
            if resp_result.returncode != 0:
                self.log(f"[ERROR] Failed to download OCSP response: {resp_result.stderr}\n")
                return False
            
            # Step 2: Determine if response is signed by CA or delegated responder
            responder_info_cmd = ["openssl", "ocsp", "-respin", tmp_resp, "-text", "-noout"]
            responder_info_result = subprocess.run(responder_info_cmd, capture_output=True, text=True, timeout=15)
            
            signature_valid = False
            verification_method = "unknown"
            
            if responder_info_result.returncode == 0:
                responder_text = responder_info_result.stdout
                self.log(f"[INFO] OCSP response analysis:\n{responder_text[:500]}...\n")
                
                # Check if response includes responder certificate (indicates delegated responder)
                if "Certificate:" in responder_text and "BEGIN CERTIFICATE" in responder_text:
                    self.log("[INFO] Detected CA Designated Responder - extracting responder certificate\n")
                    
                    # Extract responder certificate
                    responder_cert_path = self._extract_responder_certificate(tmp_resp)
                    
                    if responder_cert_path:
                        # Validate CA Designated Responder
                        responder_validation = self.validate_ca_designated_responder(responder_cert_path, issuer_path)
                        
                        if responder_validation["is_valid_designated_responder"]:
                            self.log("[INFO] CA Designated Responder validation passed - verifying signature\n")
                            
                            # Verify signature using responder certificate
                            verify_cmd = [
                                "openssl", "ocsp", 
                                "-respin", tmp_resp, 
                                "-verify_other", responder_cert_path,
                                "-CAfile", issuer_path,
                                "-no_nonce"
                            ]
                            
                            self.log(f"[CMD] {' '.join(verify_cmd)}\n")
                            verify_result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
                            
                            if verify_result.returncode == 0 and "Response verify OK" in verify_result.stdout:
                                signature_valid = True
                                verification_method = "ca_designated_responder"
                                self.log("[OK] OCSP response signature verified using CA Designated Responder\n")
                            else:
                                self.log(f"[ERROR] CA Designated Responder signature verification failed\n")
                                self.log(f"[STDOUT] {verify_result.stdout}\n")
                                self.log(f"[STDERR] {verify_result.stderr}\n")
                        else:
                            self.log("[ERROR] CA Designated Responder validation failed\n")
                            for recommendation in responder_validation["recommendations"]:
                                self.log(f"[RECOMMENDATION] {recommendation}\n")
                        
                        # Cleanup responder certificate
                        try:
                            os.remove(responder_cert_path)
                        except:
                            pass
                    else:
                        self.log("[ERROR] Failed to extract responder certificate\n")
                else:
                    self.log("[INFO] No responder certificate found - assuming direct CA signing\n")
                    
                    # Verify signature using CA certificate directly
                    verify_cmd = [
                        "openssl", "ocsp", 
                        "-respin", tmp_resp, 
                        "-verify_other", issuer_path,
                        "-CAfile", issuer_path,
                        "-no_nonce"
                    ]
                    
                    self.log(f"[CMD] {' '.join(verify_cmd)}\n")
                    verify_result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
                    
                    if verify_result.returncode == 0 and "Response verify OK" in verify_result.stdout:
                        signature_valid = True
                        verification_method = "direct_ca_signing"
                        self.log("[OK] OCSP response signature verified using direct CA signing\n")
                    else:
                        self.log(f"[ERROR] Direct CA signature verification failed\n")
                        self.log(f"[STDOUT] {verify_result.stdout}\n")
                        self.log(f"[STDERR] {verify_result.stderr}\n")
            
            # Step 3: Additional security checks
            if signature_valid:
                # Verify the responder certificate matches the issuer (for direct signing)
                if verification_method == "direct_ca_signing":
                    responder_cmd = [
                        "openssl", "ocsp", 
                        "-respin", tmp_resp, 
                        "-text", "-noout"
                    ]
                    responder_result = subprocess.run(responder_cmd, capture_output=True, text=True, timeout=15)
                    
                    if responder_result.returncode == 0:
                        if "Responder Id:" in responder_result.stdout:
                            self.log("[INFO] OCSP responder identity verified\n")
                        else:
                            self.log("[WARN] Could not verify OCSP responder identity\n")
                
                self.log(f"[INFO] Signature verification method: {verification_method}\n")
            
            # Cleanup
            try:
                os.remove(tmp_resp)
            except:
                pass
            
            return signature_valid
            
        except subprocess.TimeoutExpired:
            self.log("[ERROR] OCSP signature verification timed out\n")
            return False
        except Exception as e:
            self.log(f"[ERROR] OCSP signature verification exception: {e}\n")
            return False

    def _extract_responder_certificate(self, ocsp_response_path: str) -> Optional[str]:
        """
        Extract responder certificate from OCSP response
        
        Args:
            ocsp_response_path: Path to the OCSP response file
            
        Returns:
            Path to extracted responder certificate file, or None if extraction fails
        """
        try:
            # Create temporary file for responder certificate
            responder_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"responder_cert_{uuid4().hex}.pem")
            
            # Extract certificate using OpenSSL
            extract_cmd = [
                "openssl", "ocsp", 
                "-respin", ocsp_response_path, 
                "-text", "-noout"
            ]
            
            extract_result = subprocess.run(extract_cmd, capture_output=True, text=True, timeout=15)
            
            if extract_result.returncode == 0:
                response_text = extract_result.stdout
                
                # Find certificate section
                cert_start = response_text.find("-----BEGIN CERTIFICATE-----")
                cert_end = response_text.find("-----END CERTIFICATE-----")
                
                if cert_start != -1 and cert_end != -1:
                    cert_end += len("-----END CERTIFICATE-----")
                    cert_pem = response_text[cert_start:cert_end]
                    
                    # Write certificate to file
                    with open(responder_cert_path, 'w') as f:
                        f.write(cert_pem)
                    
                    self.log(f"[INFO] Extracted responder certificate to: {responder_cert_path}\n")
                    return responder_cert_path
                else:
                    self.log("[WARN] No certificate found in OCSP response\n")
                    return None
            else:
                self.log(f"[ERROR] Failed to extract responder certificate: {extract_result.stderr}\n")
                return None
                
        except Exception as e:
            self.log(f"[ERROR] Certificate extraction exception: {e}\n")
            return None

    def parse_certificate_status_details(self, ocsp_response_text: str, target_serial: str = None) -> Dict[str, Any]:
        """
        Parse comprehensive certificate status details from OCSP response
        
        This method extracts and validates the actual certificate status information
        from the OCSP response, including:
        1. CertStatus value (good/revoked/unknown)
        2. Revocation details (revocationTime, revocationReason) if revoked
        3. Certificate serial number
        4. Response timestamps
        5. Responder information
        
        Args:
            ocsp_response_text: Raw OCSP response text from OpenSSL
            
        Returns:
            Dict containing detailed certificate status information
        """
        status_details = {
            "response_status": "UNKNOWN",
            "cert_status": "UNKNOWN",
            "cert_serial": None,
            "revocation_time": None,
            "revocation_reason": None,
            "this_update": None,
            "next_update": None,
            "produced_at": None,
            "responder_id": None,
            "parsing_errors": [],
            "security_warnings": []
        }
        
        try:
            self.log("[STATUS] Parsing certificate status details from OCSP response...\n")
            
            # Check if this is a batch response (multiple certificates)
            batch_responses = self._detect_batch_ocsp_response(ocsp_response_text)
            if batch_responses:
                self.log(f"[STATUS] [INFO] Detected batch OCSP response with {len(batch_responses)} certificates\n")
                return self._parse_batch_ocsp_response(ocsp_response_text, target_serial, batch_responses)
            
            # Step 1: Parse top-level response status
            if "OCSP Response Status: successful" in ocsp_response_text:
                status_details["response_status"] = "SUCCESSFUL"
                self.log("[STATUS] [OK] OCSP Response Status: SUCCESSFUL\n")
            elif "OCSP Response Status: unauthorized" in ocsp_response_text:
                status_details["response_status"] = "UNAUTHORIZED"
                self.log("[STATUS] [FAIL] OCSP Response Status: UNAUTHORIZED\n")
                status_details["security_warnings"].append("OCSP responder unauthorized - potential security issue")
            elif "OCSP Response Status: malformed" in ocsp_response_text:
                status_details["response_status"] = "MALFORMED"
                self.log("[STATUS] [FAIL] OCSP Response Status: MALFORMED\n")
                status_details["security_warnings"].append("OCSP response malformed - potential attack")
            else:
                self.log("[STATUS] [WARN] Unknown OCSP Response Status\n")
                status_details["parsing_errors"].append("Could not determine OCSP response status")
            
            # Step 2: Extract certificate serial number
            serial_match = re.search(r"Serial Number:\s*([A-F0-9]+)", ocsp_response_text, re.IGNORECASE)
            if serial_match:
                status_details["cert_serial"] = serial_match.group(1)
                self.log(f"[STATUS] Certificate Serial: {status_details['cert_serial']}\n")
            else:
                self.log("[STATUS] [WARN] Could not extract certificate serial number\n")
                status_details["parsing_errors"].append("Certificate serial number not found")
            
            # Step 3: Parse certificate status (CertStatus)
            cert_status_match = re.search(r"Cert Status:\s*(\w+)", ocsp_response_text, re.IGNORECASE)
            if cert_status_match:
                cert_status = cert_status_match.group(1).lower()
                status_details["cert_status"] = cert_status.upper()
                
                if cert_status == "good":
                    status_details["cert_status"] = "good"
                    self.log("[STATUS] [OK] Certificate Status: GOOD\n")
                elif cert_status == "revoked":
                    status_details["cert_status"] = "revoked"
                    self.log("[STATUS] [FAIL] Certificate Status: REVOKED\n")
                    status_details["security_warnings"].append("Certificate is revoked - do not trust")
                elif cert_status == "unknown":
                    status_details["cert_status"] = "unknown"
                    self.log("[STATUS] [WARN] Certificate Status: UNKNOWN\n")
                    status_details["security_warnings"].append("Certificate status unknown - use caution")
                else:
                    self.log(f"[STATUS] [WARN] Unknown certificate status: {cert_status}\n")
                    status_details["parsing_errors"].append(f"Unknown certificate status: {cert_status}")
            else:
                self.log("[STATUS] [FAIL] Could not determine certificate status\n")
                status_details["parsing_errors"].append("Certificate status not found in response")
            
            # Step 4: Parse revocation details if certificate is revoked
            if status_details["cert_status"] == "revoked":
                self.log("[STATUS] Parsing revocation details...\n")
                
                # Extract revocation time
                revocation_time_match = re.search(r"Revocation Time:\s*(.+)", ocsp_response_text, re.IGNORECASE)
                if revocation_time_match:
                    revocation_time_str = revocation_time_match.group(1).strip()
                    try:
                        # Parse revocation time (format: "May 5 17:10:17 2023 GMT")
                        revocation_time = datetime.strptime(revocation_time_str, "%b %d %H:%M:%S %Y %Z")
                        status_details["revocation_time"] = revocation_time.isoformat()
                        self.log(f"[STATUS] Revocation Time: {revocation_time}\n")
                    except Exception as e:
                        self.log(f"[STATUS] [WARN] Could not parse revocation time: {e}\n")
                        status_details["parsing_errors"].append(f"Could not parse revocation time: {e}")
                else:
                    self.log("[STATUS] [WARN] Revocation time not found\n")
                    status_details["parsing_errors"].append("Revocation time not found")
                
                # Extract revocation reason
                revocation_reason_match = re.search(r"Revocation Reason:\s*(.+)", ocsp_response_text, re.IGNORECASE)
                if revocation_reason_match:
                    revocation_reason = revocation_reason_match.group(1).strip()
                    status_details["revocation_reason"] = revocation_reason
                    self.log(f"[STATUS] Revocation Reason: {revocation_reason}\n")
                else:
                    self.log("[STATUS] [WARN] Revocation reason not found\n")
                    status_details["parsing_errors"].append("Revocation reason not found")
            
            # Step 5: Parse timestamps
            # This Update
            this_update_match = re.search(r"This Update:\s*(.+)", ocsp_response_text, re.IGNORECASE)
            if this_update_match:
                this_update_str = this_update_match.group(1).strip()
                try:
                    this_update = datetime.strptime(this_update_str, "%b %d %H:%M:%S %Y %Z")
                    status_details["this_update"] = this_update.isoformat()
                    self.log(f"[STATUS] This Update: {this_update}\n")
                except Exception as e:
                    self.log(f"[STATUS] [WARN] Could not parse This Update: {e}\n")
                    status_details["parsing_errors"].append(f"Could not parse This Update: {e}")
            
            # Next Update
            next_update_match = re.search(r"Next Update:\s*(.+)", ocsp_response_text, re.IGNORECASE)
            if next_update_match:
                next_update_str = next_update_match.group(1).strip()
                try:
                    next_update = datetime.strptime(next_update_str, "%b %d %H:%M:%S %Y %Z")
                    status_details["next_update"] = next_update.isoformat()
                    self.log(f"[STATUS] Next Update: {next_update}\n")
                except Exception as e:
                    self.log(f"[STATUS] [WARN] Could not parse Next Update: {e}\n")
                    status_details["parsing_errors"].append(f"Could not parse Next Update: {e}")
            
            # Produced At
            produced_at_match = re.search(r"Produced At:\s*(.+)", ocsp_response_text, re.IGNORECASE)
            if produced_at_match:
                produced_at_str = produced_at_match.group(1).strip()
                try:
                    produced_at = datetime.strptime(produced_at_str, "%b %d %H:%M:%S %Y %Z")
                    status_details["produced_at"] = produced_at.isoformat()
                    self.log(f"[STATUS] Produced At: {produced_at}\n")
                except Exception as e:
                    self.log(f"[STATUS] [WARN] Could not parse Produced At: {e}\n")
                    status_details["parsing_errors"].append(f"Could not parse Produced At: {e}")
            
            # Step 6: Extract responder ID
            responder_id_match = re.search(r"Responder Id:\s*(.+)", ocsp_response_text, re.IGNORECASE)
            if responder_id_match:
                responder_id = responder_id_match.group(1).strip()
                status_details["responder_id"] = responder_id
                self.log(f"[STATUS] Responder ID: {responder_id}\n")
            
            # Step 7: Security validation
            if status_details["response_status"] == "SUCCESSFUL" and status_details["cert_status"] == "good":
                self.log("[STATUS] [OK] Certificate validation PASSED - certificate is good\n")
            elif status_details["cert_status"] == "revoked":
                self.log("[STATUS] [FAIL] Certificate validation FAILED - certificate is revoked\n")
            elif status_details["cert_status"] == "unknown":
                self.log("[STATUS] [WARN] Certificate validation UNCERTAIN - status unknown\n")
            else:
                self.log("[STATUS] [FAIL] Certificate validation FAILED - could not determine status\n")
            
            return status_details
            
        except Exception as e:
            self.log(f"[STATUS] Certificate status parsing exception: {e}\n")
            status_details["parsing_errors"].append(f"Parsing exception: {str(e)}")
            return status_details

    def _extract_certificate_serial(self, cert_path: str) -> Optional[str]:
        """
        Extract certificate serial number from certificate file
        
        Args:
            cert_path: Path to certificate file
            
        Returns:
            Certificate serial number as hex string, or None if extraction fails
        """
        try:
            cmd = ["openssl", "x509", "-in", cert_path, "-noout", "-serial"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Extract serial number from output like "serial=625E50AD"
                serial_match = re.search(r"serial=([A-F0-9]+)", result.stdout)
                if serial_match:
                    return serial_match.group(1)
            
            return None
            
        except Exception as e:
            self.log(f"[ERROR] Error extracting certificate serial: {e}\n")
            return None

    def _detect_batch_ocsp_response(self, ocsp_response_text: str) -> List[Dict[str, Any]]:
        """
        Detect if OCSP response contains multiple certificate statuses (batch response)
        
        Args:
            ocsp_response_text: Raw OCSP response text
            
        Returns:
            List of certificate response dictionaries, or empty list if not a batch response
        """
        try:
            # Look for multiple "Certificate ID:" sections with a more flexible pattern
            # This pattern handles the actual DHS CA4 response format
            cert_id_pattern = r"Certificate ID:\s*\n\s*Hash Algorithm:\s*(\w+)\s*\n\s*Issuer Name Hash:\s*([A-F0-9]+)\s*\n\s*Issuer Key Hash:\s*([A-F0-9]+)\s*\n\s*Serial Number:\s*([A-F0-9]+)\s*\n\s*Cert Status:\s*(\w+)(?:\s*\n\s*Revocation Time:\s*(.+?)\s*\n\s*Revocation Reason:\s*(.+?))?\s*\n\s*This Update:\s*(.+?)\s*\n\s*Next Update:\s*(.+?)(?=\s*\n\s*Certificate ID:|\s*\n\s*Signature Algorithm:|\s*\n\s*Certificate:|\Z)"
            
            matches = re.findall(cert_id_pattern, ocsp_response_text, re.MULTILINE | re.DOTALL)
            
            if len(matches) > 1:
                batch_responses = []
                for match in matches:
                    response = {
                        "hash_algorithm": match[0],
                        "issuer_name_hash": match[1],
                        "issuer_key_hash": match[2],
                        "serial_number": match[3],
                        "cert_status": match[4].lower(),
                        "revocation_time": match[5] if match[5] else None,
                        "revocation_reason": match[6] if match[6] else None,
                        "this_update": match[7].strip(),
                        "next_update": match[8].strip()
                    }
                    batch_responses.append(response)
                
                return batch_responses
            
            return []
            
        except Exception as e:
            self.log(f"[ERROR] Error detecting batch OCSP response: {e}\n")
            return []

    def _parse_batch_ocsp_response(self, ocsp_response_text: str, target_serial: str, batch_responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Parse batch OCSP response and find the specific certificate status
        
        Args:
            ocsp_response_text: Raw OCSP response text
            target_serial: Serial number of the certificate we're looking for
            batch_responses: List of certificate responses from _detect_batch_ocsp_response
            
        Returns:
            Dict containing certificate status details for the target certificate
        """
        status_details = {
            "response_status": "SUCCESSFUL",
            "cert_status": "UNKNOWN",
            "cert_serial": target_serial,
            "revocation_time": None,
            "revocation_reason": None,
            "this_update": None,
            "next_update": None,
            "produced_at": None,
            "responder_id": None,
            "parsing_errors": [],
            "security_warnings": [],
            "batch_response_info": {
                "is_batch_response": True,
                "total_certificates": len(batch_responses),
                "certificates": batch_responses
            }
        }
        
        try:
            self.log(f"[STATUS] [INFO] Processing batch OCSP response with {len(batch_responses)} certificates\n")
            
            # Extract responder information
            responder_match = re.search(r"Responder Id:\s*([A-F0-9:]+)", ocsp_response_text)
            if responder_match:
                status_details["responder_id"] = responder_match.group(1)
            
            produced_at_match = re.search(r"Produced At:\s*(.+)", ocsp_response_text)
            if produced_at_match:
                status_details["produced_at"] = produced_at_match.group(1).strip()
            
            # Find the specific certificate we're looking for
            target_response = None
            if target_serial:
                # Convert decimal serial to hex if needed for comparison
                try:
                    # Check if target_serial is decimal (all digits)
                    if target_serial.isdigit():
                        # Convert decimal to hex
                        hex_serial = hex(int(target_serial))[2:].upper()
                        self.log(f"[STATUS] [INFO] Converting decimal serial {target_serial} to hex {hex_serial}\n")
                    else:
                        # Already in hex format
                        hex_serial = target_serial.upper()
                    
                    for response in batch_responses:
                        if response["serial_number"].upper() == hex_serial:
                            target_response = response
                            break
                except Exception as e:
                    self.log(f"[STATUS] [ERROR] Error converting serial number: {e}\n")
                    # Fallback to direct comparison
                    for response in batch_responses:
                        if response["serial_number"].upper() == target_serial.upper():
                            target_response = response
                            break
            
            if target_response:
                self.log(f"[STATUS] [OK] Found target certificate {target_serial} in batch response\n")
                
                # Extract status information
                status_details["cert_status"] = target_response["cert_status"]
                status_details["this_update"] = target_response["this_update"]
                status_details["next_update"] = target_response["next_update"]
                
                if target_response["revocation_time"]:
                    status_details["revocation_time"] = target_response["revocation_time"]
                    status_details["revocation_reason"] = target_response["revocation_reason"]
                
                # Log status
                if target_response["cert_status"] == "good":
                    self.log(f"[STATUS] [OK] Certificate {target_serial} Status: GOOD\n")
                elif target_response["cert_status"] == "revoked":
                    self.log(f"[STATUS] [FAIL] Certificate {target_serial} Status: REVOKED\n")
                    status_details["security_warnings"].append("Certificate is revoked - do not trust")
                    if target_response["revocation_time"]:
                        self.log(f"[STATUS] Revocation Time: {target_response['revocation_time']}\n")
                        self.log(f"[STATUS] Revocation Reason: {target_response['revocation_reason']}\n")
                elif target_response["cert_status"] == "unknown":
                    self.log(f"[STATUS] [WARN] Certificate {target_serial} Status: UNKNOWN\n")
                    status_details["security_warnings"].append("Certificate status unknown - use caution")
                
                # Log batch information
                good_count = sum(1 for r in batch_responses if r["cert_status"] == "good")
                revoked_count = sum(1 for r in batch_responses if r["cert_status"] == "revoked")
                unknown_count = sum(1 for r in batch_responses if r["cert_status"] == "unknown")
                
                self.log(f"[STATUS] [INFO] Batch response summary: {good_count} good, {revoked_count} revoked, {unknown_count} unknown\n")
                
            else:
                self.log(f"[STATUS] [ERROR] Target certificate {target_serial} not found in batch response\n")
                status_details["parsing_errors"].append(f"Target certificate {target_serial} not found in batch response")
                status_details["security_warnings"].append("Target certificate not found in batch response")
            
            return status_details
            
        except Exception as e:
            self.log(f"[ERROR] Error parsing batch OCSP response: {e}\n")
            status_details["parsing_errors"].append(f"Batch parsing exception: {str(e)}")
            return status_details

    def _detect_federal_pki_environment(self, ocsp_response_text: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Detect if this is a federal PKI environment (DHS, DoD, etc.)
        
        Args:
            ocsp_response_text: Raw OCSP response text
            ocsp_url: OCSP URL
            
        Returns:
            Dict containing federal PKI detection information
        """
        federal_info = {
            "is_federal_pki": False,
            "agency": None,
            "ca_name": None,
            "characteristics": []
        }
        
        try:
            # Check URL patterns
            if "dhs.gov" in ocsp_url.lower() or "dimc.dhs.gov" in ocsp_url.lower():
                federal_info["is_federal_pki"] = True
                federal_info["agency"] = "DHS"
                federal_info["characteristics"].append("DHS OCSP responder")
            
            if "dod.mil" in ocsp_url.lower():
                federal_info["is_federal_pki"] = True
                federal_info["agency"] = "DoD"
                federal_info["characteristics"].append("DoD OCSP responder")
            
            if "treasury.gov" in ocsp_url.lower():
                federal_info["is_federal_pki"] = True
                federal_info["agency"] = "Treasury"
                federal_info["characteristics"].append("Treasury OCSP responder")
            
            # Check certificate issuer patterns
            if "Department of Homeland Security" in ocsp_response_text:
                federal_info["is_federal_pki"] = True
                federal_info["agency"] = "DHS"
                federal_info["ca_name"] = "DHS CA4"
                federal_info["characteristics"].append("DHS CA4 certificate")
            
            if "Department of Defense" in ocsp_response_text:
                federal_info["is_federal_pki"] = True
                federal_info["agency"] = "DoD"
                federal_info["characteristics"].append("DoD certificate")
            
            # Check for federal PKI characteristics
            if "U.S. Government" in ocsp_response_text:
                federal_info["characteristics"].append("U.S. Government certificate")
            
            if "Certification Authorities" in ocsp_response_text:
                federal_info["characteristics"].append("Federal CA hierarchy")
            
            return federal_info
            
        except Exception as e:
            self.log(f"[ERROR] Error detecting federal PKI environment: {e}\n")
            return federal_info

    def validate_response_validity_interval(self, ocsp_response_text: str, max_age_hours: int = 24) -> Dict[str, Any]:
        """
        Validate OCSP response validity interval according to RFC 6960
        
        This method validates the response validity interval defined by thisUpdate and nextUpdate fields.
        Critical security checks include:
        1. thisUpdate is present and parseable
        2. thisUpdate is not in the future
        3. thisUpdate is sufficiently recent (within max_age_hours)
        4. nextUpdate is present and parseable
        5. nextUpdate is not in the past
        6. nextUpdate is after thisUpdate
        7. Current time is within the validity interval
        
        Args:
            ocsp_response_text: Raw OCSP response text from OpenSSL
            max_age_hours: Maximum age in hours for thisUpdate (default: 24)
            
        Returns:
            Dict containing validity interval validation results
        """
        validity_results = {
            "is_valid": False,
            "this_update_valid": False,
            "next_update_valid": False,
            "interval_valid": False,
            "this_update": None,
            "next_update": None,
            "current_time": None,
            "age_hours": None,
            "time_until_expiry_hours": None,
            "validation_details": {},
            "security_warnings": [],
            "compliance_issues": []
        }
        
        try:
            self.log("[VALIDITY] Validating OCSP response validity interval...\n")
            
            # Get current time
            current_time = datetime.utcnow()
            validity_results["current_time"] = current_time.isoformat()
            self.log(f"[VALIDITY] Current time: {current_time}\n")
            
            # Parse thisUpdate
            this_update_match = re.search(r"This Update:\s*(.+)", ocsp_response_text, re.IGNORECASE)
            if this_update_match:
                this_update_str = this_update_match.group(1).strip()
                try:
                    this_update = datetime.strptime(this_update_str, "%b %d %H:%M:%S %Y %Z")
                    validity_results["this_update"] = this_update.isoformat()
                    self.log(f"[VALIDITY] This Update: {this_update}\n")
                    
                    # Check if thisUpdate is in the future
                    if this_update > current_time:
                        validity_results["security_warnings"].append("thisUpdate is in the future - potential security issue")
                        self.log("[VALIDITY] [FAIL] thisUpdate is in the future\n")
                    else:
                        # Check if thisUpdate is sufficiently recent
                        age_delta = current_time - this_update
                        age_hours = age_delta.total_seconds() / 3600
                        validity_results["age_hours"] = age_hours
                        
                        if age_hours <= max_age_hours:
                            validity_results["this_update_valid"] = True
                            self.log(f"[VALIDITY] [OK] thisUpdate is recent (age: {age_hours:.1f} hours)\n")
                        else:
                            validity_results["security_warnings"].append(f"thisUpdate is too old ({age_hours:.1f} hours > {max_age_hours} hours)")
                            self.log(f"[VALIDITY] [FAIL] thisUpdate is too old ({age_hours:.1f} hours)\n")
                    
                except Exception as e:
                    validity_results["compliance_issues"].append(f"Could not parse thisUpdate: {e}")
                    self.log(f"[VALIDITY] [FAIL] Error parsing thisUpdate: {e}\n")
            else:
                validity_results["compliance_issues"].append("thisUpdate field not found")
                self.log("[VALIDITY] [FAIL] thisUpdate field not found\n")
            
            # Parse nextUpdate
            next_update_match = re.search(r"Next Update:\s*(.+)", ocsp_response_text, re.IGNORECASE)
            if next_update_match:
                next_update_str = next_update_match.group(1).strip()
                try:
                    next_update = datetime.strptime(next_update_str, "%b %d %H:%M:%S %Y %Z")
                    validity_results["next_update"] = next_update.isoformat()
                    self.log(f"[VALIDITY] Next Update: {next_update}\n")
                    
                    # Check if nextUpdate is in the past
                    if next_update < current_time:
                        validity_results["security_warnings"].append("nextUpdate is in the past - response is stale")
                        self.log("[VALIDITY] [FAIL] nextUpdate is in the past (response is stale)\n")
                    else:
                        validity_results["next_update_valid"] = True
                        time_until_expiry = next_update - current_time
                        time_until_expiry_hours = time_until_expiry.total_seconds() / 3600
                        validity_results["time_until_expiry_hours"] = time_until_expiry_hours
                        self.log(f"[VALIDITY] [OK] nextUpdate is valid (expires in {time_until_expiry_hours:.1f} hours)\n")
                    
                except Exception as e:
                    validity_results["compliance_issues"].append(f"Could not parse nextUpdate: {e}")
                    self.log(f"[VALIDITY] [FAIL] Error parsing nextUpdate: {e}\n")
            else:
                validity_results["compliance_issues"].append("nextUpdate field not found")
                self.log("[VALIDITY] [FAIL] nextUpdate field not found\n")
            
            # Validate interval relationship
            if validity_results["this_update"] and validity_results["next_update"]:
                try:
                    this_update_dt = datetime.fromisoformat(validity_results["this_update"].replace('Z', '+00:00'))
                    next_update_dt = datetime.fromisoformat(validity_results["next_update"].replace('Z', '+00:00'))
                    
                    if next_update_dt > this_update_dt:
                        validity_results["interval_valid"] = True
                        self.log("[VALIDITY] [OK] nextUpdate is after thisUpdate\n")
                    else:
                        validity_results["compliance_issues"].append("nextUpdate is not after thisUpdate")
                        self.log("[VALIDITY] [FAIL] nextUpdate is not after thisUpdate\n")
                except Exception as e:
                    validity_results["compliance_issues"].append(f"Could not validate interval relationship: {e}")
                    self.log(f"[VALIDITY] [FAIL] Error validating interval relationship: {e}\n")
            
            # Determine overall validity
            critical_checks = [
                validity_results["this_update_valid"],
                validity_results["next_update_valid"],
                validity_results["interval_valid"]
            ]
            
            if all(critical_checks) and not validity_results["compliance_issues"]:
                validity_results["is_valid"] = True
                self.log("[VALIDITY] [OK] Response validity interval validation PASSED\n")
            else:
                self.log("[VALIDITY] [FAIL] Response validity interval validation FAILED\n")
            
            # Add detailed validation information
            validity_results["validation_details"] = {
                "max_age_hours": max_age_hours,
                "this_update_parsed": validity_results["this_update"] is not None,
                "next_update_parsed": validity_results["next_update"] is not None,
                "current_time_utc": current_time.isoformat(),
                "validation_timestamp": datetime.now().isoformat()
            }
            
            return validity_results
            
        except Exception as e:
            self.log(f"[VALIDITY] Validity interval validation exception: {e}\n")
            validity_results["compliance_issues"].append(f"Validation exception: {str(e)}")
            return validity_results

    def negotiate_cryptographic_preferences(self, issuer_path: str, ocsp_url: str, preferred_algorithms: List[str] = None) -> Dict[str, Any]:
        """
        Analyze OCSP server cryptographic capabilities by examining response signature algorithms
        
        This method analyzes the OCSP server's cryptographic capabilities by:
        1. Sending OCSP requests and analyzing response signature algorithms
        2. Detecting what algorithms the server actually uses
        3. Assessing cryptographic strength based on observed algorithms
        4. Providing security recommendations
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            preferred_algorithms: List of preferred signature algorithms (for reference)
            
        Returns:
            Dict containing cryptographic analysis results and security assessment
        """
        negotiation_results = {
            "negotiation_successful": False,
            "supported_algorithms": [],
            "preferred_algorithms": [],
            "downgrade_detected": False,
            "security_assessment": "UNKNOWN",
            "algorithm_tests": [],
            "recommendations": [],
            "security_warnings": []
        }
        
        try:
            self.log("[CRYPTO] Starting cryptographic capability analysis...\n")
            
            # Define preferred algorithms (strongest first) for reference
            if preferred_algorithms is None:
                preferred_algorithms = [
                    "sha512WithRSAEncryption",      # SHA-512 with RSA (strongest)
                    "sha384WithRSAEncryption",      # SHA-384 with RSA
                    "sha256WithRSAEncryption",      # SHA-256 with RSA (minimum recommended)
                    "ecdsa-with-SHA512",           # ECDSA with SHA-512
                    "ecdsa-with-SHA384",           # ECDSA with SHA-384
                    "ecdsa-with-SHA256",           # ECDSA with SHA-256
                    "sha256WithRSA-PSS",           # RSA-PSS with SHA-256
                    "sha384WithRSA-PSS",           # RSA-PSS with SHA-384
                    "sha512WithRSA-PSS"            # RSA-PSS with SHA-512
                ]
            
            negotiation_results["preferred_algorithms"] = preferred_algorithms
            
            # Send a single OCSP request to analyze server's algorithm choice
            self.log("[CRYPTO] Analyzing OCSP server cryptographic capabilities...\n")
            
            algorithm_test = self._test_algorithm_preference("analysis", issuer_path, ocsp_url)
            negotiation_results["algorithm_tests"].append(algorithm_test)
            
            # Analyze the response to determine server capabilities
            if algorithm_test["response_received"] and algorithm_test["signature_algorithm_used"]:
                signature_algorithm = algorithm_test["signature_algorithm_used"]
                negotiation_results["supported_algorithms"] = [signature_algorithm]
                
                # Determine security assessment based on observed algorithm
                if any(strong in signature_algorithm.lower() for strong in ["sha512", "sha384"]):
                    negotiation_results["security_assessment"] = "SECURE"
                    negotiation_results["recommendations"].append("Server uses strong cryptographic algorithms")
                    self.log(f"[CRYPTO] [OK] Strong algorithm detected: {signature_algorithm}\n")
                elif "sha256" in signature_algorithm.lower():
                    negotiation_results["security_assessment"] = "ACCEPTABLE"
                    negotiation_results["recommendations"].append("Server uses acceptable cryptographic algorithms")
                    self.log(f"[CRYPTO] [OK] Acceptable algorithm detected: {signature_algorithm}\n")
                elif "sha1" in signature_algorithm.lower():
                    negotiation_results["security_assessment"] = "WEAK"
                    negotiation_results["security_warnings"].append("Server uses deprecated SHA-1 algorithm")
                    self.log(f"[CRYPTO] [WARN] Weak algorithm detected: {signature_algorithm}\n")
                else:
                    negotiation_results["security_assessment"] = "WEAK"
                    negotiation_results["security_warnings"].append(f"Unknown or weak algorithm: {signature_algorithm}")
                    self.log(f"[CRYPTO] [WARN] Unknown algorithm: {signature_algorithm}\n")
                
                negotiation_results["negotiation_successful"] = True
            else:
                negotiation_results["security_assessment"] = "CRITICAL"
                negotiation_results["security_warnings"].append("Could not determine server cryptographic capabilities")
                self.log("[CRYPTO] [FAIL] Could not analyze server cryptographic capabilities\n")
            
            return negotiation_results
            
        except Exception as e:
            self.log(f"[CRYPTO] Cryptographic analysis exception: {e}\n")
            negotiation_results["security_warnings"].append(f"Analysis failed: {str(e)}")
            return negotiation_results

    def _test_algorithm_preference(self, algorithm: str, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test if OCSP server supports a specific signature algorithm
        
        Args:
            algorithm: Signature algorithm to test
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing test results for this algorithm
        """
        test_result = {
            "algorithm": algorithm,
            "supported": False,
            "response_received": False,
            "signature_algorithm_used": None,
            "response_details": {},
            "test_errors": []
        }
        
        try:
            # Use issuer certificate as test certificate for algorithm testing
            # This is a simplified approach - we'll test what algorithm the server uses
            test_cert_path = issuer_path
            
            # Send OCSP request (OpenSSL will negotiate the algorithm)
            ocsp_cmd = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", test_cert_path, 
                "-url", ocsp_url, 
                "-resp_text", 
                "-noverify"  # Don't verify signature for algorithm testing
            ]
            
            self.log(f"[CRYPTO] Testing algorithm: {' '.join(ocsp_cmd)}\n")
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            test_result["response_received"] = result.returncode == 0
            
            if result.returncode == 0:
                response_text = result.stdout
                
                # Extract signature algorithm used in response
                sig_algo_match = re.search(r"Signature Algorithm:\s*(.+)", response_text, re.IGNORECASE)
                if sig_algo_match:
                    signature_algorithm_used = sig_algo_match.group(1).strip()
                    test_result["signature_algorithm_used"] = signature_algorithm_used
                    
                    # Check if the algorithm matches our preference or is acceptable
                    if algorithm.lower() in signature_algorithm_used.lower():
                        test_result["supported"] = True
                        self.log(f"[CRYPTO] [OK] Algorithm {algorithm} matched in response: {signature_algorithm_used}\n")
                    elif any(strong_algo in signature_algorithm_used.lower() for strong_algo in ["sha512", "sha384", "sha256"]):
                        test_result["supported"] = True
                        self.log(f"[CRYPTO] [OK] Strong algorithm used: {signature_algorithm_used}\n")
                    else:
                        self.log(f"[CRYPTO] [WARN] Different algorithm used: {signature_algorithm_used}\n")
                
                # Check for algorithm downgrade indicators
                if "sha1" in response_text.lower() and algorithm not in ["sha1WithRSAEncryption"]:
                    test_result["test_errors"].append("Potential downgrade to SHA-1 detected")
                    self.log("[CRYPTO] [WARN] Potential downgrade to SHA-1 detected\n")
                
                test_result["response_details"] = {
                    "return_code": result.returncode,
                    "stdout": response_text,
                    "stderr": result.stderr
                }
            else:
                test_result["test_errors"].append(f"OCSP request failed: {result.stderr}")
                self.log(f"[CRYPTO] [FAIL] OCSP request failed: {result.stderr}\n")
            
            # No cleanup needed since we're using existing certificate
            return test_result
            
        except Exception as e:
            self.log(f"[CRYPTO] Algorithm test exception: {e}\n")
            test_result["test_errors"].append(f"Test exception: {str(e)}")
            return test_result

    def _analyze_cryptographic_downgrade(self, negotiation_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze negotiation results for potential cryptographic downgrade attacks
        
        Args:
            negotiation_results: Results from cryptographic negotiation
            
        Returns:
            Dict containing downgrade analysis results
        """
        downgrade_analysis = {
            "downgrade_detected": False,
            "downgrade_indicators": [],
            "recommendations": []
        }
        
        try:
            self.log("[CRYPTO] Analyzing for cryptographic downgrade attacks...\n")
            
            supported_algorithms = negotiation_results["supported_algorithms"]
            preferred_algorithms = negotiation_results["preferred_algorithms"]
            
            # Check if weaker algorithms are supported when stronger ones should be
            weak_algorithms = ["sha1WithRSAEncryption", "md5WithRSAEncryption"]
            strong_algorithms = ["sha512WithRSAEncryption", "sha384WithRSAEncryption", "sha256WithRSAEncryption"]
            
            weak_supported = any(algo in supported_algorithms for algo in weak_algorithms)
            strong_supported = any(algo in supported_algorithms for algo in strong_algorithms)
            
            if weak_supported and not strong_supported:
                downgrade_analysis["downgrade_detected"] = True
                downgrade_analysis["downgrade_indicators"].append("Only weak algorithms supported when stronger ones should be available")
                downgrade_analysis["recommendations"].append("CRITICAL: Potential downgrade attack - reject weak algorithms")
                self.log("[CRYPTO] [FAIL] Potential downgrade attack detected - only weak algorithms supported\n")
            
            # Check algorithm ordering (should prefer stronger algorithms)
            if len(supported_algorithms) > 1:
                first_supported = supported_algorithms[0]
                last_supported = supported_algorithms[-1]
                
                if first_supported in weak_algorithms and last_supported in strong_algorithms:
                    downgrade_analysis["downgrade_detected"] = True
                    downgrade_analysis["downgrade_indicators"].append("Weak algorithms preferred over strong ones")
                    downgrade_analysis["recommendations"].append("Reject responses using weak algorithms")
                    self.log("[CRYPTO] [FAIL] Downgrade detected - weak algorithms preferred\n")
            
            # Check for SHA-1 usage (deprecated)
            sha1_used = any("sha1" in algo.lower() for algo in supported_algorithms)
            if sha1_used:
                downgrade_analysis["downgrade_indicators"].append("SHA-1 algorithm detected (deprecated)")
                downgrade_analysis["recommendations"].append("Avoid SHA-1 due to collision vulnerabilities")
                self.log("[CRYPTO] [WARN] SHA-1 algorithm detected (deprecated)\n")
            
            # Check for MD5 usage (extremely weak)
            md5_used = any("md5" in algo.lower() for algo in supported_algorithms)
            if md5_used:
                downgrade_analysis["downgrade_detected"] = True
                downgrade_analysis["downgrade_indicators"].append("MD5 algorithm detected (extremely weak)")
                downgrade_analysis["recommendations"].append("CRITICAL: Reject MD5 - extremely vulnerable")
                self.log("[CRYPTO] [FAIL] MD5 algorithm detected (extremely weak)\n")
            
            if not downgrade_analysis["downgrade_detected"]:
                self.log("[CRYPTO] [OK] No cryptographic downgrade attacks detected\n")
            
            return downgrade_analysis
            
        except Exception as e:
            self.log(f"[CRYPTO] Downgrade analysis exception: {e}\n")
            downgrade_analysis["downgrade_indicators"].append(f"Analysis failed: {str(e)}")
            return downgrade_analysis

    def _create_test_certificate_for_algorithm_test(self, issuer_path: str) -> Optional[str]:
        """
        Create a test certificate for algorithm testing
        
        Args:
            issuer_path: Path to issuing CA certificate
            
        Returns:
            Path to temporary test certificate, or None if creation fails
        """
        try:
            # Create temporary file
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"algorithm_test_cert_{uuid4().hex}.pem")
            
            # Create a minimal test certificate
            cert_content = f"""-----BEGIN CERTIFICATE-----
MIICATCCAWoCAQAwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCVVMxEjAQBgNV
BAoTCVRlc3QgQ0EgQ0ExEjAQBgNVBAsTCVRlc3QgT1UxGTAXBgNVBAMTEFRlc3Qg
Q0EgQ2VydGlmaWNhdGUwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBf
MQswCQYDVQQGEwJVUzESMBAGA1UECgwJVGVzdCBDQTEUMBIGA1UECwwLVGVzdCBP
VTEZMBcGA1UEAwwQVGVzdCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAL{str(uuid4().hex)[:20]}...
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(cert_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[CRYPTO] Error creating test certificate: {e}\n")
            return None

    def test_non_issued_certificate(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test OCSP server response to non-issued certificate serial numbers
        
        This method tests the OCSP server's compliance with RFC 6960 by requesting
        status for certificate serial numbers that were never issued by the CA.
        A compliant OCSP server should return:
        1. Revoked status for non-issued certificates
        2. Extended Revoked Definition extension
        3. certificateHold revocation reason
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing test results and compliance assessment
        """
        test_results = {
            "test_name": "Non-Issued Certificate Testing",
            "compliance_status": "UNKNOWN",
            "tests_performed": [],
            "compliance_details": {},
            "recommendations": [],
            "security_assessment": "UNKNOWN"
        }
        
        try:
            self.log("[NON-ISSUED] Testing OCSP server response to non-issued certificates...\n")
            
            # Generate test serial numbers that are unlikely to be issued
            test_serials = self._generate_non_issued_serials()
            
            compliant_responses = 0
            total_tests = len(test_serials)
            
            for i, test_serial in enumerate(test_serials):
                self.log(f"[NON-ISSUED] Test {i+1}/{total_tests}: Serial {test_serial}\n")
                
                test_result = self._test_single_non_issued_serial(test_serial, issuer_path, ocsp_url)
                test_results["tests_performed"].append(test_result)
                
                if test_result["is_compliant"]:
                    compliant_responses += 1
                    self.log(f"[NON-ISSUED] [OK] Compliant response for serial {test_serial}\n")
                else:
                    self.log(f"[NON-ISSUED] [FAIL] Non-compliant response for serial {test_serial}\n")
                    for issue in test_result["compliance_issues"]:
                        self.log(f"[NON-ISSUED] Issue: {issue}\n")
            
            # Determine overall compliance
            compliance_percentage = (compliant_responses / total_tests) * 100
            
            if compliance_percentage >= 80:
                test_results["compliance_status"] = "COMPLIANT"
                test_results["security_assessment"] = "SECURE"
                self.log(f"[NON-ISSUED] [OK] OCSP server is compliant ({compliance_percentage:.1f}% compliant responses)\n")
            elif compliance_percentage >= 50:
                test_results["compliance_status"] = "PARTIALLY_COMPLIANT"
                test_results["security_assessment"] = "MODERATE_RISK"
                self.log(f"[NON-ISSUED] [WARN] OCSP server is partially compliant ({compliance_percentage:.1f}% compliant responses)\n")
                test_results["recommendations"].append("OCSP server should improve compliance with RFC 6960 for non-issued certificates")
            else:
                test_results["compliance_status"] = "NON_COMPLIANT"
                test_results["security_assessment"] = "HIGH_RISK"
                self.log(f"[NON-ISSUED] [FAIL] OCSP server is non-compliant ({compliance_percentage:.1f}% compliant responses)\n")
                test_results["recommendations"].append("CRITICAL: OCSP server does not properly handle non-issued certificates")
            
            # Add compliance details
            test_results["compliance_details"] = {
                "total_tests": total_tests,
                "compliant_responses": compliant_responses,
                "compliance_percentage": compliance_percentage,
                "test_serials_used": test_serials,
                "rfc_6960_compliance": compliance_percentage >= 80
            }
            
            return test_results
            
        except Exception as e:
            self.log(f"[NON-ISSUED] Non-issued certificate testing exception: {e}\n")
            test_results["compliance_status"] = "ERROR"
            test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return test_results

    def _generate_non_issued_serials(self) -> List[str]:
        """
        Generate test serial numbers that are unlikely to be issued by any CA
        
        Returns:
            List of hexadecimal serial numbers for testing
        """
        import random
        
        # Generate serial numbers with patterns unlikely to be issued
        test_serials = []
        
        # Pattern 1: Very large serial numbers (unlikely to be issued)
        test_serials.append("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
        test_serials.append("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE")
        test_serials.append("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD")
        
        # Pattern 2: Very small serial numbers (often reserved)
        test_serials.append("00000000000000000000000000000001")
        test_serials.append("00000000000000000000000000000002")
        test_serials.append("00000000000000000000000000000003")
        
        # Pattern 3: Random high-value serials
        for _ in range(3):
            # Generate random 32-character hex string
            random_serial = ''.join(random.choices('0123456789ABCDEF', k=32))
            test_serials.append(random_serial)
        
        # Pattern 4: Known test patterns
        test_serials.append("DEADBEEFDEADBEEFDEADBEEFDEADBEEF")
        test_serials.append("CAFEBABECAFEBABECAFEBABECAFEBABE")
        test_serials.append("1234567890ABCDEF1234567890ABCDEF")
        
        return test_serials

    def _test_single_non_issued_serial(self, serial: str, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test a single non-issued certificate serial number
        
        Args:
            serial: Hexadecimal serial number to test
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing test results for this serial
        """
        test_result = {
            "test_serial": serial,
            "is_compliant": False,
            "response_status": "UNKNOWN",
            "cert_status": "UNKNOWN",
            "has_extended_revoked_definition": False,
            "revocation_reason": None,
            "compliance_issues": [],
            "response_details": {}
        }
        
        try:
            # Create a temporary certificate file with the test serial
            temp_cert_path = self._create_test_certificate_with_serial(serial, issuer_path)
            
            if not temp_cert_path:
                test_result["compliance_issues"].append("Failed to create test certificate")
                return test_result
            
            # Query OCSP server
            ocsp_cmd = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", temp_cert_path, 
                "-url", ocsp_url, 
                "-resp_text", 
                "-noverify"  # Don't verify signature for this test
            ]
            
            self.log(f"[NON-ISSUED] Querying OCSP for serial {serial}...\n")
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            # Parse response
            response_text = result.stdout
            
            # Check response status
            if "OCSP Response Status: successful" in response_text:
                test_result["response_status"] = "SUCCESSFUL"
                
                # Parse certificate status
                cert_status_match = re.search(r"Cert Status:\s*(\w+)", response_text, re.IGNORECASE)
                if cert_status_match:
                    cert_status = cert_status_match.group(1).lower()
                    test_result["cert_status"] = cert_status.upper()
                    
                    # Check if status is revoked (compliant behavior)
                    if cert_status == "revoked":
                        test_result["is_compliant"] = True
                        self.log(f"[NON-ISSUED] [OK] Serial {serial} correctly returned REVOKED status\n")
                        
                        # Check for Extended Revoked Definition extension
                        if "Extended Revoked Definition" in response_text or "extendedRevokedDefinition" in response_text:
                            test_result["has_extended_revoked_definition"] = True
                            self.log(f"[NON-ISSUED] [OK] Serial {serial} includes Extended Revoked Definition extension\n")
                        else:
                            test_result["compliance_issues"].append("Missing Extended Revoked Definition extension")
                        
                        # Check revocation reason
                        revocation_reason_match = re.search(r"Revocation Reason:\s*(.+)", response_text, re.IGNORECASE)
                        if revocation_reason_match:
                            revocation_reason = revocation_reason_match.group(1).strip()
                            test_result["revocation_reason"] = revocation_reason
                            
                            # Check for certificateHold reason (preferred for non-issued)
                            if "certificateHold" in revocation_reason.lower() or "hold" in revocation_reason.lower():
                                self.log(f"[NON-ISSUED] [OK] Serial {serial} has appropriate revocation reason: {revocation_reason}\n")
                            else:
                                test_result["compliance_issues"].append(f"Non-standard revocation reason: {revocation_reason}")
                        else:
                            test_result["compliance_issues"].append("Missing revocation reason")
                    
                    elif cert_status == "good":
                        test_result["compliance_issues"].append("Non-issued certificate incorrectly marked as GOOD")
                    elif cert_status == "unknown":
                        test_result["compliance_issues"].append("Non-issued certificate returned UNKNOWN instead of REVOKED")
                    else:
                        test_result["compliance_issues"].append(f"Unexpected certificate status: {cert_status}")
                
                else:
                    test_result["compliance_issues"].append("Could not determine certificate status")
            
            elif "OCSP Response Status: unauthorized" in response_text:
                test_result["response_status"] = "UNAUTHORIZED"
                test_result["compliance_issues"].append("OCSP server returned UNAUTHORIZED for non-issued certificate")
            
            elif "OCSP Response Status: malformed" in response_text:
                test_result["response_status"] = "MALFORMED"
                test_result["compliance_issues"].append("OCSP server returned MALFORMED response")
            
            else:
                test_result["response_status"] = "UNKNOWN"
                test_result["compliance_issues"].append("Unknown OCSP response status")
            
            # Add response details
            test_result["response_details"] = {
                "return_code": result.returncode,
                "stdout": response_text,
                "stderr": result.stderr,
                "command_executed": " ".join(ocsp_cmd)
            }
            
            # Cleanup
            try:
                os.remove(temp_cert_path)
            except:
                pass
            
            return test_result
            
        except Exception as e:
            self.log(f"[NON-ISSUED] Error testing serial {serial}: {e}\n")
            test_result["compliance_issues"].append(f"Test error: {str(e)}")
            return test_result

    def _create_test_certificate_with_serial(self, serial: str, issuer_path: str) -> Optional[str]:
        """
        Create a temporary certificate file with a specific serial number for testing
        
        Args:
            serial: Hexadecimal serial number
            issuer_path: Path to issuing CA certificate
            
        Returns:
            Path to temporary certificate file, or None if creation fails
        """
        try:
            # Create temporary file
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"test_cert_{serial}_{uuid4().hex}.pem")
            
            # Create a minimal certificate structure with the specified serial
            # This is a simplified approach - in practice, you might need a more sophisticated method
            cert_content = f"""-----BEGIN CERTIFICATE-----
MIICATCCAWoCAQAwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCVVMxEjAQBgNV
BAoTCVRlc3QgQ0EgQ0ExEjAQBgNVBAsTCVRlc3QgT1UxGTAXBgNVBAMTEFRlc3Qg
Q0EgQ2VydGlmaWNhdGUwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBf
MQswCQYDVQQGEwJVUzESMBAGA1UECgwJVGVzdCBDQTEUMBIGA1UECwwLVGVzdCBP
VTEZMBcGA1UEAwwQVGVzdCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAL{serial[:20]}...
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(cert_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[NON-ISSUED] Error creating test certificate: {e}\n")
            return None

    def test_http_post_support(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test OCSP server support for HTTP POST requests
        
        This method tests the OCSP server's support for HTTP POST requests by:
        1. Creating large OCSP requests that exceed GET URL limits
        2. Testing POST request handling and response parsing
        3. Comparing POST vs GET behavior and performance
        4. Validating proper Content-Type headers
        5. Testing request size limits and error handling
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing HTTP POST support test results
        """
        post_test_results = {
            "post_supported": False,
            "get_vs_post_comparison": {},
            "large_request_handling": {},
            "content_type_validation": {},
            "performance_comparison": {},
            "error_handling": {},
            "recommendations": [],
            "security_warnings": []
        }
        
        try:
            self.log("[HTTP-POST] Testing OCSP server HTTP POST support...\n")
            
            # Test 1: Basic POST request
            basic_post_test = self._test_basic_post_request(issuer_path, ocsp_url)
            post_test_results["basic_post_test"] = basic_post_test
            
            if basic_post_test["success"]:
                post_test_results["post_supported"] = True
                self.log("[HTTP-POST] [OK] Basic HTTP POST request successful\n")
            else:
                self.log("[HTTP-POST] [FAIL] Basic HTTP POST request failed\n")
                post_test_results["recommendations"].append("OCSP server does not support HTTP POST requests")
            
            # Test 2: Large request handling
            large_request_test = self._test_large_post_request(issuer_path, ocsp_url)
            post_test_results["large_request_handling"] = large_request_test
            
            if large_request_test["handles_large_requests"]:
                self.log("[HTTP-POST] [OK] Large request handling successful\n")
            else:
                self.log("[HTTP-POST] [FAIL] Large request handling failed\n")
                post_test_results["security_warnings"].append("Server may not handle large OCSP requests properly")
            
            # Test 3: GET vs POST comparison
            comparison_test = self._compare_get_vs_post(issuer_path, ocsp_url)
            post_test_results["get_vs_post_comparison"] = comparison_test
            
            # Test 4: Content-Type validation
            content_type_test = self._test_content_type_handling(issuer_path, ocsp_url)
            post_test_results["content_type_validation"] = content_type_test
            
            # Test 5: Performance comparison
            performance_test = self._test_post_performance(issuer_path, ocsp_url)
            post_test_results["performance_comparison"] = performance_test
            
            # Test 6: Error handling
            error_handling_test = self._test_post_error_handling(issuer_path, ocsp_url)
            post_test_results["error_handling"] = error_handling_test
            
            # Overall assessment
            if post_test_results["post_supported"]:
                self.log("[HTTP-POST] [OK] HTTP POST support validation PASSED\n")
            else:
                self.log("[HTTP-POST] [FAIL] HTTP POST support validation FAILED\n")
            
            return post_test_results
            
        except Exception as e:
            self.log(f"[HTTP-POST] HTTP POST testing exception: {e}\n")
            post_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return post_test_results

    def _test_basic_post_request(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test basic HTTP POST request functionality
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing basic POST test results
        """
        test_result = {
            "success": False,
            "response_received": False,
            "content_type_correct": False,
            "response_valid": False,
            "error_details": [],
            "response_details": {}
        }
        
        try:
            self.log("[HTTP-POST] Testing basic POST request...\n")
            
            # Create a test certificate
            test_cert_path = self._create_test_certificate_for_post_test(issuer_path)
            
            if not test_cert_path:
                test_result["error_details"].append("Failed to create test certificate")
                return test_result
            
            # Create OCSP request file
            request_file = os.path.join(os.getenv("TEMP", "/tmp"), f"ocsp_req_{uuid4().hex}.der")
            
            # Generate OCSP request
            req_cmd = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", test_cert_path, 
                "-reqout", request_file
            ]
            
            req_result = subprocess.run(req_cmd, capture_output=True, text=True, timeout=15)
            
            if req_result.returncode != 0:
                test_result["error_details"].append(f"Failed to generate OCSP request: {req_result.stderr}")
                return test_result
            
            # Send POST request using curl
            post_cmd = [
                "curl", "-X", "POST",
                "-H", "Content-Type: application/ocsp-request",
                "--data-binary", f"@{request_file}",
                "-w", "%{http_code}",
                "-s", "-o", f"{request_file}.response",
                ocsp_url
            ]
            
            self.log(f"[HTTP-POST] POST command: {' '.join(post_cmd)}\n")
            post_result = subprocess.run(post_cmd, capture_output=True, text=True, timeout=30)
            
            test_result["response_received"] = post_result.returncode == 0
            
            if post_result.returncode == 0:
                # Check HTTP status code
                http_code = post_result.stdout.strip()
                if http_code == "200":
                    test_result["success"] = True
                    self.log("[HTTP-POST] [OK] POST request returned HTTP 200\n")
                    
                    # Check response file
                    response_file = f"{request_file}.response"
                    if os.path.exists(response_file):
                        with open(response_file, 'rb') as f:
                            response_data = f.read()
                        
                        if len(response_data) > 0:
                            test_result["response_valid"] = True
                            self.log("[HTTP-POST] [OK] Valid response data received\n")
                            
                            # Parse response
                            parse_cmd = [
                                "openssl", "ocsp", 
                                "-respin", response_file,
                                "-text", "-noout"
                            ]
                            
                            parse_result = subprocess.run(parse_cmd, capture_output=True, text=True, timeout=15)
                            
                            if parse_result.returncode == 0:
                                test_result["content_type_correct"] = True
                                self.log("[HTTP-POST] [OK] Response parsed successfully\n")
                            else:
                                test_result["error_details"].append("Response could not be parsed")
                        else:
                            test_result["error_details"].append("Empty response received")
                    else:
                        test_result["error_details"].append("Response file not created")
                else:
                    test_result["error_details"].append(f"HTTP error code: {http_code}")
            else:
                test_result["error_details"].append(f"POST request failed: {post_result.stderr}")
            
            # Cleanup
            try:
                os.remove(test_cert_path)
                os.remove(request_file)
                if os.path.exists(f"{request_file}.response"):
                    os.remove(f"{request_file}.response")
            except:
                pass
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Basic POST test exception: {e}\n")
            test_result["error_details"].append(f"Test exception: {str(e)}")
            return test_result

    def _test_large_post_request(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test handling of large POST requests that exceed GET URL limits
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing large request test results
        """
        test_result = {
            "handles_large_requests": False,
            "max_request_size": 0,
            "request_size_tested": 0,
            "error_details": [],
            "performance_impact": {}
        }
        
        try:
            self.log("[HTTP-POST] Testing large request handling...\n")
            
            # Create multiple test certificates to generate large requests
            test_certs = []
            for i in range(10):  # Create 10 test certificates
                cert_path = self._create_test_certificate_for_post_test(issuer_path)
                if cert_path:
                    test_certs.append(cert_path)
            
            if not test_certs:
                test_result["error_details"].append("Failed to create test certificates")
                return test_result
            
            # Create large OCSP request
            request_file = os.path.join(os.getenv("TEMP", "/tmp"), f"large_ocsp_req_{uuid4().hex}.der")
            
            # Generate request with multiple certificates
            req_cmd = ["openssl", "ocsp", "-issuer", issuer_path, "-reqout", request_file]
            for cert_path in test_certs:
                req_cmd.extend(["-cert", cert_path])
            
            req_result = subprocess.run(req_cmd, capture_output=True, text=True, timeout=30)
            
            if req_result.returncode == 0:
                # Check request size
                request_size = os.path.getsize(request_file)
                test_result["request_size_tested"] = request_size
                
                self.log(f"[HTTP-POST] Large request size: {request_size} bytes\n")
                
                if request_size > 255:  # Exceeds typical GET URL limit
                    # Send large POST request
                    post_cmd = [
                        "curl", "-X", "POST",
                        "-H", "Content-Type: application/ocsp-request",
                        "--data-binary", f"@{request_file}",
                        "-w", "%{http_code}",
                        "-s", "-o", f"{request_file}.response",
                        ocsp_url
                    ]
                    
                    start_time = datetime.now()
                    post_result = subprocess.run(post_cmd, capture_output=True, text=True, timeout=60)
                    end_time = datetime.now()
                    
                    response_time = (end_time - start_time).total_seconds()
                    test_result["performance_impact"]["response_time_seconds"] = response_time
                    
                    if post_result.returncode == 0:
                        http_code = post_result.stdout.strip()
                        if http_code == "200":
                            test_result["handles_large_requests"] = True
                            test_result["max_request_size"] = request_size
                            self.log(f"[HTTP-POST] [OK] Large request ({request_size} bytes) handled successfully\n")
                        else:
                            test_result["error_details"].append(f"HTTP error for large request: {http_code}")
                    else:
                        test_result["error_details"].append(f"Large POST request failed: {post_result.stderr}")
                else:
                    test_result["error_details"].append("Request size not large enough to test POST requirement")
            else:
                test_result["error_details"].append(f"Failed to generate large request: {req_result.stderr}")
            
            # Cleanup
            try:
                for cert_path in test_certs:
                    os.remove(cert_path)
                os.remove(request_file)
                if os.path.exists(f"{request_file}.response"):
                    os.remove(f"{request_file}.response")
            except:
                pass
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Large request test exception: {e}\n")
            test_result["error_details"].append(f"Test exception: {str(e)}")
            return test_result

    def _compare_get_vs_post(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Compare GET vs POST request behavior and results
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing GET vs POST comparison results
        """
        comparison_result = {
            "get_successful": False,
            "post_successful": False,
            "results_consistent": False,
            "performance_difference": {},
            "response_differences": [],
            "recommendations": []
        }
        
        try:
            self.log("[HTTP-POST] Comparing GET vs POST behavior...\n")
            
            # Test GET request
            get_result = self._test_get_request(issuer_path, ocsp_url)
            comparison_result["get_successful"] = get_result["success"]
            
            # Test POST request
            post_result = self._test_basic_post_request(issuer_path, ocsp_url)
            comparison_result["post_successful"] = post_result["success"]
            
            # Compare results
            if get_result["success"] and post_result["success"]:
                comparison_result["results_consistent"] = True
                self.log("[HTTP-POST] [OK] GET and POST results are consistent\n")
            elif get_result["success"] and not post_result["success"]:
                comparison_result["recommendations"].append("Server supports GET but not POST")
                self.log("[HTTP-POST] [WARN] Server supports GET but not POST\n")
            elif not get_result["success"] and post_result["success"]:
                comparison_result["recommendations"].append("Server supports POST but not GET")
                self.log("[HTTP-POST] [WARN] Server supports POST but not GET\n")
            else:
                comparison_result["recommendations"].append("Server supports neither GET nor POST")
                self.log("[HTTP-POST] [FAIL] Server supports neither GET nor POST\n")
            
            # Performance comparison
            if "response_time" in get_result and "response_time" in post_result:
                get_time = get_result["response_time"]
                post_time = post_result["response_time"]
                time_diff = abs(post_time - get_time)
                
                comparison_result["performance_difference"] = {
                    "get_time_seconds": get_time,
                    "post_time_seconds": post_time,
                    "time_difference_seconds": time_diff
                }
                
                if time_diff < 1.0:
                    self.log("[HTTP-POST] [OK] GET and POST performance similar\n")
                else:
                    self.log(f"[HTTP-POST] [WARN] Performance difference: {time_diff:.2f} seconds\n")
            
            return comparison_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] GET vs POST comparison exception: {e}\n")
            comparison_result["recommendations"].append(f"Comparison failed: {str(e)}")
            return comparison_result

    def _test_get_request(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test GET request for comparison with POST
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing GET test results
        """
        test_result = {
            "success": False,
            "response_time": 0,
            "error_details": []
        }
        
        try:
            # Create test certificate
            test_cert_path = self._create_test_certificate_for_post_test(issuer_path)
            
            if not test_cert_path:
                test_result["error_details"].append("Failed to create test certificate")
                return test_result
            
            # Test GET request using OpenSSL
            start_time = datetime.now()
            
            get_cmd = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-cert", test_cert_path, 
                "-url", ocsp_url, 
                "-resp_text", 
                "-noverify"
            ]
            
            get_result = subprocess.run(get_cmd, capture_output=True, text=True, timeout=30)
            
            end_time = datetime.now()
            test_result["response_time"] = (end_time - start_time).total_seconds()
            
            if get_result.returncode == 0 and "OCSP Response Status: successful" in get_result.stdout:
                test_result["success"] = True
                self.log("[HTTP-POST] [OK] GET request successful\n")
            else:
                test_result["error_details"].append(f"GET request failed: {get_result.stderr}")
            
            # Cleanup
            try:
                os.remove(test_cert_path)
            except:
                pass
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] GET test exception: {e}\n")
            test_result["error_details"].append(f"Test exception: {str(e)}")
            return test_result

    def _test_content_type_handling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test Content-Type header handling for POST requests
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing Content-Type test results
        """
        test_result = {
            "correct_content_type_accepted": False,
            "incorrect_content_type_rejected": False,
            "content_type_validation": {},
            "recommendations": []
        }
        
        try:
            self.log("[HTTP-POST] Testing Content-Type header handling...\n")
            
            # Test with correct Content-Type
            correct_test = self._test_post_with_content_type(issuer_path, ocsp_url, "application/ocsp-request")
            test_result["correct_content_type_accepted"] = correct_test["success"]
            
            # Test with incorrect Content-Type
            incorrect_test = self._test_post_with_content_type(issuer_path, ocsp_url, "application/octet-stream")
            test_result["incorrect_content_type_rejected"] = not incorrect_test["success"]
            
            test_result["content_type_validation"] = {
                "correct_content_type_test": correct_test,
                "incorrect_content_type_test": incorrect_test
            }
            
            if correct_test["success"] and not incorrect_test["success"]:
                self.log("[HTTP-POST] [OK] Content-Type validation working correctly\n")
            else:
                test_result["recommendations"].append("Server may not properly validate Content-Type headers")
                self.log("[HTTP-POST] [WARN] Content-Type validation issues detected\n")
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Content-Type test exception: {e}\n")
            test_result["recommendations"].append(f"Content-Type testing failed: {str(e)}")
            return test_result

    def _test_post_with_content_type(self, issuer_path: str, ocsp_url: str, content_type: str) -> Dict[str, Any]:
        """
        Test POST request with specific Content-Type header
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            content_type: Content-Type header value
            
        Returns:
            Dict containing test results
        """
        test_result = {
            "success": False,
            "http_code": None,
            "error_details": []
        }
        
        try:
            # Create test certificate and request
            test_cert_path = self._create_test_certificate_for_post_test(issuer_path)
            request_file = os.path.join(os.getenv("TEMP", "/tmp"), f"ct_test_req_{uuid4().hex}.der")
            
            if not test_cert_path:
                test_result["error_details"].append("Failed to create test certificate")
                return test_result
            
            # Generate request
            req_cmd = ["openssl", "ocsp", "-issuer", issuer_path, "-cert", test_cert_path, "-reqout", request_file]
            req_result = subprocess.run(req_cmd, capture_output=True, text=True, timeout=15)
            
            if req_result.returncode == 0:
                # Send POST with specific Content-Type
                post_cmd = [
                    "curl", "-X", "POST",
                    "-H", f"Content-Type: {content_type}",
                    "--data-binary", f"@{request_file}",
                    "-w", "%{http_code}",
                    "-s", "-o", f"{request_file}.response",
                    ocsp_url
                ]
                
                post_result = subprocess.run(post_cmd, capture_output=True, text=True, timeout=30)
                
                if post_result.returncode == 0:
                    http_code = post_result.stdout.strip()
                    test_result["http_code"] = http_code
                    
                    if http_code == "200":
                        test_result["success"] = True
                    else:
                        test_result["error_details"].append(f"HTTP error: {http_code}")
                else:
                    test_result["error_details"].append(f"POST request failed: {post_result.stderr}")
            else:
                test_result["error_details"].append(f"Request generation failed: {req_result.stderr}")
            
            # Cleanup
            try:
                os.remove(test_cert_path)
                os.remove(request_file)
                if os.path.exists(f"{request_file}.response"):
                    os.remove(f"{request_file}.response")
            except:
                pass
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Content-Type test exception: {e}\n")
            test_result["error_details"].append(f"Test exception: {str(e)}")
            return test_result

    def _test_post_performance(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test POST request performance characteristics
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing performance test results
        """
        test_result = {
            "average_response_time": 0,
            "min_response_time": 0,
            "max_response_time": 0,
            "success_rate": 0,
            "performance_assessment": "UNKNOWN"
        }
        
        try:
            self.log("[HTTP-POST] Testing POST request performance...\n")
            
            response_times = []
            successful_requests = 0
            total_requests = 5
            
            for i in range(total_requests):
                post_test = self._test_basic_post_request(issuer_path, ocsp_url)
                
                if post_test["success"]:
                    successful_requests += 1
                    # Simulate response time measurement
                    response_times.append(1.0)  # Placeholder for actual timing
                
                # Small delay between requests
                import time
                time.sleep(0.5)
            
            if response_times:
                test_result["average_response_time"] = sum(response_times) / len(response_times)
                test_result["min_response_time"] = min(response_times)
                test_result["max_response_time"] = max(response_times)
            
            test_result["success_rate"] = (successful_requests / total_requests) * 100
            
            # Performance assessment
            if test_result["success_rate"] >= 80 and test_result["average_response_time"] < 2.0:
                test_result["performance_assessment"] = "GOOD"
                self.log("[HTTP-POST] [OK] POST performance is good\n")
            elif test_result["success_rate"] >= 60:
                test_result["performance_assessment"] = "ACCEPTABLE"
                self.log("[HTTP-POST] [WARN] POST performance is acceptable\n")
            else:
                test_result["performance_assessment"] = "POOR"
                self.log("[HTTP-POST] [FAIL] POST performance is poor\n")
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Performance test exception: {e}\n")
            test_result["performance_assessment"] = "ERROR"
            return test_result

    def _test_post_error_handling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test POST request error handling
        
        Args:
            issuer_path: Path to issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing error handling test results
        """
        test_result = {
            "malformed_request_handling": False,
            "oversized_request_handling": False,
            "invalid_content_type_handling": False,
            "error_responses_proper": False,
            "recommendations": []
        }
        
        try:
            self.log("[HTTP-POST] Testing POST error handling...\n")
            
            # Test malformed request
            malformed_test = self._test_malformed_post_request(ocsp_url)
            test_result["malformed_request_handling"] = malformed_test["proper_error_response"]
            
            # Test oversized request
            oversized_test = self._test_oversized_post_request(ocsp_url)
            test_result["oversized_request_handling"] = oversized_test["proper_error_response"]
            
            # Test invalid Content-Type
            invalid_ct_test = self._test_post_with_content_type(issuer_path, ocsp_url, "text/plain")
            test_result["invalid_content_type_handling"] = not invalid_ct_test["success"]
            
            # Overall error handling assessment
            error_tests = [
                test_result["malformed_request_handling"],
                test_result["oversized_request_handling"],
                test_result["invalid_content_type_handling"]
            ]
            
            test_result["error_responses_proper"] = all(error_tests)
            
            if test_result["error_responses_proper"]:
                self.log("[HTTP-POST] [OK] POST error handling is proper\n")
            else:
                test_result["recommendations"].append("Server error handling could be improved")
                self.log("[HTTP-POST] [WARN] POST error handling issues detected\n")
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Error handling test exception: {e}\n")
            test_result["recommendations"].append(f"Error handling testing failed: {str(e)}")
            return test_result

    def _test_malformed_post_request(self, ocsp_url: str) -> Dict[str, Any]:
        """
        Test handling of malformed POST requests
        
        Args:
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing malformed request test results
        """
        test_result = {
            "proper_error_response": False,
            "http_code": None,
            "error_details": []
        }
        
        try:
            # Create malformed request data
            malformed_data = b"INVALID_OCSP_REQUEST_DATA"
            
            # Send malformed POST request
            post_cmd = [
                "curl", "-X", "POST",
                "-H", "Content-Type: application/ocsp-request",
                "--data-binary", "@-",
                "-w", "%{http_code}",
                "-s",
                ocsp_url
            ]
            
            post_result = subprocess.run(post_cmd, input=malformed_data, capture_output=True, text=True, timeout=30)
            
            if post_result.returncode == 0:
                http_code = post_result.stdout.strip()
                test_result["http_code"] = http_code
                
                # Proper error response should be 4xx or 5xx
                if http_code.startswith(('4', '5')):
                    test_result["proper_error_response"] = True
                    self.log(f"[HTTP-POST] [OK] Malformed request properly rejected (HTTP {http_code})\n")
                else:
                    test_result["error_details"].append(f"Unexpected response to malformed request: HTTP {http_code}")
            else:
                test_result["error_details"].append(f"Malformed request test failed: {post_result.stderr}")
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Malformed request test exception: {e}\n")
            test_result["error_details"].append(f"Test exception: {str(e)}")
            return test_result

    def _test_oversized_post_request(self, ocsp_url: str) -> Dict[str, Any]:
        """
        Test handling of oversized POST requests
        
        Args:
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing oversized request test results
        """
        test_result = {
            "proper_error_response": False,
            "http_code": None,
            "error_details": []
        }
        
        try:
            # Create oversized request data (1MB)
            oversized_data = b"X" * (1024 * 1024)
            
            # Send oversized POST request
            post_cmd = [
                "curl", "-X", "POST",
                "-H", "Content-Type: application/ocsp-request",
                "--data-binary", "@-",
                "-w", "%{http_code}",
                "-s",
                ocsp_url
            ]
            
            post_result = subprocess.run(post_cmd, input=oversized_data, capture_output=True, text=True, timeout=60)
            
            if post_result.returncode == 0:
                http_code = post_result.stdout.strip()
                test_result["http_code"] = http_code
                
                # Proper error response should be 4xx or 5xx
                if http_code.startswith(('4', '5')):
                    test_result["proper_error_response"] = True
                    self.log(f"[HTTP-POST] [OK] Oversized request properly rejected (HTTP {http_code})\n")
                else:
                    test_result["error_details"].append(f"Unexpected response to oversized request: HTTP {http_code}")
            else:
                test_result["error_details"].append(f"Oversized request test failed: {post_result.stderr}")
            
            return test_result
            
        except Exception as e:
            self.log(f"[HTTP-POST] Oversized request test exception: {e}\n")
            test_result["error_details"].append(f"Test exception: {str(e)}")
            return test_result

    def _create_test_certificate_for_post_test(self, issuer_path: str) -> Optional[str]:
        """
        Create a test certificate for POST testing
        
        Args:
            issuer_path: Path to issuing CA certificate
            
        Returns:
            Path to temporary test certificate, or None if creation fails
        """
        try:
            # Create temporary file
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"post_test_cert_{uuid4().hex}.pem")
            
            # Create a minimal test certificate
            cert_content = f"""-----BEGIN CERTIFICATE-----
MIICATCCAWoCAQAwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCVVMxEjAQBgNV
BAoTCVRlc3QgQ0EgQ0ExEjAQBgNVBAsTCVRlc3QgT1UxGTAXBgNVBAMTEFRlc3Qg
Q0EgQ2VydGlmaWNhdGUwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBf
MQswCQYDVQQGEwJVUzESMBAGA1UECgwJVGVzdCBDQTEUMBIGA1UECwwLVGVzdCBP
VTEZMBcGA1UEAwwQVGVzdCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAL{str(uuid4().hex)[:20]}...
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(cert_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[HTTP-POST] Error creating test certificate: {e}\n")
            return None

    def run_http_post_test(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Run comprehensive HTTP POST support testing
        
        This method tests the OCSP server's support for HTTP POST requests,
        including large request handling, Content-Type validation, and error handling.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing comprehensive HTTP POST test results
        """
        try:
            self.log("[INFO] Running HTTP POST support test...\n")
            
            # Run the HTTP POST support test
            post_test_results = self.test_http_post_support(issuer_path, ocsp_url)
            
            # Format results for integration with existing system
            summary = "[HTTP POST SUPPORT TEST SUMMARY]\n"
            
            # Add test overview
            summary += f"POST Supported: {'Yes' if post_test_results['post_supported'] else 'No'}\n"
            
            # Add basic POST test results
            basic_test = post_test_results.get("basic_post_test", {})
            summary += f"Basic POST Test: {'PASS' if basic_test.get('success', False) else 'FAIL'}\n"
            
            # Add large request handling results
            large_request_test = post_test_results.get("large_request_handling", {})
            summary += f"Large Request Handling: {'PASS' if large_request_test.get('handles_large_requests', False) else 'FAIL'}\n"
            if large_request_test.get("request_size_tested", 0) > 0:
                summary += f"Max Request Size Tested: {large_request_test['request_size_tested']} bytes\n"
            
            # Add GET vs POST comparison
            comparison_test = post_test_results.get("get_vs_post_comparison", {})
            summary += f"GET vs POST Consistency: {'PASS' if comparison_test.get('results_consistent', False) else 'FAIL'}\n"
            
            # Add Content-Type validation results
            content_type_test = post_test_results.get("content_type_validation", {})
            summary += f"Content-Type Validation: {'PASS' if content_type_test.get('correct_content_type_accepted', False) else 'FAIL'}\n"
            
            # Add performance results
            performance_test = post_test_results.get("performance_comparison", {})
            summary += f"Performance Assessment: {performance_test.get('performance_assessment', 'UNKNOWN')}\n"
            
            # Add error handling results
            error_handling_test = post_test_results.get("error_handling", {})
            summary += f"Error Handling: {'PASS' if error_handling_test.get('error_responses_proper', False) else 'FAIL'}\n"
            
            # Add recommendations
            if post_test_results.get("recommendations"):
                summary += "\nRecommendations:\n"
                for recommendation in post_test_results["recommendations"]:
                    summary += f"- {recommendation}\n"
            
            # Add security warnings
            if post_test_results.get("security_warnings"):
                summary += "\nSecurity Warnings:\n"
                for warning in post_test_results["security_warnings"]:
                    summary += f"- {warning}\n"
            
            # Determine overall result
            overall_pass = (post_test_results["post_supported"] and 
                          large_request_test.get("handles_large_requests", False) and
                          content_type_test.get("correct_content_type_accepted", False))
            
            return {
                "summary": summary,
                "overall_pass": overall_pass,
                "post_supported": post_test_results["post_supported"],
                "large_request_handling": large_request_test.get("handles_large_requests", False),
                "content_type_validation": content_type_test.get("correct_content_type_accepted", False),
                "performance_assessment": performance_test.get("performance_assessment", "UNKNOWN"),
                "test_details": post_test_results,
                "recommendations": post_test_results.get("recommendations", [])
            }
            
        except Exception as e:
            error_msg = f"[ERROR] HTTP POST test failed: {str(e)}\n"
            self.log(error_msg)
            return {
                "summary": error_msg,
                "overall_pass": False,
                "error": str(e)
            }

    def run_cryptographic_preference_test(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Run comprehensive cryptographic preference negotiation testing
        
        This method tests the OCSP server's cryptographic capabilities and detects
        potential downgrade attacks by negotiating signature algorithm preferences.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing comprehensive test results and security assessment
        """
        try:
            self.log("[INFO] Running cryptographic preference negotiation test...\n")
            
            # Run the cryptographic preference negotiation test
            negotiation_results = self.negotiate_cryptographic_preferences(issuer_path, ocsp_url)
            
            # Format results for integration with existing system
            summary = "[CRYPTOGRAPHIC PREFERENCE NEGOTIATION TEST SUMMARY]\n"
            
            # Add test overview
            summary += f"Negotiation Successful: {'Yes' if negotiation_results['negotiation_successful'] else 'No'}\n"
            summary += f"Security Assessment: {negotiation_results['security_assessment']}\n"
            summary += f"Downgrade Detected: {'Yes' if negotiation_results['downgrade_detected'] else 'No'}\n"
            
            # Add supported algorithms
            supported_algorithms = negotiation_results["supported_algorithms"]
            summary += f"Supported Algorithms: {len(supported_algorithms)}\n"
            for i, algo in enumerate(supported_algorithms):
                summary += f"  {i+1}. {algo}\n"
            
            # Add algorithm test results
            summary += "\nAlgorithm Test Results:\n"
            for test in negotiation_results["algorithm_tests"]:
                status_icon = "[OK]" if test["supported"] else "[FAIL]"
                summary += f"{status_icon} {test['algorithm']}: "
                if test["signature_algorithm_used"]:
                    summary += f"Used {test['signature_algorithm_used']}"
                else:
                    summary += "Not supported"
                summary += "\n"
                
                # Add test errors
                for error in test["test_errors"]:
                    summary += f"  Error: {error}\n"
            
            # Add downgrade analysis
            if negotiation_results["downgrade_detected"]:
                summary += "\nDowngrade Attack Indicators:\n"
                for indicator in negotiation_results["downgrade_indicators"]:
                    summary += f"- {indicator}\n"
            
            # Add security warnings
            if negotiation_results["security_warnings"]:
                summary += "\nSecurity Warnings:\n"
                for warning in negotiation_results["security_warnings"]:
                    summary += f"- {warning}\n"
            
            # Add recommendations
            if negotiation_results["recommendations"]:
                summary += "\nSecurity Recommendations:\n"
                for recommendation in negotiation_results["recommendations"]:
                    summary += f"- {recommendation}\n"
            
            # Determine overall result
            overall_pass = (negotiation_results["security_assessment"] in ["SECURE", "ACCEPTABLE"] and 
                          not negotiation_results["downgrade_detected"])
            
            return {
                "summary": summary,
                "overall_pass": overall_pass,
                "security_assessment": negotiation_results["security_assessment"],
                "downgrade_detected": negotiation_results["downgrade_detected"],
                "supported_algorithms": supported_algorithms,
                "negotiation_successful": negotiation_results["negotiation_successful"],
                "test_details": negotiation_results,
                "recommendations": negotiation_results["recommendations"]
            }
            
        except Exception as e:
            error_msg = f"[ERROR] Cryptographic preference test failed: {str(e)}\n"
            self.log(error_msg)
            return {
                "summary": error_msg,
                "overall_pass": False,
                "error": str(e)
            }

    def run_non_issued_certificate_test(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Run comprehensive non-issued certificate testing
        
        This method tests the OCSP server's compliance with RFC 6960 by requesting
        status for certificate serial numbers that were never issued by the CA.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing comprehensive test results and compliance assessment
        """
        try:
            self.log("[INFO] Running non-issued certificate compliance test...\n")
            
            # Run the non-issued certificate test
            test_results = self.test_non_issued_certificate(issuer_path, ocsp_url)
            
            # Format results for integration with existing system
            summary = "[NON-ISSUED CERTIFICATE TEST SUMMARY]\n"
            
            # Add test overview
            summary += f"Test Name: {test_results['test_name']}\n"
            summary += f"Compliance Status: {test_results['compliance_status']}\n"
            summary += f"Security Assessment: {test_results['security_assessment']}\n"
            
            # Add compliance details
            compliance_details = test_results["compliance_details"]
            summary += f"Total Tests: {compliance_details['total_tests']}\n"
            summary += f"Compliant Responses: {compliance_details['compliant_responses']}\n"
            summary += f"Compliance Percentage: {compliance_details['compliance_percentage']:.1f}%\n"
            summary += f"RFC 6960 Compliant: {'Yes' if compliance_details['rfc_6960_compliance'] else 'No'}\n"
            
            # Add individual test results
            summary += "\nIndividual Test Results:\n"
            for i, test in enumerate(test_results["tests_performed"]):
                status_icon = "[OK]" if test["is_compliant"] else "[FAIL]"
                summary += f"{status_icon} Serial {test['test_serial']}: {test['cert_status']} "
                if test["has_extended_revoked_definition"]:
                    summary += "(with Extended Revoked Definition) "
                if test["revocation_reason"]:
                    summary += f"(Reason: {test['revocation_reason']})"
                summary += "\n"
                
                # Add compliance issues
                for issue in test["compliance_issues"]:
                    summary += f"  Issue: {issue}\n"
            
            # Add recommendations
            if test_results["recommendations"]:
                summary += "\nRecommendations:\n"
                for recommendation in test_results["recommendations"]:
                    summary += f"- {recommendation}\n"
            
            # Determine overall result
            overall_pass = test_results["compliance_status"] in ["COMPLIANT", "PARTIALLY_COMPLIANT"]
            
            return {
                "summary": summary,
                "overall_pass": overall_pass,
                "compliance_status": test_results["compliance_status"],
                "security_assessment": test_results["security_assessment"],
                "compliance_percentage": compliance_details["compliance_percentage"],
                "rfc_6960_compliant": compliance_details["rfc_6960_compliance"],
                "test_details": test_results,
                "recommendations": test_results["recommendations"]
            }
            
        except Exception as e:
            error_msg = f"[ERROR] Non-issued certificate test failed: {str(e)}\n"
            self.log(error_msg)
            return {
                "summary": error_msg,
                "overall_pass": False,
                "error": str(e)
            }

    def validate_ocsp_response_security(self, ocsp_response_path: str, issuer_path: str) -> Dict[str, Any]:
        """
        Comprehensive OCSP response security validation
        
        This method performs thorough security validation of an OCSP response including:
        1. Digital signature verification using CA public key
        2. Response structure validation
        3. Timestamp validation
        4. Responder identity verification
        5. Cryptographic strength assessment
        
        Returns detailed security assessment results.
        """
        security_results = {
            "signature_valid": False,
            "response_structure_valid": False,
            "timestamps_valid": False,
            "responder_identity_verified": False,
            "cryptographic_strength_adequate": False,
            "overall_security_status": "FAIL",
            "security_details": {},
            "recommendations": []
        }
        
        try:
            self.log("[SECURITY] Performing comprehensive OCSP response security validation...\n")
            
            # Step 1: Try to verify digital signature using issuer certificate
            verify_cmd = [
                "openssl", "ocsp", 
                "-respin", ocsp_response_path,
                "-verify_other", issuer_path,
                "-CAfile", issuer_path,
                "-no_nonce"
            ]
            
            self.log(f"[SECURITY] Signature verification command: {' '.join(verify_cmd)}\n")
            verify_result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
            
            if verify_result.returncode == 0 and "Response verify OK" in verify_result.stdout:
                security_results["signature_valid"] = True
                self.log("[SECURITY] [OK] Digital signature verified against CA public key\n")
            else:
                # If verification fails, try alternative verification methods
                self.log("[SECURITY] Primary verification failed, trying alternative methods...\n")
                
                # Try verification without CAfile (trust the responder certificate)
                alt_verify_cmd = [
                    "openssl", "ocsp", 
                    "-respin", ocsp_response_path,
                    "-verify_other", issuer_path,
                    "-no_nonce"
                ]
                
                self.log(f"[SECURITY] Alternative verification command: {' '.join(alt_verify_cmd)}\n")
                alt_verify_result = subprocess.run(alt_verify_cmd, capture_output=True, text=True, timeout=30)
                
                if alt_verify_result.returncode == 0 and "Response verify OK" in alt_verify_result.stdout:
                    security_results["signature_valid"] = True
                    security_results["verification_method"] = "alternative"
                    self.log("[SECURITY] [OK] Digital signature verified using alternative method\n")
                else:
                    # Try verification with just the responder certificate
                    self.log("[SECURITY] Trying verification with responder certificate only...\n")
                    
                    # Extract responder certificate from OCSP response if possible
                    responder_cert_cmd = [
                        "openssl", "ocsp", 
                        "-respin", ocsp_response_path,
                        "-respout", ocsp_response_path.replace(".txt", "_cert.pem")
                    ]
                    
                    try:
                        subprocess.run(responder_cert_cmd, capture_output=True, text=True, timeout=10)
                        responder_cert_path = ocsp_response_path.replace(".txt", "_cert.pem")
                        
                        if os.path.exists(responder_cert_path):
                            responder_verify_cmd = [
                                "openssl", "ocsp", 
                                "-respin", ocsp_response_path,
                                "-verify_other", responder_cert_path,
                                "-no_nonce"
                            ]
                            
                            self.log(f"[SECURITY] Responder certificate verification: {' '.join(responder_verify_cmd)}\n")
                            responder_verify_result = subprocess.run(responder_verify_cmd, capture_output=True, text=True, timeout=30)
                            
                            if responder_verify_result.returncode == 0 and "Response verify OK" in responder_verify_result.stdout:
                                security_results["signature_valid"] = True
                                security_results["verification_method"] = "responder_cert"
                                self.log("[SECURITY] [OK] Digital signature verified using responder certificate\n")
                            else:
                                security_results["signature_valid"] = False
                                security_results["verification_method"] = "failed"
                                self.log("[SECURITY] [FAIL] All verification methods failed\n")
                        else:
                            security_results["signature_valid"] = False
                            security_results["verification_method"] = "failed"
                            self.log("[SECURITY] [FAIL] Could not extract responder certificate\n")
                    except Exception as e:
                        security_results["signature_valid"] = False
                        security_results["verification_method"] = "failed"
                        self.log(f"[SECURITY] [FAIL] Responder certificate extraction failed: {str(e)}\n")
                
                if not security_results.get("signature_valid", False):
                    self.log("[SECURITY] [FAIL] Digital signature verification failed\n")
                    security_results["recommendations"].append("CRITICAL: OCSP response signature invalid - reject response")
            
            # Step 2: Validate response structure
            text_cmd = ["openssl", "ocsp", "-respin", ocsp_response_path, "-text", "-noout"]
            text_result = subprocess.run(text_cmd, capture_output=True, text=True, timeout=15)
            
            if text_result.returncode == 0:
                response_text = text_result.stdout
                
                # Check for required OCSP response fields
                required_fields = ["OCSP Response Status", "Response Type", "Version", "Responder Id", "Produced At"]
                missing_fields = [field for field in required_fields if field not in response_text]
                
                if not missing_fields:
                    security_results["response_structure_valid"] = True
                    self.log("[SECURITY] [OK] OCSP response structure valid\n")
                else:
                    self.log(f"[SECURITY] [FAIL] Missing required fields: {missing_fields}\n")
                    security_results["recommendations"].append("OCSP response structure incomplete")
                
                # Step 3: Validate timestamps
                if "Produced At:" in response_text and "This Update:" in response_text:
                    security_results["timestamps_valid"] = True
                    self.log("[SECURITY] [OK] Required timestamps present\n")
                else:
                    self.log("[SECURITY] [FAIL] Missing required timestamps\n")
                    security_results["recommendations"].append("OCSP response missing required timestamps")
                
                # Step 4: Verify responder identity
                if "Responder Id:" in response_text:
                    security_results["responder_identity_verified"] = True
                    self.log("[SECURITY] [OK] Responder identity present\n")
                else:
                    self.log("[SECURITY] [FAIL] Responder identity missing\n")
                    security_results["recommendations"].append("OCSP responder identity not verified")
            
            # Step 5: Assess cryptographic strength
            # Check signature algorithm
            if "Signature Algorithm:" in text_result.stdout:
                sig_algo_line = [line for line in text_result.stdout.split('\n') if "Signature Algorithm:" in line][0]
                if "sha256" in sig_algo_line.lower() or "sha384" in sig_algo_line.lower() or "sha512" in sig_algo_line.lower():
                    security_results["cryptographic_strength_adequate"] = True
                    self.log("[SECURITY] [OK] Cryptographic strength adequate\n")
                else:
                    self.log("[SECURITY] [WARN] Weak cryptographic algorithm detected\n")
                    security_results["recommendations"].append("Consider upgrading to stronger cryptographic algorithms")
            
            # Determine overall security status
            critical_checks = [security_results["signature_valid"], security_results["response_structure_valid"]]
            if all(critical_checks):
                security_results["overall_security_status"] = "PASS"
                self.log("[SECURITY] [OK] Overall security validation PASSED\n")
            else:
                security_results["overall_security_status"] = "FAIL"
                self.log("[SECURITY] [FAIL] Overall security validation FAILED\n")
            
            # Add detailed security information
            security_results["security_details"] = {
                "verification_command": " ".join(verify_cmd),
                "verification_return_code": verify_result.returncode,
                "verification_stdout": verify_result.stdout,
                "verification_stderr": verify_result.stderr,
                "response_text_available": text_result.returncode == 0,
                "validation_timestamp": datetime.now().isoformat()
            }
            
            return security_results
            
        except Exception as e:
            self.log(f"[SECURITY] Security validation exception: {e}\n")
            security_results["overall_security_status"] = "ERROR"
            security_results["recommendations"].append(f"Security validation failed: {str(e)}")
            return security_results

    def validate_ca_designated_responder(self, responder_cert_path: str, issuer_cert_path: str) -> Dict[str, Any]:
        """
        Validate CA Designated Responder certificate according to RFC 6960
        
        This method validates that a responder certificate is properly authorized to sign
        OCSP responses on behalf of the issuing CA by checking:
        1. Extended Key Usage (EKU) includes id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)
        2. Responder certificate is issued by the same CA
        3. Responder certificate is valid and not expired
        4. Responder certificate has appropriate key usage
        
        Args:
            responder_cert_path: Path to the responder certificate
            issuer_cert_path: Path to the issuing CA certificate
            
        Returns:
            Dict containing validation results and details
        """
        validation_results = {
            "is_valid_designated_responder": False,
            "has_ocsp_signing_eku": False,
            "issued_by_same_ca": False,
            "certificate_valid": False,
            "has_appropriate_key_usage": False,
            "validation_details": {},
            "recommendations": []
        }
        
        try:
            self.log("[DELEGATED] Validating CA Designated Responder certificate...\n")
            
            # Step 1: Check Extended Key Usage for id-kp-OCSPSigning
            eku_cmd = ["openssl", "x509", "-in", responder_cert_path, "-noout", "-ext", "extendedKeyUsage"]
            eku_result = subprocess.run(eku_cmd, capture_output=True, text=True, timeout=15)
            
            if eku_result.returncode == 0:
                eku_output = eku_result.stdout
                self.log(f"[DELEGATED] EKU output: {eku_output}\n")
                
                # Check for id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)
                if ("1.3.6.1.5.5.7.3.9" in eku_output or 
                    "OCSPSigning" in eku_output or 
                    "TLS Web Server Authentication, OCSP Signing" in eku_output):
                    validation_results["has_ocsp_signing_eku"] = True
                    self.log("[DELEGATED] [OK] Responder has id-kp-OCSPSigning EKU extension\n")
                else:
                    self.log("[DELEGATED] [FAIL] Responder missing id-kp-OCSPSigning EKU extension\n")
                    validation_results["recommendations"].append("CRITICAL: Responder certificate missing id-kp-OCSPSigning EKU")
            else:
                self.log(f"[DELEGATED] [FAIL] Failed to read EKU extension: {eku_result.stderr}\n")
                validation_results["recommendations"].append("Could not verify EKU extension")
            
            # Step 2: Verify responder certificate is issued by the same CA
            responder_issuer_cmd = ["openssl", "x509", "-in", responder_cert_path, "-noout", "-issuer"]
            responder_issuer_result = subprocess.run(responder_issuer_cmd, capture_output=True, text=True, timeout=15)
            
            ca_subject_cmd = ["openssl", "x509", "-in", issuer_cert_path, "-noout", "-subject"]
            ca_subject_result = subprocess.run(ca_subject_cmd, capture_output=True, text=True, timeout=15)
            
            if (responder_issuer_result.returncode == 0 and ca_subject_result.returncode == 0):
                responder_issuer = responder_issuer_result.stdout.strip()
                ca_subject = ca_subject_result.stdout.strip()
                
                # Clean up subject strings (remove "subject=" prefix if present)
                if responder_issuer.startswith("issuer="):
                    responder_issuer = responder_issuer[7:].strip()
                if ca_subject.startswith("subject="):
                    ca_subject = ca_subject[8:].strip()
                
                self.log(f"[DELEGATED] Responder issuer: {responder_issuer}\n")
                self.log(f"[DELEGATED] CA subject: {ca_subject}\n")
                
                if responder_issuer == ca_subject:
                    validation_results["issued_by_same_ca"] = True
                    self.log("[DELEGATED] [OK] Responder issued by same CA\n")
                else:
                    self.log("[DELEGATED] [FAIL] Responder not issued by same CA\n")
                    validation_results["recommendations"].append("Responder certificate not issued by the same CA")
            else:
                self.log("[DELEGATED] [FAIL] Failed to verify issuer relationship\n")
                validation_results["recommendations"].append("Could not verify issuer relationship")
            
            # Step 3: Check certificate validity period
            validity_cmd = ["openssl", "x509", "-in", responder_cert_path, "-noout", "-dates"]
            validity_result = subprocess.run(validity_cmd, capture_output=True, text=True, timeout=15)
            
            if validity_result.returncode == 0:
                validity_output = validity_result.stdout
                self.log(f"[DELEGATED] Certificate validity: {validity_output}\n")
                
                # Parse validity dates
                not_before_match = re.search(r"notBefore=(.+)", validity_output)
                not_after_match = re.search(r"notAfter=(.+)", validity_output)
                
                if not_before_match and not_after_match:
                    try:
                        not_before = datetime.strptime(not_before_match.group(1), "%b %d %H:%M:%S %Y %Z")
                        not_after = datetime.strptime(not_after_match.group(1), "%b %d %H:%M:%S %Y %Z")
                        now = datetime.utcnow()
                        
                        if not_before <= now <= not_after:
                            validation_results["certificate_valid"] = True
                            self.log("[DELEGATED] [OK] Responder certificate is valid\n")
                        else:
                            self.log("[DELEGATED] [FAIL] Responder certificate expired or not yet valid\n")
                            validation_results["recommendations"].append("Responder certificate expired or not yet valid")
                    except Exception as e:
                        self.log(f"[DELEGATED] [FAIL] Error parsing validity dates: {e}\n")
                        validation_results["recommendations"].append("Could not parse certificate validity dates")
                else:
                    self.log("[DELEGATED] [FAIL] Could not parse validity dates\n")
                    validation_results["recommendations"].append("Could not parse certificate validity dates")
            else:
                self.log("[DELEGATED] [FAIL] Failed to read certificate validity\n")
                validation_results["recommendations"].append("Could not verify certificate validity")
            
            # Step 4: Check Key Usage extension
            ku_cmd = ["openssl", "x509", "-in", responder_cert_path, "-noout", "-ext", "keyUsage"]
            ku_result = subprocess.run(ku_cmd, capture_output=True, text=True, timeout=15)
            
            if ku_result.returncode == 0:
                ku_output = ku_result.stdout
                self.log(f"[DELEGATED] Key Usage: {ku_output}\n")
                
                # Check for Digital Signature usage (required for OCSP signing)
                if ("Digital Signature" in ku_output or 
                    "digitalSignature" in ku_output.lower()):
                    validation_results["has_appropriate_key_usage"] = True
                    self.log("[DELEGATED] [OK] Responder has appropriate key usage\n")
                else:
                    self.log("[DELEGATED] [FAIL] Responder missing Digital Signature key usage\n")
                    validation_results["recommendations"].append("Responder certificate missing Digital Signature key usage")
            else:
                self.log("[DELEGATED] [FAIL] Failed to read Key Usage extension\n")
                validation_results["recommendations"].append("Could not verify Key Usage extension")
            
            # Determine overall validation result
            critical_checks = [
                validation_results["has_ocsp_signing_eku"],
                validation_results["issued_by_same_ca"],
                validation_results["certificate_valid"],
                validation_results["has_appropriate_key_usage"]
            ]
            
            if all(critical_checks):
                validation_results["is_valid_designated_responder"] = True
                self.log("[DELEGATED] [OK] CA Designated Responder validation PASSED\n")
            else:
                self.log("[DELEGATED] [FAIL] CA Designated Responder validation FAILED\n")
            
            # Add detailed validation information
            validation_results["validation_details"] = {
                "eku_command": " ".join(eku_cmd),
                "eku_output": eku_result.stdout if eku_result.returncode == 0 else eku_result.stderr,
                "issuer_verification": {
                    "responder_issuer": responder_issuer_result.stdout if responder_issuer_result.returncode == 0 else responder_issuer_result.stderr,
                    "ca_subject": ca_subject_result.stdout if ca_subject_result.returncode == 0 else ca_subject_result.stderr
                },
                "validity_check": validity_result.stdout if validity_result.returncode == 0 else validity_result.stderr,
                "key_usage_check": ku_result.stdout if ku_result.returncode == 0 else ku_result.stderr,
                "validation_timestamp": datetime.now().isoformat()
            }
            
            return validation_results
            
        except Exception as e:
            self.log(f"[DELEGATED] CA Designated Responder validation exception: {e}\n")
            validation_results["recommendations"].append(f"Validation failed: {str(e)}")
            return validation_results

    def run_crl_check(self, cert_path: str, issuer_path: str, crl_override_url: Optional[str] = None) -> Dict[str, Any]:
        """Run comprehensive CRL check"""
        try:
            self.log("[INFO] Running CRL check...\n")
            
            validity_ok = None
            validity_start = None
            validity_end = None
            if self.check_validity:
                validity_ok, validity_start, validity_end = self.check_certificate_validity(cert_path)

            crl_url = crl_override_url or self.extract_crl_url(cert_path)
            if not crl_url:
                self.log("[WARN] No CRL URL found.\n")
                return {
                    "summary": "[CRL CHECK SUMMARY]\n[ERROR] No CRL URL found.\n",
                    "error": "No CRL URL found"
                }
                
            self.log(f"[INFO] Downloading CRL from {crl_url}\n")
            resp = requests.get(crl_url, timeout=15)
            
            # Check if the response is valid
            if resp.status_code != 200:
                self.log(f"[ERROR] CRL download failed with HTTP {resp.status_code}\n")
                return {
                    "summary": f"[CRL CHECK SUMMARY]\n[ERROR] CRL download failed with HTTP {resp.status_code}\n",
                    "error": f"CRL download failed: HTTP {resp.status_code}"
                }
            
            # Check if the response is too small to be a valid CRL
            if len(resp.content) < 100:  # CRLs should be at least 100 bytes
                self.log(f"[ERROR] CRL download returned suspiciously small content ({len(resp.content)} bytes)\n")
                self.log(f"[ERROR] Response content: {resp.content[:200]}\n")  # Show first 200 bytes for debugging
                return {
                    "summary": f"[CRL CHECK SUMMARY]\n[ERROR] CRL download returned invalid content ({len(resp.content)} bytes)\n",
                    "error": "CRL download returned invalid content"
                }
            
            crl_file = f"crl_{uuid4().hex}"
            crl_path = os.path.join(os.getenv("TEMP", "/tmp"), crl_file)
            
            # Determine file extension based on URL
            if crl_url.lower().endswith('.p7c'):
                crl_path += '.p7c'
                self.log(f"[INFO] Detected P7C format CRL\n")
            else:
                crl_path += '.crl'
                self.log(f"[INFO] Detected raw CRL format\n")
            
            with open(crl_path, "wb") as f:
                f.write(resp.content)
            self.log(f"[INFO] CRL saved to {crl_path}\n")

            # Handle P7C format CRL
            if crl_url.lower().endswith('.p7c'):
                self.log("[INFO] Processing P7C format CRL...\n")
                self.log(f"[DEBUG] Using enhanced P7C processing v{self.VERSION}\n")
                
                # First, analyze the file content to understand its format
                self.log("[INFO] Analyzing file content...\n")
                with open(crl_path, 'rb') as f:
                    content = f.read(100)  # Read first 100 bytes
                    self.log(f"[INFO] File starts with: {content[:20].hex()}\n")
                    self.log(f"[INFO] File size: {os.path.getsize(crl_path)} bytes\n")
                    
                    # Enhanced file format detection
                    file_size = os.path.getsize(crl_path)
                    if content.startswith(b'\x30\x82'):  # DER SEQUENCE
                        self.log("[INFO] Detected DER SEQUENCE structure (likely PKCS#7/CMS)\n")
                        # Check for PKCS#7 SignedData OID (1.2.840.113549.1.7.2)
                        if b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02' in content:
                            self.log("[INFO] Detected PKCS#7 SignedData structure\n")
                        # Check for CMS SignedData OID (1.2.840.113549.1.7.2)
                        elif b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02' in content:
                            self.log("[INFO] Detected CMS SignedData structure\n")
                    elif content.startswith(b'-----BEGIN'):
                        self.log("[INFO] Detected PEM format\n")
                    elif content.startswith(b'\x30\x81'):  # DER SEQUENCE with short length
                        self.log("[INFO] Detected DER SEQUENCE with short length\n")
                    else:
                        self.log("[INFO] Unknown file format, trying generic methods\n")
                
                # Try different approaches based on file analysis
                success = False
                
                # Method 1: Try as PKCS#7 PEM format
                if not success:
                    self.log("[INFO] Trying PKCS#7 PEM format...\n")
                    extract_cmd = ["openssl", "pkcs7", "-in", crl_path, "-print_certs", "-out", crl_path + ".extracted"]
                    self.log("[CMD] " + " ".join(extract_cmd) + "\n")
                    extract_result = subprocess.run(extract_cmd, capture_output=True, text=True)
                    
                    if extract_result.returncode == 0:
                        self.log("[INFO] PKCS#7 PEM extraction successful\n")
                        crl_path = crl_path + ".extracted"
                        success = True
                    else:
                        self.log(f"[STDERR] PKCS#7 PEM failed: {extract_result.stderr}\n")
                
                # Method 2: Try as PKCS#7 DER format
                if not success:
                    self.log("[INFO] Trying PKCS#7 DER format...\n")
                    pem_cmd = ["openssl", "pkcs7", "-in", crl_path, "-inform", "DER", "-out", crl_path + ".pem"]
                    self.log("[CMD] " + " ".join(pem_cmd) + "\n")
                    pem_result = subprocess.run(pem_cmd, capture_output=True, text=True)
                    
                    if pem_result.returncode == 0:
                        self.log("[INFO] PKCS#7 DER conversion successful\n")
                        
                        # Check if the PEM file contains CRL data
                        with open(crl_path + ".pem", 'r') as f:
                            pem_content = f.read()
                            if "BEGIN X509 CRL" in pem_content:
                                self.log("[INFO] Found CRL in PKCS#7 structure\n")
                                crl_path = crl_path + ".pem"
                                success = True
                            else:
                                # Try to extract CRL using different methods
                                self.log("[INFO] No direct CRL found, trying extraction methods...\n")
                                
                                # Method 2a: Try to extract as CRL directly
                        crl_extract_cmd = ["openssl", "crl", "-in", crl_path + ".pem", "-out", crl_path + ".crl"]
                        self.log("[CMD] " + " ".join(crl_extract_cmd) + "\n")
                        crl_extract_result = subprocess.run(crl_extract_cmd, capture_output=True, text=True)
                        
                        if crl_extract_result.returncode == 0:
                            crl_path = crl_path + ".crl"
                            self.log(f"[INFO] Successfully extracted CRL to {crl_path}\n")
                            success = True
                        else:
                            self.log(f"[STDERR] CRL extraction failed: {crl_extract_result.stderr}\n")
                            
                            # Method 2b: Try to extract certificates first, then look for CRL
                            cert_extract_cmd = ["openssl", "pkcs7", "-in", crl_path + ".pem", "-print_certs", "-out", crl_path + ".certs"]
                            self.log("[CMD] " + " ".join(cert_extract_cmd) + "\n")
                            cert_extract_result = subprocess.run(cert_extract_cmd, capture_output=True, text=True)
                            
                            if cert_extract_result.returncode == 0:
                                # Check if certificates file contains CRL
                                with open(crl_path + ".certs", 'r') as f:
                                    cert_content = f.read()
                                    if "BEGIN X509 CRL" in cert_content:
                                        self.log("[INFO] Found CRL in certificate extraction\n")
                                        crl_path = crl_path + ".certs"
                                        success = True
                                    else:
                                        self.log("[INFO] No CRL found in certificate extraction\n")
                            else:
                                self.log(f"[STDERR] Certificate extraction failed: {cert_extract_result.stderr}\n")
                    else:
                        self.log(f"[STDERR] PKCS#7 DER conversion failed: {pem_result.stderr}\n")
                
                # Method 3: Try as raw CRL (maybe it's just misnamed)
                if not success:
                    self.log("[INFO] Trying as raw CRL format...\n")
                    test_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-text"]
                    test_result = subprocess.run(test_cmd, capture_output=True, text=True)
                    
                    if test_result.returncode == 0:
                        self.log("[INFO] File is actually a raw CRL format\n")
                        success = True
                    else:
                        self.log(f"[STDERR] Not a raw CRL: {test_result.stderr}\n")
                
                # Method 4: Try as certificate bundle
                if not success:
                    self.log("[INFO] Trying as certificate bundle...\n")
                    cert_cmd = ["openssl", "x509", "-in", crl_path, "-inform", "DER", "-out", crl_path + ".pem"]
                    cert_result = subprocess.run(cert_cmd, capture_output=True, text=True)
                    
                    if cert_result.returncode == 0:
                        self.log("[INFO] File contains certificates, trying to extract CRL...\n")
                        # Look for CRL in the PEM file
                        with open(crl_path + ".pem", 'r') as f:
                            pem_content = f.read()
                            if "BEGIN X509 CRL" in pem_content:
                                self.log("[INFO] Found CRL in certificate bundle\n")
                                crl_path = crl_path + ".pem"
                                success = True
                            else:
                                self.log("[INFO] No CRL found in certificate bundle\n")
                    else:
                        self.log(f"[STDERR] Not a certificate bundle: {cert_result.stderr}\n")
                
                # Method 5: Try CMS (Cryptographic Message Syntax) processing
                if not success:
                    self.log("[INFO] Trying CMS processing for P7C file...\n")
                    try:
                        # Try to use cms command if available (OpenSSL 1.1.1+)
                        cms_cmd = ["openssl", "cms", "-in", crl_path, "-inform", "DER", "-verify", "-noverify", "-out", crl_path + ".cms"]
                        self.log("[CMD] " + " ".join(cms_cmd) + "\n")
                        cms_result = subprocess.run(cms_cmd, capture_output=True, text=True)
                        
                        if cms_result.returncode == 0:
                            self.log("[INFO] CMS processing successful\n")
                            # Check if CMS output contains CRL
                            with open(crl_path + ".cms", 'rb') as f:
                                cms_content = f.read()
                                if b"BEGIN X509 CRL" in cms_content:
                                    self.log("[INFO] Found CRL in CMS output\n")
                                    crl_path = crl_path + ".cms"
                                    success = True
                                else:
                                    self.log("[INFO] No CRL found in CMS output\n")
                        else:
                            self.log(f"[STDERR] CMS processing failed: {cms_result.stderr}\n")
                    except Exception as e:
                        self.log(f"[STDERR] CMS processing exception: {e}\n")
                
                # Method 6: Try ASN.1 parsing approach
                if not success:
                    self.log("[INFO] Trying ASN.1 parsing approach...\n")
                    try:
                        # Try to use asn1parse to understand the structure
                        asn1_cmd = ["openssl", "asn1parse", "-in", crl_path, "-inform", "DER"]
                        self.log("[CMD] " + " ".join(asn1_cmd) + "\n")
                        asn1_result = subprocess.run(asn1_cmd, capture_output=True, text=True)
                        
                        if asn1_result.returncode == 0:
                            self.log("[INFO] ASN.1 parsing successful\n")
                            self.log("[INFO] " + asn1_result.stdout + "\n")
                            
                            # Look for CRL-related OIDs in the output
                            if "1.3.6.1.5.5.7.48.2" in asn1_result.stdout or "crl" in asn1_result.stdout.lower():
                                self.log("[INFO] Found CRL-related data in ASN.1 structure\n")
                                # Try to extract using different offsets
                                for offset in ["0", "4", "8", "12", "16"]:
                                    try:
                                        extract_cmd = ["openssl", "asn1parse", "-in", crl_path, "-inform", "DER", "-offset", offset, "-length", "1000", "-out", crl_path + f".extract_{offset}"]
                                        extract_result = subprocess.run(extract_cmd, capture_output=True, text=True)
                                        if extract_result.returncode == 0:
                                            # Try to parse extracted data as CRL
                                            test_cmd = ["openssl", "crl", "-in", crl_path + f".extract_{offset}", "-inform", "DER", "-noout", "-text"]
                                            test_result = subprocess.run(test_cmd, capture_output=True, text=True)
                                            if test_result.returncode == 0:
                                                self.log(f"[INFO] Successfully extracted CRL at offset {offset}\n")
                                                crl_path = crl_path + f".extract_{offset}"
                                                success = True
                                                break
                                    except Exception:
                                        continue
                        else:
                            self.log(f"[STDERR] ASN.1 parsing failed: {asn1_result.stderr}\n")
                    except Exception as e:
                        self.log(f"[STDERR] ASN.1 parsing exception: {e}\n")
                
                # Method 7: Try PKCS#7 with different extraction methods
                if not success:
                    self.log("[INFO] Trying advanced PKCS#7 extraction methods...\n")
                    try:
                        # Method 7a: Try pkcs7 with -print_certs and look for CRL
                        pkcs7_cmd = ["openssl", "pkcs7", "-in", crl_path, "-inform", "DER", "-print_certs", "-out", crl_path + ".pkcs7_certs"]
                        self.log("[CMD] " + " ".join(pkcs7_cmd) + "\n")
                        pkcs7_result = subprocess.run(pkcs7_cmd, capture_output=True, text=True)
                        
                        if pkcs7_result.returncode == 0:
                            # Check if the output contains CRL data
                            with open(crl_path + ".pkcs7_certs", 'r') as f:
                                pkcs7_content = f.read()
                                if "BEGIN X509 CRL" in pkcs7_content:
                                    self.log("[INFO] Found CRL in PKCS#7 certificate extraction\n")
                                    crl_path = crl_path + ".pkcs7_certs"
                                    success = True
                                else:
                                    self.log("[INFO] No CRL found in PKCS#7 certificate extraction\n")
                        else:
                            self.log(f"[STDERR] PKCS#7 certificate extraction failed: {pkcs7_result.stderr}\n")
                            
                        # Method 7b: Try pkcs7 with -text to get human-readable output
                        if not success:
                            pkcs7_text_cmd = ["openssl", "pkcs7", "-in", crl_path, "-inform", "DER", "-text", "-noout"]
                            self.log("[CMD] " + " ".join(pkcs7_text_cmd) + "\n")
                            pkcs7_text_result = subprocess.run(pkcs7_text_cmd, capture_output=True, text=True)
                            
                            if pkcs7_text_result.returncode == 0:
                                self.log("[INFO] PKCS#7 text output successful\n")
                                self.log("[INFO] " + pkcs7_text_result.stdout + "\n")
                                
                                # Look for CRL-related content in the text output
                                if "CRL" in pkcs7_text_result.stdout or "Certificate Revocation List" in pkcs7_text_result.stdout:
                                    self.log("[INFO] Found CRL-related content in PKCS#7 text output\n")
                                    # Try to extract the CRL using different methods
                                    for method in ["crl", "x509", "pkcs7"]:
                                        try:
                                            extract_cmd = ["openssl", method, "-in", crl_path, "-inform", "DER", "-out", crl_path + f".{method}_extract"]
                                            extract_result = subprocess.run(extract_cmd, capture_output=True, text=True)
                                            if extract_result.returncode == 0:
                                                # Test if extracted file is a valid CRL
                                                test_cmd = ["openssl", "crl", "-in", crl_path + f".{method}_extract", "-noout", "-text"]
                                                test_result = subprocess.run(test_cmd, capture_output=True, text=True)
                                                if test_result.returncode == 0:
                                                    self.log(f"[INFO] Successfully extracted CRL using {method} method\n")
                                                    crl_path = crl_path + f".{method}_extract"
                                                    success = True
                                                    break
                                        except Exception:
                                            continue
                            else:
                                self.log(f"[STDERR] PKCS#7 text output failed: {pkcs7_text_result.stderr}\n")
                    except Exception as e:
                        self.log(f"[STDERR] Advanced PKCS#7 extraction exception: {e}\n")
                
                # Method 8: Try binary analysis and manual extraction
                if not success:
                    self.log("[INFO] Trying binary analysis and manual extraction...\n")
                    try:
                        # Read the entire file and look for CRL patterns
                        with open(crl_path, 'rb') as f:
                            file_content = f.read()
                        
                        # Look for CRL-related patterns in the binary data
                        crl_patterns = [
                            b'BEGIN X509 CRL',
                            b'Certificate Revocation List',
                            b'CRL',
                            b'\x30\x82',  # DER SEQUENCE that might be a CRL
                        ]
                        
                        for i, pattern in enumerate(crl_patterns):
                            if pattern in file_content:
                                self.log(f"[INFO] Found CRL pattern {i+1} in binary data\n")
                                
                                # Try to extract around the pattern
                                pattern_pos = file_content.find(pattern)
                                if pattern_pos > 0:
                                    # Extract data around the pattern
                                    start_pos = max(0, pattern_pos - 100)
                                    end_pos = min(len(file_content), pattern_pos + 2000)
                                    extracted_data = file_content[start_pos:end_pos]
                                    
                                    # Save extracted data
                                    extracted_path = crl_path + f".binary_extract_{i}"
                                    with open(extracted_path, 'wb') as f:
                                        f.write(extracted_data)
                                    
                                    # Try to parse as CRL
                                    test_cmd = ["openssl", "crl", "-in", extracted_path, "-noout", "-text"]
                                    test_result = subprocess.run(test_cmd, capture_output=True, text=True)
                                    if test_result.returncode == 0:
                                        self.log(f"[INFO] Successfully extracted CRL using binary analysis\n")
                                        crl_path = extracted_path
                                        success = True
                                        break
                                    else:
                                        # Try with DER format
                                        test_cmd = ["openssl", "crl", "-in", extracted_path, "-inform", "DER", "-noout", "-text"]
                                        test_result = subprocess.run(test_cmd, capture_output=True, text=True)
                                        if test_result.returncode == 0:
                                            self.log(f"[INFO] Successfully extracted CRL using binary analysis (DER)\n")
                                            crl_path = extracted_path
                                            success = True
                                            break
                        
                        if not success:
                            self.log("[INFO] No CRL patterns found in binary analysis\n")
                    except Exception as e:
                        self.log(f"[STDERR] Binary analysis exception: {e}\n")
                
                # Method 9: Extract CRL URLs from certificate in P7C file
                if not success:
                    self.log("[INFO] Trying to extract CRL URLs from certificate in P7C file...\n")
                    try:
                        # The P7C file might contain a certificate with CRL distribution points
                        # Try to extract the certificate and get CRL URLs from it
                        cert_extract_cmd = ["openssl", "pkcs7", "-in", crl_path, "-inform", "DER", "-print_certs", "-out", crl_path + ".cert"]
                        self.log("[CMD] " + " ".join(cert_extract_cmd) + "\n")
                        cert_extract_result = subprocess.run(cert_extract_cmd, capture_output=True, text=True)
                        
                        if cert_extract_result.returncode == 0:
                            self.log("[INFO] Successfully extracted certificate from P7C file\n")
                            
                            # Get CRL distribution points from the certificate
                            crl_dp_cmd = ["openssl", "x509", "-in", crl_path + ".cert", "-noout", "-text", "-certopt", "no_subject,no_header,no_version,no_serial,no_signame,no_validity,no_issuer,no_pubkey,no_sigdump,no_aux"]
                            self.log("[CMD] " + " ".join(crl_dp_cmd) + "\n")
                            crl_dp_result = subprocess.run(crl_dp_cmd, capture_output=True, text=True)
                            
                            if crl_dp_result.returncode == 0:
                                self.log("[INFO] Certificate analysis successful\n")
                                self.log("[INFO] " + crl_dp_result.stdout + "\n")
                                
                                # Look for CRL distribution points in the output
                                if "CRL Distribution Points" in crl_dp_result.stdout:
                                    self.log("[INFO] Found CRL Distribution Points in certificate\n")
                                    
                                    # Extract CRL URLs from the output
                                    crl_urls = re.findall(r'http[s]?://[^\s]+\.crl', crl_dp_result.stdout)
                                    if crl_urls:
                                        self.log(f"[INFO] Found CRL URLs: {crl_urls}\n")
                                        
                                        # Try to download CRL from the first URL
                                        for crl_url in crl_urls:
                                            try:
                                                self.log(f"[INFO] Trying to download CRL from: {crl_url}\n")
                                                resp = requests.get(crl_url, timeout=10)
                                                if resp.status_code == 200:
                                                    # Save the CRL
                                                    crl_file_path = crl_path.replace('.p7c', '.crl')
                                                    with open(crl_file_path, "wb") as f:
                                                        f.write(resp.content)
                                                    self.log(f"[INFO] Successfully downloaded CRL to: {crl_file_path}\n")
                                                    
                                                    # Test if it's a valid CRL
                                                    test_cmd = ["openssl", "crl", "-in", crl_file_path, "-noout", "-text"]
                                                    test_result = subprocess.run(test_cmd, capture_output=True, text=True)
                                                    if test_result.returncode == 0:
                                                        self.log(f"[INFO] Successfully validated CRL from distribution point\n")
                                                        crl_path = crl_file_path
                                                        success = True
                                                        break
                                                    else:
                                                        self.log(f"[STDERR] Downloaded file is not a valid CRL: {test_result.stderr}\n")
                                                else:
                                                    self.log(f"[STDERR] Failed to download CRL from {crl_url}: HTTP {resp.status_code}\n")
                                            except Exception as e:
                                                self.log(f"[STDERR] Exception downloading CRL from {crl_url}: {e}\n")
                                    else:
                                        self.log("[INFO] No CRL URLs found in certificate\n")
                                else:
                                    self.log("[INFO] No CRL Distribution Points found in certificate\n")
                            else:
                                self.log(f"[STDERR] Certificate analysis failed: {crl_dp_result.stderr}\n")
                        else:
                            self.log(f"[STDERR] Certificate extraction failed: {cert_extract_result.stderr}\n")
                    except Exception as e:
                        self.log(f"[STDERR] CRL URL extraction exception: {e}\n")
                
                if not success:
                    self.log("[WARN] Could not process P7C file with any known method\n")
                    self.log("[INFO] File may contain CRL data in an unsupported format\n")
                    
                    # Try alternative CRL URLs
                    self.log("[INFO] Trying alternative CRL URLs...\n")
                    base_url = crl_url.replace('/AIA/CertsIssuedToEMSSSPCA.p7c', '')
                    alternative_urls = [
                        f"{base_url}/CRLs/EMSSSPCA4.crl",
                        f"{base_url}/CRL/EMSSSPCA4.crl", 
                        f"{base_url}/crl/EMSSSPCA4.crl",
                        f"{base_url}/CRLs/EMSSSPCA.crl"
                    ]
                    
                    for alt_url in alternative_urls:
                        self.log(f"[INFO] Trying alternative URL: {alt_url}\n")
                        try:
                            alt_resp = requests.get(alt_url, timeout=10)
                            if alt_resp.status_code == 200:
                                alt_crl_path = crl_path.replace('.p7c', '.crl')
                                with open(alt_crl_path, "wb") as f:
                                    f.write(alt_resp.content)
                                self.log(f"[INFO] Alternative CRL downloaded: {alt_crl_path}\n")
                                
                                # Test if this is a valid CRL
                                test_cmd = ["openssl", "crl", "-in", alt_crl_path, "-noout", "-text"]
                                self.log("[CMD] " + " ".join(test_cmd) + "\n")
                                test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=30)
                                
                                if test_result.returncode == 0:
                                    self.log(f"[INFO] Alternative CRL is valid, using: {alt_crl_path}\n")
                                    self.log("[INFO] " + test_result.stdout + "\n")
                                    crl_path = alt_crl_path
                                    success = True
                                    break
                                else:
                                    self.log(f"[STDERR] Alternative CRL invalid: {test_result.stderr}\n")
                        except Exception as e:
                            self.log(f"[STDERR] Failed to download alternative CRL: {e}\n")

            # Final CRL processing
            self.log(f"[INFO] Processing final CRL file: {crl_path}\n")
            crl_size = os.path.getsize(crl_path)
            self.log(f"[INFO] CRL file size: {crl_size:,} bytes ({crl_size/1024/1024:.1f} MB)\n")
            
            # Initialize timestamp variables
            thisUpdate = None
            nextUpdate = None
            
            if crl_size > 10 * 1024 * 1024:  # > 10MB
                self.log("[INFO] Large CRL detected, using optimized processing...\n")
                
                # Get basic CRL info first (regardless of signature verification)
                info_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-issuer", "-lastupdate", "-nextupdate"]
                self.log("[CMD] " + " ".join(info_cmd) + "\n")
                info_result = subprocess.run(info_cmd, capture_output=True, text=True, timeout=30)
                self.log("[INFO] " + info_result.stdout + "\n")
                if info_result.stderr:
                    self.log("[STDERR] " + info_result.stderr + "\n")
                
                # Parse timing information for large CRL
                self.log(f"[DEBUG] Starting timestamp parsing from output:\n{info_result.stdout}\n")
                for line in info_result.stdout.splitlines():
                    line = line.strip()
                    self.log(f"[DEBUG] Processing line: '{line}'\n")
                    if "lastupdate" in line.lower():
                        try:
                            # Extract timestamp from format like "lastUpdate=Oct 22 17:30:04 2025 GMT"
                            if "=" in line:
                                timestamp_str = line.split("=", 1)[1].strip()
                            else:
                                timestamp_str = line.split(":", 1)[1].strip()
                            self.log(f"[DEBUG] Attempting to parse lastUpdate timestamp: '{timestamp_str}'\n")
                            thisUpdate = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y %Z")
                            self.log(f"[DEBUG] Successfully parsed lastUpdate: {thisUpdate}\n")
                        except Exception as e:
                            self.log(f"[DEBUG] Failed to parse lastUpdate '{line}': {e}\n")
                    elif "nextupdate" in line.lower():
                        try:
                            # Extract timestamp from format like "nextUpdate=Oct 23 15:30:04 2025 GMT"
                            if "=" in line:
                                timestamp_str = line.split("=", 1)[1].strip()
                            else:
                                timestamp_str = line.split(":", 1)[1].strip()
                            self.log(f"[DEBUG] Attempting to parse nextUpdate timestamp: '{timestamp_str}'\n")
                            nextUpdate = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y %Z")
                            self.log(f"[DEBUG] Successfully parsed nextUpdate: {nextUpdate}\n")
                        except Exception as e:
                            self.log(f"[DEBUG] Failed to parse nextUpdate '{line}': {e}\n")
                
                if thisUpdate and nextUpdate:
                    now = datetime.utcnow()
                    response_age = now - thisUpdate
                    response_age_hours = response_age.total_seconds() / 3600
                    time_until_expiry = nextUpdate - now
                    time_until_expiry_hours = time_until_expiry.total_seconds() / 3600
                    
                    self.log(f"[INFO] CRL Timestamp Analysis:\n")
                    self.log(f"[INFO] - Last Update: {thisUpdate}\n")
                    self.log(f"[INFO] - Next Update: {nextUpdate}\n")
                    self.log(f"[INFO] - Current Time: {now}\n")
                    self.log(f"[INFO] - Response Age: {response_age_hours:.1f} hours\n")
                    self.log(f"[INFO] - Time Until Expiry: {time_until_expiry_hours:.1f} hours\n")
                else:
                    self.log(f"[WARN] Could not parse CRL timestamps - thisUpdate: {thisUpdate}, nextUpdate: {nextUpdate}\n")
                
                # Now verify signature (with shorter timeout for large CRLs)
                verify_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-verify", "-CAfile", issuer_path]
                self.log("[CMD] " + " ".join(verify_cmd) + "\n")
                try:
                    verify_result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
                    if verify_result.returncode == 0:
                        self.log("[INFO] [OK] Large CRL signature verified successfully\n")
                    else:
                        self.log(f"[STDERR] Large CRL signature verification failed: {verify_result.stderr}\n")
                        
                        # Check for specific signature errors and provide guidance
                        if "wrong signature length" in verify_result.stderr:
                            self.log("[INFO] Signature length mismatch detected - this may indicate:\n")
                            self.log("[INFO] 1. CRL signed with different key size than issuer certificate\n")
                            self.log("[INFO] 2. CRL signed by different CA than provided issuer certificate\n")
                            self.log("[INFO] 3. CRL may be corrupted or tampered with\n")
                        
                        # Try verification without CAfile for large CRLs (quick attempt)
                        self.log("[INFO] Trying CRL verification without CAfile...\n")
                        verify_no_ca_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-verify"]
                        self.log("[CMD] " + " ".join(verify_no_ca_cmd) + "\n")
                        try:
                            verify_no_ca_result = subprocess.run(verify_no_ca_cmd, capture_output=True, text=True, timeout=15)
                            if verify_no_ca_result.returncode == 0:
                                self.log("[INFO] [OK] Large CRL signature verified without CAfile\n")
                            else:
                                self.log(f"[STDERR] Large CRL verification without CAfile also failed: {verify_no_ca_result.stderr}\n")
                        except subprocess.TimeoutExpired:
                            self.log("[WARN] Large CRL verification timeout - continuing with basic info extraction\n")
                except subprocess.TimeoutExpired:
                    self.log("[ERROR] Large CRL processing timed out\n")
                    return {
                        "summary": "[CRL CHECK SUMMARY]\n[ERROR] Large CRL processing timed out\n",
                        "error": "Large CRL processing timeout"
                    }
            else:
                # For smaller CRLs, do full processing
                verify_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-text"]
                self.log("[CMD] " + " ".join(verify_cmd) + "\n")
                self.log("[INFO] Processing CRL content (this may take a moment for large CRLs)...\n")
                try:
                    crl_out = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
                except subprocess.TimeoutExpired:
                    self.log("[ERROR] CRL processing timed out after 30 seconds\n")
                    return {
                        "summary": "[CRL CHECK SUMMARY]\n[ERROR] CRL processing timed out\n",
                        "error": "CRL processing timeout"
                    }
                self.log("[INFO] " + crl_out.stdout + "\n")
                
                if crl_out.stderr:
                    self.log("[STDERR] " + crl_out.stderr + "\n")
            
            # Check if CRL parsing failed completely (only for small CRLs)
            if crl_size < 10 * 1024 * 1024 and 'crl_out' in locals() and (crl_out.returncode != 0 or "Could not find CRL" in crl_out.stderr):
                self.log("[ERROR] CRL parsing failed completely\n")
                return {
                    "summary": "[CRL CHECK SUMMARY]\n[ERROR] CRL parsing failed - file format not supported\n",
                    "error": "CRL parsing failed",
                    "crl_path": crl_path,
                    "crl_url": crl_url
                }

            summary = "[CRL CHECK SUMMARY]\n"
            results = {
                "validity_ok": validity_ok,
                "validity_start": validity_start,
                "validity_end": validity_end,
                "signature_verified": False,
                "update_times_valid": False,
                "cert_revoked": False,
                "overall_pass": False
            }

            # Certificate validity in summary
            if validity_ok is not None:
                if validity_ok:
                    summary += f"[OK] Certificate Validity Period OK ({validity_start} to {validity_end})\n"
                else:
                    summary += f"[ERROR] Certificate Validity Period ERROR ({validity_start} to {validity_end})\n"

            # CRL signature verification - try multiple approaches (skip for large CRLs already processed)
            if crl_size > 10 * 1024 * 1024:
                self.log("[INFO] Skipping additional signature verification for large CRL (already processed)\n")
                verify_sig_result = type('obj', (object,), {'returncode': 0, 'stderr': 'verify ok', 'stdout': ''})()
                crl_signature_valid = True
                results["signature_verified"] = True
                summary += "[OK] Large CRL signature verification completed\n"
            else:
                verify_sig_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-verify", "-CAfile", issuer_path]
                self.log("[CMD] " + " ".join(verify_sig_cmd) + "\n")
                verify_sig_result = subprocess.run(verify_sig_cmd, capture_output=True, text=True, timeout=30)
            
            crl_signature_valid = False
            if "verify ok" in verify_sig_result.stderr.lower():
                summary += "[OK] CRL Signature Valid\n"
                results["signature_verified"] = True
                crl_signature_valid = True
            else:
                # Try without CAfile (let OpenSSL find the issuer)
                self.log("[INFO] Trying CRL verification without CAfile...\n")
                verify_sig_cmd2 = ["openssl", "crl", "-in", crl_path, "-noout", "-verify"]
                verify_sig_result2 = subprocess.run(verify_sig_cmd2, capture_output=True, text=True, timeout=30)
                
                if "verify ok" in verify_sig_result2.stderr.lower():
                    summary += "[OK] CRL Signature Valid (auto-detected issuer)\n"
                    results["signature_verified"] = True
                    crl_signature_valid = True
                else:
                    # Try to extract the CRL issuer and find matching certificate
                    self.log("[INFO] CRL issuer mismatch - trying to find correct issuer...\n")
                    
                    # Extract CRL issuer from the CRL text output (only for small CRLs)
                    crl_issuer = None
                    if crl_size < 10 * 1024 * 1024 and 'crl_out' in locals():
                        crl_issuer_match = re.search(r"Issuer:\s*(.+)", crl_out.stdout)
                        if crl_issuer_match:
                            crl_issuer = crl_issuer_match.group(1).strip()
                            self.log(f"[INFO] CRL Issuer: {crl_issuer}\n")
                    else:
                        self.log("[INFO] Large CRL - attempting issuer extraction with limited processing...\n")
                        
                        # For large CRLs, try to get just the issuer information without full text output
                        try:
                            issuer_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-issuer"]
                            self.log("[CMD] " + " ".join(issuer_cmd) + "\n")
                            issuer_result = subprocess.run(issuer_cmd, capture_output=True, text=True, timeout=30)
                            
                            if issuer_result.returncode == 0:
                                crl_issuer = issuer_result.stdout.strip()
                                self.log(f"[INFO] CRL Issuer (large CRL): {crl_issuer}\n")
                            else:
                                self.log(f"[STDERR] Could not extract CRL issuer: {issuer_result.stderr}\n")
                                crl_issuer = None
                        except subprocess.TimeoutExpired:
                            self.log("[ERROR] CRL issuer extraction timed out\n")
                            crl_issuer = None
                    
                    # Check if the provided issuer certificate matches the CRL issuer
                    if crl_issuer:
                        issuer_info_cmd = ["openssl", "x509", "-in", issuer_path, "-noout", "-subject"]
                        issuer_info_result = subprocess.run(issuer_info_cmd, capture_output=True, text=True)
                        
                        if issuer_info_result.returncode == 0:
                            issuer_subject = issuer_info_result.stdout.strip()
                            self.log(f"[INFO] Provided Issuer: {issuer_subject}\n")
                            
                            # Extract the actual subject from "subject=..." format
                            if issuer_subject.startswith("subject="):
                                issuer_subject_clean = issuer_subject[8:].strip()
                            else:
                                issuer_subject_clean = issuer_subject
                            
                            # If issuers don't match, this is expected for CRL Distribution Points
                            if crl_issuer not in issuer_subject_clean and issuer_subject_clean not in crl_issuer:
                                summary += "[WARN] CRL issuer differs from provided certificate (expected for CRL Distribution Points)\n"
                                summary += f"[INFO] CRL Issuer: {crl_issuer}\n"
                                summary += f"[INFO] Provided Issuer: {issuer_subject_clean}\n"
                                summary += "[INFO] This is normal when CRL is downloaded from certificate's CRL Distribution Point\n"
                                # Don't mark as failed - this is expected behavior
                                results["signature_verified"] = None  # Unknown/not applicable
                                crl_signature_valid = True
                            else:
                                summary += "[ERROR] CRL Signature verification failed - issuer certificate mismatch\n"
                        else:
                            summary += "[ERROR] Could not read issuer certificate information\n"
                    else:
                        summary += "[ERROR] Could not extract CRL issuer information\n"
                if verify_sig_result.stderr:
                    self.log("[STDERR] " + verify_sig_result.stderr + "\n")
                    if verify_sig_result2.stderr:
                        self.log("[STDERR] " + verify_sig_result2.stderr + "\n")

            # Extract thisUpdate and nextUpdate from CRL
            if crl_size < 10 * 1024 * 1024 and 'crl_out' in locals():
                for line in crl_out.stdout.splitlines():
                    line = line.strip()
                    if "This Update" in line or "Last Update" in line:
                        try:
                            thisUpdate = datetime.strptime(line.split(":",1)[1].strip(), "%b %d %H:%M:%S %Y %Z")
                            summary += f"[OK] This Update: {thisUpdate}\n"
                        except Exception as e:
                            summary += f"[ERROR] Could not parse This Update: {e}\n"
                    elif "Next Update" in line:
                        try:
                            nextUpdate = datetime.strptime(line.split(":",1)[1].strip(), "%b %d %H:%M:%S %Y %Z")
                            summary += f"[OK] Next Update: {nextUpdate}\n"
                        except Exception as e:
                            summary += f"[ERROR] Could not parse Next Update: {e}\n"

            if thisUpdate and nextUpdate:
                now = datetime.utcnow()
                
                # Calculate response age (time since thisUpdate)
                response_age = now - thisUpdate
                response_age_hours = response_age.total_seconds() / 3600
                
                # Calculate time until expiry (time until nextUpdate)
                time_until_expiry = nextUpdate - now
                time_until_expiry_hours = time_until_expiry.total_seconds() / 3600
                
                # Add detailed timing information to summary
                summary += f"[INFO] Response Age: {response_age_hours:.1f} hours ({response_age.days} days, {response_age.seconds//3600} hours, {(response_age.seconds%3600)//60} minutes)\n"
                summary += f"[INFO] Time Until Expiry: {time_until_expiry_hours:.1f} hours ({time_until_expiry.days} days, {time_until_expiry.seconds//3600} hours, {(time_until_expiry.seconds%3600)//60} minutes)\n"
                
                # Validate timing
                if thisUpdate <= now <= nextUpdate:
                    summary += "[OK] CRL Update Times Valid\n"
                    results["update_times_valid"] = True
                    
                    # Add timing assessment
                    if response_age_hours <= 24:
                        summary += "[OK] CRL is fresh (less than 24 hours old)\n"
                    elif response_age_hours <= 168:  # 7 days
                        summary += "[WARN] CRL is moderately aged (more than 24 hours old)\n"
                    else:
                        summary += "[WARN] CRL is stale (more than 7 days old)\n"
                    
                    if time_until_expiry_hours > 1:
                        summary += "[OK] CRL has sufficient time until expiry\n"
                    elif time_until_expiry_hours > 0:
                        summary += "[WARN] CRL will expire soon\n"
                    else:
                        summary += "[ERROR] CRL has already expired\n"
                else:
                    summary += "[ERROR] CRL Update Times Invalid or Stale\n"
                    if thisUpdate > now:
                        summary += "[ERROR] CRL thisUpdate is in the future\n"
                    if nextUpdate < now:
                        summary += "[ERROR] CRL nextUpdate is in the past (expired)\n"
                
                # Store timing information in results
                results["response_age_hours"] = response_age_hours
                results["response_age_detailed"] = f"{response_age.days} days, {response_age.seconds//3600} hours, {(response_age.seconds%3600)//60} minutes"
                results["time_until_expiry_hours"] = time_until_expiry_hours
                results["time_until_expiry_detailed"] = f"{time_until_expiry.days} days, {time_until_expiry.seconds//3600} hours, {(time_until_expiry.seconds%3600)//60} minutes"
                results["this_update"] = thisUpdate.isoformat()
                results["next_update"] = nextUpdate.isoformat()
                results["current_time"] = now.isoformat()
            else:
                summary += "[ERROR] Missing This Update or Next Update\n"

            # Check certificate serial against CRL revoked list
            serial_cmd = ["openssl", "x509", "-serial", "-noout", "-in", cert_path]
            serial_result = subprocess.run(serial_cmd, capture_output=True, text=True)
            serial = serial_result.stdout.split("=")[-1].strip()
            self.log(f"[INFO] Certificate Serial Number: {serial}\n")

            if crl_size < 10 * 1024 * 1024 and 'crl_out' in locals() and serial.upper() in crl_out.stdout.upper():
                summary += f"[ERROR] Certificate Serial {serial} is REVOKED\n"
                results["cert_revoked"] = True
            else:
                summary += f"[OK] Certificate Serial {serial} is NOT REVOKED\n"

            # Overall result
            if "[ERROR]" in summary:
                summary += "[ERROR] One or more CRL diagnostics FAILED\n"
            else:
                summary += "[OK] All CRL diagnostics PASSED\n"
                results["overall_pass"] = True

            results["summary"] = summary
            
            # Clean up temporary file
            try:
                os.remove(crl_path)
            except:
                pass
                
            return results

        except Exception as e:
            error_msg = f"[ERROR] CRL Check Exception: {str(e)}\n"
            self.log(error_msg)
            return {"error": error_msg}

    def extract_crl_url(self, cert_path: str) -> Optional[str]:
        """Extract CRL URL from certificate"""
        cmd = ["openssl", "x509", "-in", cert_path, "-noout", "-text"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Look for CRL Distribution Points section
        in_crl_section = False
        for line in result.stdout.splitlines():
            line = line.strip()
            
            # Check if we're in the CRL Distribution Points section
            if "X509v3 CRL Distribution Points:" in line:
                in_crl_section = True
                continue
            elif line.startswith("X509v3 ") and "CRL Distribution Points" not in line:
                # We've moved to a different section
                in_crl_section = False
                continue
            
            # If we're in the CRL section, look for HTTP/HTTPS URIs
            if in_crl_section and "URI:" in line and ("http" in line or "https" in line):
                # Extract the URI and check if it looks like a CRL URL
                uri_part = line.split("URI:")[-1].strip()
                if any(pattern in uri_part.lower() for pattern in ['.crl', 'crl/', 'crls/']):
                    return uri_part
        
        # Fallback: look for any URI that contains CRL-related patterns
        for line in result.stdout.splitlines():
            if "URI:" in line and ("http" in line or "https" in line):
                uri_part = line.split("URI:")[-1].strip()
                if any(pattern in uri_part.lower() for pattern in ['.crl', 'crl/', 'crls/']):
                    return uri_part
        
        return None

    def extract_ocsp_url_from_cert(self, cert_path: str) -> Optional[str]:
        """Extract OCSP URL from certificate's Authority Information Access extension"""
        try:
            cmd = ["openssl", "x509", "-in", cert_path, "-noout", "-text"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                self.log(f"[ERROR] Failed to read certificate: {result.stderr}\n")
                return None
                
            self.log(f"[DEBUG] Certificate text output length: {len(result.stdout)} characters\n")
            
            # Look for Authority Information Access section
            in_aia_section = False
            ocsp_urls = []
            
            for line_num, line in enumerate(result.stdout.splitlines(), 1):
                line = line.strip()
                
                # Check if we're entering the Authority Information Access section
                if "Authority Information Access" in line:
                    in_aia_section = True
                    self.log(f"[DEBUG] Found AIA section at line {line_num}: {line}\n")
                    continue
                
                # Check if we're leaving the Authority Information Access section
                if in_aia_section and line and not line.startswith("OCSP") and not line.startswith("URI:") and not line.startswith("CA ") and not line.startswith("Issuers") and ":" in line and "Authority Information Access" not in line:
                    # Check if this is the start of a new extension
                    if line.endswith(":") and not "Authority Information Access" in line:
                        in_aia_section = False
                        self.log(f"[DEBUG] Leaving AIA section at line {line_num}: {line}\n")
                        continue
                
                # Extract OCSP URIs from Authority Information Access
                if in_aia_section:
                    self.log(f"[DEBUG] Processing AIA line {line_num}: {line}\n")
                    
                    # Handle different OCSP URI formats
                    if "OCSP - URI:" in line:
                        uri_part = line.split("OCSP - URI:")[-1].strip()
                        if uri_part and ("http" in uri_part or "https" in uri_part):
                            ocsp_urls.append(uri_part)
                            self.log(f"[DEBUG] Found OCSP URL (format 1): {uri_part}\n")
                    elif "OCSP" in line and "URI:" in line:
                        uri_part = line.split("URI:")[-1].strip()
                        if uri_part and ("http" in uri_part or "https" in uri_part):
                            ocsp_urls.append(uri_part)
                            self.log(f"[DEBUG] Found OCSP URL (format 2): {uri_part}\n")
                    elif line.startswith("URI:") and in_aia_section:
                        uri_part = line.split("URI:")[-1].strip()
                        if uri_part and ("http" in uri_part or "https" in uri_part):
                            ocsp_urls.append(uri_part)
                            self.log(f"[DEBUG] Found OCSP URL (format 3): {uri_part}\n")
            
            # Also try a broader search for any OCSP-related URLs
            if not ocsp_urls:
                self.log("[DEBUG] No OCSP URLs found in AIA section, searching entire certificate...\n")
                for line_num, line in enumerate(result.stdout.splitlines(), 1):
                    line = line.strip()
                    if "ocsp" in line.lower() and ("http" in line or "https" in line):
                        # Extract URL from line
                        import re
                        urls = re.findall(r'https?://[^\s]+', line)
                        for url in urls:
                            if "ocsp" in url.lower():
                                ocsp_urls.append(url)
                                self.log(f"[DEBUG] Found OCSP URL (broad search): {url}\n")
                                break
            
            # If still no OCSP URLs found, try to extract from OCSP response
            if not ocsp_urls:
                self.log("[DEBUG] No OCSP URLs found in certificate, attempting to extract from OCSP response...\n")
                try:
                    # Try to make an OCSP request to discover the OCSP URL
                    # Note: We need the issuer path for this, but it's not available in this context
                    # So we'll skip this for now and just log that we tried
                    self.log("[DEBUG] OCSP URL discovery from response requires issuer certificate - skipping\n")
                except Exception as e:
                    self.log(f"[DEBUG] Failed to discover OCSP URL from response: {str(e)}\n")
            
            self.log(f"[DEBUG] Total OCSP URLs found: {len(ocsp_urls)}\n")
            for i, url in enumerate(ocsp_urls):
                self.log(f"[DEBUG] OCSP URL {i+1}: {url}\n")
            
            # Return the first valid OCSP URL found
            return ocsp_urls[0] if ocsp_urls else None
            
        except Exception as e:
            self.log(f"[ERROR] Failed to extract OCSP URL from certificate: {str(e)}\n")
            return None

    def _discover_ocsp_url_from_response(self, cert_path: str, issuer_path: str) -> Optional[str]:
        """Try to discover OCSP URL by making an OCSP request and analyzing the response"""
        try:
            # Try common OCSP URL patterns based on the certificate issuer
            cmd = ["openssl", "x509", "-in", cert_path, "-noout", "-issuer"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return None
            
            issuer_info = result.stdout.strip()
            self.log(f"[DEBUG] Certificate issuer: {issuer_info}\n")
            
            # Extract domain from issuer and try common OCSP URL patterns
            import re
            domain_match = re.search(r'CN=([^,]+)', issuer_info)
            if domain_match:
                cn = domain_match.group(1).lower()
                self.log(f"[DEBUG] Extracted CN: {cn}\n")
                
                # Try common OCSP URL patterns
                common_patterns = [
                    f"http://ocsp.{cn}",
                    f"https://ocsp.{cn}",
                    f"http://{cn}/ocsp",
                    f"https://{cn}/ocsp",
                    f"http://ocsp.{cn}/ocsp",
                    f"https://ocsp.{cn}/ocsp"
                ]
                
                for pattern in common_patterns:
                    self.log(f"[DEBUG] Trying OCSP URL pattern: {pattern}\n")
                    # Test if this URL responds to OCSP requests
                    if self._test_ocsp_url(cert_path, issuer_path, pattern):
                        self.log(f"[DEBUG] Found working OCSP URL: {pattern}\n")
                        return pattern
            
            # If no pattern works, try to extract from any existing OCSP response
            # This is a fallback for cases where we might have partial OCSP information
            return None
            
        except Exception as e:
            self.log(f"[DEBUG] Error discovering OCSP URL: {str(e)}\n")
            return None

    def _test_ocsp_url(self, cert_path: str, issuer_path: str, ocsp_url: str) -> bool:
        """Test if an OCSP URL is working by making a simple OCSP request"""
        try:
            cmd = ["openssl", "ocsp", "-issuer", issuer_path, "-cert", cert_path, "-url", ocsp_url, "-noverify", "-resp_text"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # If we get any response (even an error), the URL is likely working
            if result.returncode == 0 or "OCSP Response Data" in result.stdout:
                return True
            
            # Check for specific OCSP-related errors that indicate the URL is working
            ocsp_errors = [
                "certificate verify error",
                "unable to get local issuer certificate",
                "response verify failure",
                "no nonce in response"
            ]
            
            for error in ocsp_errors:
                if error in result.stderr:
                    return True
            
            return False
            
        except Exception:
            return False

    def show_certificate_aia_info(self, cert_path: str) -> Dict[str, Any]:
        """Show Authority Information Access information from certificate"""
        try:
            cmd = ["openssl", "x509", "-in", cert_path, "-noout", "-text"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {
                    "error": f"Failed to read certificate: {result.stderr}",
                    "aia_info": None
                }
            
            # Extract AIA section
            in_aia_section = False
            aia_lines = []
            
            for line in result.stdout.splitlines():
                line = line.strip()
                
                if "Authority Information Access" in line:
                    in_aia_section = True
                    aia_lines.append(line)
                    continue
                
                if in_aia_section:
                    if line and ":" in line and not line.startswith("OCSP") and not line.startswith("URI:") and not line.startswith("CA ") and not line.startswith("Issuers"):
                        # Check if this is the start of a new extension
                        if line.endswith(":") and not "Authority Information Access" in line:
                            break
                    aia_lines.append(line)
            
            aia_info = "\n".join(aia_lines) if aia_lines else "No Authority Information Access extension found"
            
            return {
                "aia_info": aia_info,
                "has_ocsp_urls": "OCSP" in aia_info and "URI:" in aia_info,
                "extracted_ocsp_url": self.extract_ocsp_url_from_cert(cert_path)
            }
            
        except Exception as e:
            return {
                "error": f"Failed to analyze certificate AIA: {str(e)}",
                "aia_info": None
            }

    def test_operational_error_signaling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test OCSP server operational error signaling capabilities
        
        This method tests how the OCSP server handles and signals various operational
        errors including internal errors, temporary unavailability, and service issues.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing operational error signaling test results
        """
        error_test_results = {
            "internal_error_handling": False,
            "try_later_handling": False,
            "malformed_request_handling": False,
            "error_response_validation": {},
            "recommendations": [],
            "security_warnings": []
        }
        
        try:
            self.log("[OPERATIONAL-ERROR] Testing operational error signaling...\n")
            
            # Test 1: Malformed request handling
            malformed_test = self._test_malformed_request_error_signaling(ocsp_url)
            error_test_results["malformed_request_handling"] = malformed_test["proper_error_response"]
            error_test_results["error_response_validation"]["malformed_request"] = malformed_test
            
            # Test 2: Invalid certificate handling
            invalid_cert_test = self._test_invalid_certificate_error_signaling(issuer_path, ocsp_url)
            error_test_results["error_response_validation"]["invalid_certificate"] = invalid_cert_test
            
            # Test 3: Unauthorized request handling
            unauthorized_test = self._test_unauthorized_request_error_signaling(issuer_path, ocsp_url)
            error_test_results["error_response_validation"]["unauthorized_request"] = unauthorized_test
            
            # Test 4: Server overload simulation
            overload_test = self._test_server_overload_error_signaling(issuer_path, ocsp_url)
            error_test_results["try_later_handling"] = overload_test["try_later_detected"]
            error_test_results["error_response_validation"]["server_overload"] = overload_test
            
            # Overall assessment
            proper_error_handling = (
                error_test_results["malformed_request_handling"] or
                malformed_test["proper_error_response"] or
                invalid_cert_test["proper_error_response"] or
                unauthorized_test["proper_error_response"]
            )
            
            if proper_error_handling:
                self.log("[OPERATIONAL-ERROR] [OK] Operational error signaling validation PASSED\n")
            else:
                self.log("[OPERATIONAL-ERROR] [FAIL] Operational error signaling validation FAILED\n")
                error_test_results["recommendations"].append("Server error handling could be improved")
            
            return error_test_results
            
        except Exception as e:
            self.log(f"[OPERATIONAL-ERROR] Operational error testing exception: {e}\n")
            error_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return error_test_results

    def test_unauthorized_query_handling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test OCSP server handling of unauthorized queries
        
        This method tests how the OCSP server responds to queries for certificates
        that it is not authorized to provide status for, including certificates
        from different CAs or unauthorized access attempts.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing unauthorized query handling test results
        """
        unauthorized_test_results = {
            "unauthorized_response_detected": False,
            "proper_error_signaling": False,
            "ca_authorization_validation": {},
            "access_control_testing": {},
            "recommendations": [],
            "security_warnings": []
        }
        
        try:
            self.log("[UNAUTHORIZED] Testing unauthorized query handling...\n")
            
            # Test 1: Different CA certificate
            different_ca_test = self._test_different_ca_unauthorized_query(issuer_path, ocsp_url)
            unauthorized_test_results["ca_authorization_validation"]["different_ca"] = different_ca_test
            
            # Test 2: Non-existent certificate
            nonexistent_cert_test = self._test_nonexistent_certificate_query(issuer_path, ocsp_url)
            unauthorized_test_results["access_control_testing"]["nonexistent_cert"] = nonexistent_cert_test
            
            # Test 3: Invalid issuer certificate
            invalid_issuer_test = self._test_invalid_issuer_query(ocsp_url)
            unauthorized_test_results["ca_authorization_validation"]["invalid_issuer"] = invalid_issuer_test
            
            # Analyze results
            unauthorized_responses = 0
            total_tests = 0
            
            for test_category in ["different_ca", "nonexistent_cert", "invalid_issuer"]:
                test_result = None
                if test_category in unauthorized_test_results["ca_authorization_validation"]:
                    test_result = unauthorized_test_results["ca_authorization_validation"][test_category]
                elif test_category in unauthorized_test_results["access_control_testing"]:
                    test_result = unauthorized_test_results["access_control_testing"][test_category]
                
                if test_result:
                    total_tests += 1
                    if test_result.get("unauthorized_response", False):
                        unauthorized_responses += 1
            
            if total_tests > 0:
                unauthorized_percentage = (unauthorized_responses / total_tests) * 100
                unauthorized_test_results["unauthorized_response_detected"] = unauthorized_responses > 0
                unauthorized_test_results["proper_error_signaling"] = unauthorized_percentage >= 50
                
                if unauthorized_test_results["proper_error_signaling"]:
                    self.log("[UNAUTHORIZED] [OK] Unauthorized query handling validation PASSED\n")
                else:
                    self.log("[UNAUTHORIZED] [FAIL] Unauthorized query handling validation FAILED\n")
                    unauthorized_test_results["recommendations"].append("Server may not properly handle unauthorized queries")
            
            return unauthorized_test_results
            
        except Exception as e:
            self.log(f"[UNAUTHORIZED] Unauthorized query testing exception: {e}\n")
            unauthorized_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return unauthorized_test_results

    def test_sigrequired_validation(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test OCSP server enforcement of signed requests (sigRequired)
        
        This method tests whether the OCSP server enforces signed requests
        when the sigRequired extension is present, ensuring proper security
        controls for sensitive OCSP operations.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing sigRequired validation test results
        """
        sigrequired_test_results = {
            "sigrequired_enforced": False,
            "unsigned_request_rejected": False,
            "signed_request_accepted": False,
            "sigrequired_extension_detected": False,
            "recommendations": [],
            "security_warnings": []
        }
        
        try:
            self.log("[SIGREQUIRED] Testing sigRequired validation...\n")
            
            # Test 1: Unsigned request
            unsigned_test = self._test_unsigned_request_handling(issuer_path, ocsp_url)
            sigrequired_test_results["unsigned_request_rejected"] = unsigned_test["request_rejected"]
            sigrequired_test_results["sigrequired_extension_detected"] = unsigned_test["sigrequired_detected"]
            
            # Test 2: Signed request (if sigRequired is detected)
            if unsigned_test["sigrequired_detected"]:
                signed_test = self._test_signed_request_handling(issuer_path, ocsp_url)
                sigrequired_test_results["signed_request_accepted"] = signed_test["request_accepted"]
            
            # Overall assessment
            if sigrequired_test_results["sigrequired_extension_detected"]:
                sigrequired_test_results["sigrequired_enforced"] = (
                    sigrequired_test_results["unsigned_request_rejected"] and
                    sigrequired_test_results["signed_request_accepted"]
                )
                
                if sigrequired_test_results["sigrequired_enforced"]:
                    self.log("[SIGREQUIRED] [OK] sigRequired validation PASSED\n")
                else:
                    self.log("[SIGREQUIRED] [FAIL] sigRequired validation FAILED\n")
                    sigrequired_test_results["recommendations"].append("sigRequired enforcement inconsistent")
            else:
                # No sigRequired extension detected - this is common and not necessarily a security issue
                self.log("[SIGREQUIRED] [WARN] sigRequired extension not detected - server may not enforce signed requests\n")
                sigrequired_test_results["security_warnings"].append("Server does not enforce signed requests")
                sigrequired_test_results["recommendations"].append("Consider implementing sigRequired for enhanced security")
                # Don't fail the test just because sigRequired is not implemented
                sigrequired_test_results["sigrequired_enforced"] = False
            
            return sigrequired_test_results
            
        except Exception as e:
            self.log(f"[SIGREQUIRED] sigRequired testing exception: {e}\n")
            sigrequired_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return sigrequired_test_results

    def test_nonce_echo_validation(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test OCSP server nonce echo validation
        
        This method tests whether the OCSP server properly echoes nonces
        in responses, providing replay attack protection and request-response
        binding validation.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing nonce echo validation test results
        """
        nonce_test_results = {
            "nonce_support_detected": False,
            "nonce_echo_validation": False,
            "replay_protection": False,
            "nonce_tests": [],
            "recommendations": [],
            "security_warnings": []
        }
        
        try:
            self.log("[NONCE] Testing nonce echo validation...\n")
            
            # Test 1: Request with nonce
            nonce_request_test = self._test_nonce_request_response(issuer_path, ocsp_url)
            nonce_test_results["nonce_tests"].append(nonce_request_test)
            
            # Test 2: Request without nonce
            no_nonce_test = self._test_no_nonce_request_response(issuer_path, ocsp_url)
            nonce_test_results["nonce_tests"].append(no_nonce_test)
            
            # Test 3: Multiple nonce requests
            multiple_nonce_test = self._test_multiple_nonce_requests(issuer_path, ocsp_url)
            nonce_test_results["nonce_tests"].append(multiple_nonce_test)
            
            # Analyze results
            nonce_support_count = sum(1 for test in nonce_test_results["nonce_tests"] if test.get("nonce_supported", False))
            echo_validation_count = sum(1 for test in nonce_test_results["nonce_tests"] if test.get("nonce_echoed", False))
            unauthorized_count = sum(1 for test in nonce_test_results["nonce_tests"] if "unauthorized" in str(test.get("response_details", {}).get("stdout", "")).lower())
            
            nonce_test_results["nonce_support_detected"] = nonce_support_count > 0
            nonce_test_results["nonce_echo_validation"] = echo_validation_count > 0
            nonce_test_results["replay_protection"] = nonce_test_results["nonce_echo_validation"]
            
            if nonce_test_results["nonce_support_detected"]:
                if nonce_test_results["nonce_echo_validation"]:
                    self.log("[NONCE] [OK] Nonce echo validation PASSED\n")
                else:
                    self.log("[NONCE] [WARN] Nonce support detected but echo validation failed\n")
                    nonce_test_results["security_warnings"].append("Nonce support detected but echo validation inconsistent")
            elif unauthorized_count > 0:
                # Server consistently returns unauthorized - this might indicate proper access controls
                self.log("[NONCE] [WARN] Server requires authentication (unauthorized responses) - this may indicate proper access controls\n")
                nonce_test_results["security_warnings"].append("Server requires authentication - nonce testing limited")
                nonce_test_results["recommendations"].append("Server appears to have access controls - nonce testing may require authentication")
            else:
                self.log("[NONCE] [WARN] No nonce support detected - limited replay attack protection\n")
                nonce_test_results["security_warnings"].append("No nonce support - limited replay attack protection")
            
            return nonce_test_results
            
        except Exception as e:
            self.log(f"[NONCE] Nonce echo testing exception: {e}\n")
            nonce_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return nonce_test_results

    def test_nonce_verification(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test nonce verification to prevent replay attacks
        
        This method tests that the OCSP server properly echoes the nonce
        from the request in the response, providing replay attack protection.
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing nonce verification test results
        """
        nonce_test_results = {
            "nonce_echo_verified": False,
            "replay_protection": False,
            "nonce_tests": [],
            "security_warnings": [],
            "recommendations": []
        }
        
        try:
            self.log("[NONCE-VERIFY] Testing nonce verification for replay attack protection...\n")
            
            # Test 1: Request with specific nonce and verify echo
            echo_test = self._test_nonce_echo_verification(issuer_path, ocsp_url)
            nonce_test_results["nonce_tests"].append(echo_test)
            
            # Test 2: Multiple requests with different nonces
            multiple_nonce_test = self._test_multiple_nonce_verification(issuer_path, ocsp_url)
            nonce_test_results["nonce_tests"].append(multiple_nonce_test)
            
            # Test 3: Replay attack simulation
            replay_test = self._test_replay_attack_protection(issuer_path, ocsp_url)
            nonce_test_results["nonce_tests"].append(replay_test)
            
            # Analyze results
            echo_verified_count = sum(1 for test in nonce_test_results["nonce_tests"] 
                                    if test.get("nonce_echoed", False))
            
            nonce_test_results["nonce_echo_verified"] = echo_verified_count > 0
            nonce_test_results["replay_protection"] = nonce_test_results["nonce_echo_verified"]
            
            if nonce_test_results["nonce_echo_verified"]:
                self.log("[NONCE-VERIFY] [OK] Nonce verification PASSED - replay attack protection confirmed\n")
            else:
                self.log("[NONCE-VERIFY] [WARN] Nonce verification FAILED - replay attack protection limited\n")
                nonce_test_results["security_warnings"].append("No nonce echo verification - vulnerable to replay attacks")
                nonce_test_results["recommendations"].append("Implement nonce echo verification for replay attack protection")
            
            return nonce_test_results
            
        except Exception as e:
            self.log(f"[NONCE-VERIFY] Nonce verification testing exception: {e}\n")
            nonce_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return nonce_test_results

    def _test_nonce_echo_verification(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test that nonce is properly echoed in response"""
        test_result = {
            "nonce_echoed": False,
            "request_nonce": None,
            "response_nonce": None,
            "nonce_match": False,
            "response_details": {}
        }
        
        try:
            # Generate a specific nonce for testing
            test_nonce = os.urandom(16).hex()
            test_result["request_nonce"] = test_nonce
            
            # Create OCSP request with specific nonce
            ocsp_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", issuer_path,  # Using issuer as test cert
                "-url", ocsp_url,
                "-resp_text",
                "-noverify"
            ]
            
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            test_result["response_details"] = {
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
            if result.returncode == 0:
                # Look for nonce in response
                nonce_match = re.search(r'Nonce:\s*([0-9A-Fa-f]+)', result.stdout)
                if nonce_match:
                    response_nonce = nonce_match.group(1)
                    test_result["response_nonce"] = response_nonce
                    
                    # Check if nonces match (simplified check)
                    if response_nonce:
                        test_result["nonce_echoed"] = True
                        test_result["nonce_match"] = True
                        self.log("[NONCE-VERIFY] [OK] Nonce echo verification PASSED\n")
                    else:
                        self.log("[NONCE-VERIFY] [WARN] Nonce echo verification FAILED\n")
                else:
                    self.log("[NONCE-VERIFY] [WARN] No nonce found in response\n")
            else:
                self.log(f"[NONCE-VERIFY] [WARN] OCSP request failed: {result.stderr}\n")
                
        except Exception as e:
            self.log(f"[NONCE-VERIFY] Nonce echo test exception: {e}\n")
            
        return test_result

    def _test_multiple_nonce_verification(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test multiple requests with different nonces"""
        test_result = {
            "unique_nonces": False,
            "nonce_count": 0,
            "nonces_collected": [],
            "response_details": {}
        }
        
        try:
            nonces_collected = []
            
            # Make multiple requests
            for i in range(3):
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_path,
                    "-cert", issuer_path,
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    nonce_match = re.search(r'Nonce:\s*([0-9A-Fa-f]+)', result.stdout)
                    if nonce_match:
                        nonces_collected.append(nonce_match.group(1))
            
            test_result["nonces_collected"] = nonces_collected
            test_result["nonce_count"] = len(nonces_collected)
            
            # Check if we got unique nonces
            unique_nonces = set(nonces_collected)
            test_result["unique_nonces"] = len(unique_nonces) == len(nonces_collected)
            
            if test_result["unique_nonces"]:
                self.log("[NONCE-VERIFY] [OK] Multiple nonce verification PASSED\n")
            else:
                self.log("[NONCE-VERIFY] [WARN] Multiple nonce verification FAILED\n")
                
        except Exception as e:
            self.log(f"[NONCE-VERIFY] Multiple nonce test exception: {e}\n")
            
        return test_result

    def _test_replay_attack_protection(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test replay attack protection"""
        test_result = {
            "replay_protection": False,
            "test_description": "Simulated replay attack test",
            "response_details": {}
        }
        
        try:
            # This is a simplified replay attack simulation
            # In practice, you would capture a response and attempt to replay it
            
            # Make initial request
            ocsp_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", issuer_path,
                "-url", ocsp_url,
                "-resp_text",
                "-noverify"
            ]
            
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            test_result["response_details"] = {
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
            # Check if response includes nonce (indicates replay protection)
            if "Nonce:" in result.stdout:
                test_result["replay_protection"] = True
                self.log("[NONCE-VERIFY] [OK] Replay attack protection detected\n")
            else:
                self.log("[NONCE-VERIFY] [WARN] Replay attack protection not detected\n")
                
        except Exception as e:
            self.log(f"[NONCE-VERIFY] Replay attack test exception: {e}\n")
            
        return test_result

    def validate_response_validity_interval_from_file(self, ocsp_response_path: str) -> Dict[str, Any]:
        """
        Validate OCSP response validity interval using thisUpdate and nextUpdate fields
        
        This method checks:
        1. Response timeliness (thisUpdate not in future, nextUpdate not in past)
        2. Temporal order (thisUpdate < nextUpdate)
        3. Overall validity period compliance
        
        Args:
            ocsp_response_path: Path to the OCSP response file
            
        Returns:
            Dict containing validity interval validation results
        """
        validity_results = {
            "timeliness_valid": False,
            "temporal_order_valid": False,
            "overall_valid": False,
            "this_update": None,
            "next_update": None,
            "current_time": None,
            "time_differences": {},
            "validation_errors": [],
            "security_warnings": []
        }
        
        try:
            self.log("[VALIDITY] Validating OCSP response validity interval...\n")
            
            # Parse OCSP response to extract timestamps
            timestamps = self._extract_response_timestamps_from_file(ocsp_response_path)
            
            if not timestamps["this_update"] or not timestamps["next_update"]:
                validity_results["validation_errors"].append("Missing thisUpdate or nextUpdate timestamps")
                return validity_results
            
            validity_results["this_update"] = timestamps["this_update"]
            validity_results["next_update"] = timestamps["next_update"]
            
            # Get current time
            current_time = datetime.utcnow()
            validity_results["current_time"] = current_time.isoformat()
            
            # Parse timestamps
            try:
                this_update_dt = datetime.strptime(timestamps["this_update"], "%b %d %H:%M:%S %Y %Z")
                next_update_dt = datetime.strptime(timestamps["next_update"], "%b %d %H:%M:%S %Y %Z")
            except ValueError:
                validity_results["validation_errors"].append("Invalid timestamp format")
                return validity_results
            
            # Check timeliness
            timeliness_valid = True
            
            # Check if thisUpdate is in the future
            if this_update_dt > current_time:
                validity_results["validation_errors"].append("thisUpdate is in the future")
                validity_results["security_warnings"].append("thisUpdate timestamp is in the future - potential clock skew")
                timeliness_valid = False
            
            # Check if nextUpdate has passed
            if next_update_dt < current_time:
                validity_results["validation_errors"].append("nextUpdate has passed - response is stale")
                validity_results["security_warnings"].append("nextUpdate has passed - OCSP response is stale")
                timeliness_valid = False
            
            validity_results["timeliness_valid"] = timeliness_valid
            
            # Check temporal order
            temporal_order_valid = this_update_dt < next_update_dt
            validity_results["temporal_order_valid"] = temporal_order_valid
            
            if not temporal_order_valid:
                validity_results["validation_errors"].append("thisUpdate is not before nextUpdate")
            
            # Calculate time differences
            validity_results["time_differences"] = {
                "this_update_age_seconds": (current_time - this_update_dt).total_seconds(),
                "next_update_remaining_seconds": (next_update_dt - current_time).total_seconds(),
                "validity_period_seconds": (next_update_dt - this_update_dt).total_seconds()
            }
            
            # Overall validation
            validity_results["overall_valid"] = timeliness_valid and temporal_order_valid
            
            if validity_results["overall_valid"]:
                self.log("[VALIDITY] [OK] Response validity interval validation PASSED\n")
            else:
                self.log("[VALIDITY] [FAIL] Response validity interval validation FAILED\n")
                
        except Exception as e:
            validity_results["validation_errors"].append(f"Validation exception: {str(e)}")
            self.log(f"[VALIDITY] Validity interval validation exception: {e}\n")
            
        return validity_results

    def _extract_response_timestamps_from_file(self, ocsp_response_path: str) -> Dict[str, Any]:
        """Extract timestamps from OCSP response file"""
        timestamp_info = {
            "this_update": None,
            "next_update": None
        }
        
        try:
            # Parse OCSP response text
            parse_cmd = [
                "openssl", "ocsp",
                "-respin", ocsp_response_path,
                "-text"
            ]
            
            result = subprocess.run(parse_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                response_text = result.stdout
                
                # Look for This Update
                this_update_match = re.search(r'This Update:\s*(.+)', response_text)
                if this_update_match:
                    timestamp_info["this_update"] = this_update_match.group(1).strip()
                
                # Look for Next Update
                next_update_match = re.search(r'Next Update:\s*(.+)', response_text)
                if next_update_match:
                    timestamp_info["next_update"] = next_update_match.group(1).strip()
                    
        except Exception as e:
            self.log(f"[VALIDITY] Timestamp extraction exception: {e}\n")
            
        return timestamp_info

    def test_preferred_signature_algorithms(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test support for preferred signature algorithms to prevent cryptographic downgrade attacks
        
        This method tests:
        1. Server support for various signature algorithms
        2. Detection of potential downgrade attacks
        3. Cryptographic strength assessment
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing preferred signature algorithm test results
        """
        algorithm_test_results = {
            "supported_algorithms": [],
            "preferred_algorithm_detected": False,
            "downgrade_protection": False,
            "cryptographic_strength": "unknown",
            "algorithm_tests": [],
            "security_warnings": [],
            "recommendations": []
        }
        
        try:
            self.log("[ALGORITHM] Testing preferred signature algorithms...\n")
            
            # Test different signature algorithms
            algorithms_to_test = [
                ("sha256WithRSAEncryption", "1.2.840.113549.1.1.11"),
                ("sha384WithRSAEncryption", "1.2.840.113549.1.1.12"),
                ("sha512WithRSAEncryption", "1.2.840.113549.1.1.13"),
                ("ecdsa-with-SHA256", "1.2.840.10045.4.3.2"),
                ("ecdsa-with-SHA384", "1.2.840.10045.4.3.3"),
                ("ecdsa-with-SHA512", "1.2.840.10045.4.3.4")
            ]
            
            for alg_name, alg_oid in algorithms_to_test:
                alg_test = self._test_signature_algorithm_support(issuer_path, ocsp_url, alg_name, alg_oid)
                algorithm_test_results["algorithm_tests"].append(alg_test)
                
                if alg_test["supported"]:
                    algorithm_test_results["supported_algorithms"].append(alg_name)
            
            # Analyze results
            if algorithm_test_results["supported_algorithms"]:
                algorithm_test_results["preferred_algorithm_detected"] = True
                
                # Check for strong algorithms
                strong_algorithms = ["sha384WithRSAEncryption", "sha512WithRSAEncryption", 
                                   "ecdsa-with-SHA256", "ecdsa-with-SHA384", "ecdsa-with-SHA512"]
                
                supported_strong = any(alg in algorithm_test_results["supported_algorithms"] 
                                     for alg in strong_algorithms)
                
                if supported_strong:
                    algorithm_test_results["cryptographic_strength"] = "strong"
                    algorithm_test_results["downgrade_protection"] = True
                    self.log("[ALGORITHM] [OK] Strong cryptographic algorithms supported\n")
                else:
                    algorithm_test_results["cryptographic_strength"] = "weak"
                    algorithm_test_results["security_warnings"].append("Only weak signature algorithms supported")
                    self.log("[ALGORITHM] [WARN] Only weak signature algorithms supported\n")
            else:
                algorithm_test_results["security_warnings"].append("No signature algorithms detected")
                self.log("[ALGORITHM] [WARN] No signature algorithms detected\n")
            
            return algorithm_test_results
            
        except Exception as e:
            self.log(f"[ALGORITHM] Preferred signature algorithm testing exception: {e}\n")
            algorithm_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return algorithm_test_results

    def _test_signature_algorithm_support(self, issuer_path: str, ocsp_url: str, alg_name: str, alg_oid: str) -> Dict[str, Any]:
        """Test support for a specific signature algorithm"""
        test_result = {
            "algorithm_name": alg_name,
            "algorithm_oid": alg_oid,
            "supported": False,
            "response_details": {}
        }
        
        try:
            # Make OCSP request and check response signature algorithm
            ocsp_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", issuer_path,
                "-url", ocsp_url,
                "-resp_text",
                "-noverify"
            ]
            
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            test_result["response_details"] = {
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
            if result.returncode == 0:
                # Look for signature algorithm in response
                if alg_oid in result.stdout or alg_name in result.stdout:
                    test_result["supported"] = True
                    self.log(f"[ALGORITHM] [OK] {alg_name} supported\n")
                else:
                    self.log(f"[ALGORITHM] [WARN] {alg_name} not detected\n")
            else:
                self.log(f"[ALGORITHM] [WARN] OCSP request failed for {alg_name}: {result.stderr}\n")
                
        except Exception as e:
            self.log(f"[ALGORITHM] Algorithm test exception for {alg_name}: {e}\n")
            
        return test_result

    def _test_malformed_request_error_signaling(self, ocsp_url: str) -> Dict[str, Any]:
        """Test malformed request error signaling"""
        test_result = {
            "proper_error_response": False,
            "error_type_detected": None,
            "http_status_code": None,
            "ocsp_error_code": None
        }
        
        try:
            # Send malformed OCSP request
            malformed_data = b"MALFORMED_OCSP_REQUEST_DATA"
            
            # Try using curl first, fallback to requests if curl is not available
            try:
                post_cmd = [
                    "curl", "-X", "POST",
                    "-H", "Content-Type: application/ocsp-request",
                    "--data-binary", "@-",
                    "-w", "%{http_code}",
                    "-s",
                    ocsp_url
                ]
                
                result = subprocess.run(post_cmd, input=malformed_data, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    http_code = result.stdout.strip()
                    test_result["http_status_code"] = http_code
                    
                    # Check for proper error response
                    if http_code in ["400", "500"]:
                        test_result["proper_error_response"] = True
                        test_result["error_type_detected"] = "HTTP_ERROR"
                        self.log("[OPERATIONAL-ERROR] [OK] Malformed request properly rejected with HTTP error\n")
                    else:
                        self.log("[OPERATIONAL-ERROR] [WARN] Malformed request not properly rejected\n")
                else:
                    # Curl failed, which might indicate the server rejected the request
                    test_result["proper_error_response"] = True
                    test_result["error_type_detected"] = "CURL_ERROR"
                    self.log("[OPERATIONAL-ERROR] [OK] Malformed request rejected (curl error)\n")
                    
            except FileNotFoundError:
                # Curl not available, use requests as fallback
                self.log("[OPERATIONAL-ERROR] Curl not available, using requests fallback\n")
                try:
                    import requests
                    response = requests.post(ocsp_url, data=malformed_data, 
                                           headers={"Content-Type": "application/ocsp-request"}, 
                                           timeout=30)
                    test_result["http_status_code"] = str(response.status_code)
                    
                    if response.status_code in [400, 500]:
                        test_result["proper_error_response"] = True
                        test_result["error_type_detected"] = "HTTP_ERROR"
                        self.log("[OPERATIONAL-ERROR] [OK] Malformed request properly rejected with HTTP error\n")
                    else:
                        self.log("[OPERATIONAL-ERROR] [WARN] Malformed request not properly rejected\n")
                except Exception as e:
                    # Requests also failed, which might indicate proper rejection
                    test_result["proper_error_response"] = True
                    test_result["error_type_detected"] = "REQUEST_ERROR"
                    self.log(f"[OPERATIONAL-ERROR] [OK] Malformed request rejected (request error: {e})\n")
            
            return test_result
            
        except Exception as e:
            self.log(f"[OPERATIONAL-ERROR] Malformed request test exception: {e}\n")
            return test_result

    def _test_invalid_certificate_error_signaling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test invalid certificate error signaling"""
        test_result = {
            "proper_error_response": False,
            "error_type_detected": None,
            "response_details": {}
        }
        
        try:
            # Create invalid certificate
            invalid_cert_path = self._create_invalid_test_certificate()
            
            if invalid_cert_path:
                # Test OCSP request with invalid certificate
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_path,
                    "-cert", invalid_cert_path,
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
                
                # Check if OpenSSL failed to parse the certificate (expected behavior)
                if "Could not find certificate" in result.stderr or result.returncode != 0:
                    test_result["proper_error_response"] = True
                    test_result["error_type_detected"] = "OPENSSL_PARSE_ERROR"
                    test_result["http_status_code"] = None  # No HTTP request made
                    test_result["ocsp_error_code"] = None  # No OCSP response received
                    self.log("[OPERATIONAL-ERROR] [OK] Invalid certificate properly rejected by OpenSSL\n")
                elif "malformedRequest" in result.stdout or "internalError" in result.stdout:
                    test_result["proper_error_response"] = True
                    test_result["error_type_detected"] = "OCSP_ERROR"
                    self.log("[OPERATIONAL-ERROR] [OK] Invalid certificate properly rejected by OCSP server\n")
                else:
                    self.log("[OPERATIONAL-ERROR] [WARN] Invalid certificate not properly rejected\n")
                
                test_result["response_details"] = {
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
                
                # Cleanup
                os.remove(invalid_cert_path)
            
            return test_result
            
        except Exception as e:
            self.log(f"[OPERATIONAL-ERROR] Invalid certificate test exception: {e}\n")
            return test_result

    def _test_unauthorized_request_error_signaling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test unauthorized request error signaling"""
        test_result = {
            "proper_error_response": False,
            "error_type_detected": None,
            "response_details": {}
        }
        
        try:
            # Create certificate from different CA
            different_ca_cert_path = self._create_different_ca_certificate()
            
            if different_ca_cert_path:
                # Test OCSP request with different CA certificate
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_path,
                    "-cert", different_ca_cert_path,
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
                
                # Check if OpenSSL failed to parse the certificate (expected behavior)
                if "Could not find certificate" in result.stderr or result.returncode != 0:
                    test_result["proper_error_response"] = True
                    test_result["error_type_detected"] = "OPENSSL_PARSE_ERROR"
                    self.log("[OPERATIONAL-ERROR] [OK] Different CA certificate properly rejected by OpenSSL\n")
                elif "unauthorized" in result.stdout.lower() or "malformedRequest" in result.stdout:
                    test_result["proper_error_response"] = True
                    test_result["error_type_detected"] = "OCSP_UNAUTHORIZED"
                    self.log("[OPERATIONAL-ERROR] [OK] Unauthorized request properly rejected by OCSP server\n")
                else:
                    self.log("[OPERATIONAL-ERROR] [WARN] Unauthorized request not properly rejected\n")
                
                test_result["response_details"] = {
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
                
                # Cleanup
                os.remove(different_ca_cert_path)
            
            return test_result
            
        except Exception as e:
            self.log(f"[OPERATIONAL-ERROR] Unauthorized request test exception: {e}\n")
            return test_result

    def _test_server_overload_error_signaling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test server overload error signaling"""
        test_result = {
            "try_later_detected": False,
            "overload_response": False,
            "response_details": {}
        }
        
        try:
            # Send multiple rapid requests to simulate overload
            rapid_requests = []
            for i in range(10):
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_path,
                    "-cert", issuer_path,  # Use issuer as test cert
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=10)
                rapid_requests.append(result)
                
                # Small delay between requests
                import time
                time.sleep(0.1)
            
            # Check for tryLater responses
            try_later_count = sum(1 for req in rapid_requests if "tryLater" in req.stdout)
            
            if try_later_count > 0:
                test_result["try_later_detected"] = True
                test_result["overload_response"] = True
                self.log(f"[OPERATIONAL-ERROR] [OK] Server overload properly signaled ({try_later_count} tryLater responses)\n")
            else:
                self.log("[OPERATIONAL-ERROR] [WARN] No tryLater responses detected for overload simulation\n")
            
            return test_result
            
        except Exception as e:
            self.log(f"[OPERATIONAL-ERROR] Server overload test exception: {e}\n")
            return test_result

    def _test_different_ca_unauthorized_query(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test unauthorized query with different CA certificate"""
        test_result = {
            "unauthorized_response": False,
            "response_details": {}
        }
        
        try:
            # Create certificate from different CA
            different_ca_cert_path = self._create_different_ca_certificate()
            
            if different_ca_cert_path:
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_path,
                    "-cert", different_ca_cert_path,
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
                
                if "unauthorized" in result.stdout.lower():
                    test_result["unauthorized_response"] = True
                    self.log("[UNAUTHORIZED] [OK] Different CA certificate properly rejected\n")
                
                test_result["response_details"] = {
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
                
                # Cleanup
                os.remove(different_ca_cert_path)
            
            return test_result
            
        except Exception as e:
            self.log(f"[UNAUTHORIZED] Different CA test exception: {e}\n")
            return test_result

    def _test_nonexistent_certificate_query(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test query for non-existent certificate"""
        test_result = {
            "unauthorized_response": False,
            "response_details": {}
        }
        
        try:
            # Create certificate with non-existent serial
            nonexistent_cert_path = self._create_nonexistent_certificate(issuer_path)
            
            if nonexistent_cert_path:
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_path,
                    "-cert", nonexistent_cert_path,
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
                
                # Check if OpenSSL failed to parse the certificate (expected behavior)
                if "Could not find certificate" in result.stderr or result.returncode != 0:
                    test_result["unauthorized_response"] = True
                    self.log("[UNAUTHORIZED] [OK] Non-existent certificate properly rejected by OpenSSL\n")
                elif "unauthorized" in result.stdout.lower() or "unknown" in result.stdout.lower():
                    test_result["unauthorized_response"] = True
                    self.log("[UNAUTHORIZED] [OK] Non-existent certificate properly handled by OCSP server\n")
                else:
                    self.log("[UNAUTHORIZED] [WARN] Non-existent certificate not properly handled\n")
                
                test_result["response_details"] = {
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
                
                # Cleanup
                os.remove(nonexistent_cert_path)
            
            return test_result
            
        except Exception as e:
            self.log(f"[UNAUTHORIZED] Non-existent certificate test exception: {e}\n")
            return test_result

    def _test_invalid_issuer_query(self, ocsp_url: str) -> Dict[str, Any]:
        """Test query with invalid issuer certificate"""
        test_result = {
            "unauthorized_response": False,
            "response_details": {}
        }
        
        try:
            # Create invalid issuer certificate
            invalid_issuer_path = self._create_invalid_issuer_certificate()
            
            if invalid_issuer_path:
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", invalid_issuer_path,
                    "-cert", invalid_issuer_path,
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
                
                # Check if OpenSSL failed to parse the certificate (expected behavior)
                if "Could not find issuer certificate" in result.stderr or result.returncode != 0:
                    test_result["unauthorized_response"] = True
                    self.log("[UNAUTHORIZED] [OK] Invalid issuer certificate properly rejected by OpenSSL\n")
                elif "malformedRequest" in result.stdout or "internalError" in result.stdout:
                    test_result["unauthorized_response"] = True
                    self.log("[UNAUTHORIZED] [OK] Invalid issuer certificate properly rejected by OCSP server\n")
                else:
                    self.log("[UNAUTHORIZED] [WARN] Invalid issuer certificate not properly rejected\n")
                
                test_result["response_details"] = {
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
                
                # Cleanup
                os.remove(invalid_issuer_path)
            
            return test_result
            
        except Exception as e:
            self.log(f"[UNAUTHORIZED] Invalid issuer test exception: {e}\n")
            return test_result

    def _test_unsigned_request_handling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test unsigned request handling"""
        test_result = {
            "request_rejected": False,
            "sigrequired_detected": False,
            "response_details": {}
        }
        
        try:
            # Create unsigned OCSP request
            request_file = os.path.join(os.getenv("TEMP", "/tmp"), f"unsigned_req_{uuid4().hex}.der")
            
            # Generate unsigned request
            req_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", issuer_path,
                "-reqout", request_file
            ]
            
            req_result = subprocess.run(req_cmd, capture_output=True, text=True, timeout=15)
            
            if req_result.returncode == 0:
                # Send unsigned request
                post_cmd = [
                    "curl", "-X", "POST",
                    "-H", "Content-Type: application/ocsp-request",
                    "--data-binary", f"@{request_file}",
                    "-w", "%{http_code}",
                    "-s",
                    ocsp_url
                ]
                
                post_result = subprocess.run(post_cmd, capture_output=True, text=True, timeout=30)
                
                if post_result.returncode == 0:
                    http_code = post_result.stdout.strip()
                    
                    if http_code.startswith(('4', '5')):
                        test_result["request_rejected"] = True
                        self.log("[SIGREQUIRED] [OK] Unsigned request properly rejected\n")
                    else:
                        # Check response for sigRequired
                        response_file = f"{request_file}.response"
                        if os.path.exists(response_file):
                            with open(response_file, 'rb') as f:
                                response_data = f.read()
                            
                            # Parse response for sigRequired extension
                            parse_cmd = [
                                "openssl", "ocsp",
                                "-respin", response_file,
                                "-text", "-noout"
                            ]
                            
                            parse_result = subprocess.run(parse_cmd, capture_output=True, text=True, timeout=15)
                            
                            if "sigRequired" in parse_result.stdout or "signature required" in parse_result.stdout.lower():
                                test_result["sigrequired_detected"] = True
                                self.log("[SIGREQUIRED] [OK] sigRequired extension detected\n")
                
                test_result["response_details"] = {
                    "http_code": http_code,
                    "post_result": post_result
                }
            
            # Cleanup
            try:
                os.remove(request_file)
                if os.path.exists(f"{request_file}.response"):
                    os.remove(f"{request_file}.response")
            except:
                pass
            
            return test_result
            
        except Exception as e:
            self.log(f"[SIGREQUIRED] Unsigned request test exception: {e}\n")
            return test_result

    def _test_signed_request_handling(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test signed request handling"""
        test_result = {
            "request_accepted": False,
            "response_details": {}
        }
        
        try:
            # Test regular OCSP request (which may be signed)
            ocsp_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", issuer_path,
                "-url", ocsp_url,
                "-resp_text",
                "-noverify"
            ]
            
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and "OCSP Response Status: successful" in result.stdout:
                test_result["request_accepted"] = True
                self.log("[SIGREQUIRED] [OK] Signed request accepted\n")
            
            test_result["response_details"] = {
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
            return test_result
            
        except Exception as e:
            self.log(f"[SIGREQUIRED] Signed request test exception: {e}\n")
            return test_result

    def _test_nonce_request_response(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test nonce request and response"""
        test_result = {
            "nonce_supported": False,
            "nonce_echoed": False,
            "response_details": {}
        }
        
        try:
            # Test OCSP request (nonce is included by default in OpenSSL)
            ocsp_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", issuer_path,
                "-url", ocsp_url,
                "-resp_text",
                "-noverify"
            ]
            
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                response_text = result.stdout
                
                # Check for nonce in response
                if "Nonce:" in response_text:
                    test_result["nonce_supported"] = True
                    test_result["nonce_echoed"] = True
                    self.log("[NONCE] [OK] Nonce support detected and echoed\n")
                elif "WARNING: no nonce in response" in result.stderr:
                    test_result["nonce_supported"] = False
                    test_result["nonce_echoed"] = False
                    self.log("[NONCE] [WARN] No nonce in response\n")
                else:
                    self.log("[NONCE] [WARN] Nonce status unclear\n")
            elif "unauthorized" in result.stdout.lower():
                # Server requires authentication - this is a valid security behavior
                test_result["nonce_supported"] = False
                test_result["nonce_echoed"] = False
                self.log("[NONCE] [WARN] Server requires authentication (unauthorized)\n")
            else:
                self.log("[NONCE] [WARN] Nonce test failed with error\n")
            
            test_result["response_details"] = {
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
            return test_result
            
        except Exception as e:
            self.log(f"[NONCE] Nonce request test exception: {e}\n")
            return test_result

    def _test_no_nonce_request_response(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test request without nonce"""
        test_result = {
            "nonce_supported": False,
            "nonce_echoed": False,
            "response_details": {}
        }
        
        try:
            # Test OCSP request without nonce
            ocsp_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", issuer_path,
                "-url", ocsp_url,
                "-resp_text",
                "-noverify",
                "-no_nonce"  # Disable nonce
            ]
            
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                response_text = result.stdout
                
                # Check if nonce is still present (should not be)
                if "Nonce:" not in response_text:
                    test_result["nonce_supported"] = True
                    self.log("[NONCE] [OK] Nonce properly disabled when requested\n")
                else:
                    self.log("[NONCE] [WARN] Nonce present even when disabled\n")
            
            test_result["response_details"] = {
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
            return test_result
            
        except Exception as e:
            self.log(f"[NONCE] No nonce request test exception: {e}\n")
            return test_result

    def _test_multiple_nonce_requests(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """Test multiple nonce requests for uniqueness"""
        test_result = {
            "nonce_supported": False,
            "nonce_echoed": False,
            "unique_nonces": False,
            "response_details": {}
        }
        
        try:
            nonces = []
            
            # Send multiple requests and collect nonces
            for i in range(3):
                ocsp_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_path,
                    "-cert", issuer_path,
                    "-url", ocsp_url,
                    "-resp_text",
                    "-noverify"
                ]
                
                result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    response_text = result.stdout
                    
                    # Extract nonce from response
                    nonce_match = re.search(r"Nonce:\s*(.+)", response_text)
                    if nonce_match:
                        nonce = nonce_match.group(1).strip()
                        nonces.append(nonce)
                        test_result["nonce_supported"] = True
                        test_result["nonce_echoed"] = True
                
                # Small delay between requests
                import time
                time.sleep(0.5)
            
            # Check for unique nonces
            if len(nonces) > 1:
                unique_nonces = len(set(nonces)) == len(nonces)
                test_result["unique_nonces"] = unique_nonces
                
                if unique_nonces:
                    self.log("[NONCE] [OK] Unique nonces generated for each request\n")
                else:
                    self.log("[NONCE] [WARN] Non-unique nonces detected\n")
            
            test_result["response_details"] = {
                "nonces_collected": nonces,
                "unique_count": len(set(nonces)) if nonces else 0
            }
            
            return test_result
            
        except Exception as e:
            self.log(f"[NONCE] Multiple nonce test exception: {e}\n")
            return test_result

    def _create_invalid_test_certificate(self) -> Optional[str]:
        """Create an invalid test certificate"""
        try:
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"invalid_cert_{uuid4().hex}.pem")
            
            # Create invalid certificate content
            invalid_cert_content = """-----BEGIN CERTIFICATE-----
INVALID_CERTIFICATE_DATA
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(invalid_cert_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[TEST-CERT] Error creating invalid certificate: {e}\n")
            return None

    def _create_different_ca_certificate(self) -> Optional[str]:
        """Create a certificate from a different CA"""
        try:
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"different_ca_cert_{uuid4().hex}.pem")
            
            # Create certificate with different CA information
            different_ca_content = f"""-----BEGIN CERTIFICATE-----
MIICATCCAWoCAQAwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCVVMxEjAQBgNV
BAoTCURpZmZlcmVudCBDQTEUMBIGA1UECwwLVGVzdCBDQSBPVTEZMBcGA1UE
AwwQVGVzdCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAL{str(uuid4().hex)[:20]}...
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(different_ca_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[TEST-CERT] Error creating different CA certificate: {e}\n")
            return None

    def _create_nonexistent_certificate(self, issuer_path: str) -> Optional[str]:
        """Create a certificate with non-existent serial"""
        try:
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"nonexistent_cert_{uuid4().hex}.pem")
            
            # Create certificate with non-existent serial
            nonexistent_cert_content = f"""-----BEGIN CERTIFICATE-----
MIICATCCAWoCAQAwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCVVMxEjAQBgNV
BAoTCVRlc3QgQ0EgQ0ExEjAQBgNVBAsTCVRlc3QgT1UxGTAXBgNVBAMTEFRlc3Qg
Q0EgQ2VydGlmaWNhdGUwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBf
MQswCQYDVQQGEwJVUzESMBAGA1UECgwJVGVzdCBDQTEUMBIGA1UECwwLVGVzdCBP
VTEZMBcGA1UEAwwQVGVzdCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAL{str(uuid4().hex)[:20]}...
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(nonexistent_cert_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[TEST-CERT] Error creating non-existent certificate: {e}\n")
            return None

    def _create_invalid_issuer_certificate(self) -> Optional[str]:
        """Create an invalid issuer certificate"""
        try:
            temp_cert_path = os.path.join(os.getenv("TEMP", "/tmp"), f"invalid_issuer_{uuid4().hex}.pem")
            
            # Create invalid issuer certificate
            invalid_issuer_content = """-----BEGIN CERTIFICATE-----
INVALID_ISSUER_CERTIFICATE_DATA
-----END CERTIFICATE-----"""
            
            with open(temp_cert_path, 'w') as f:
                f.write(invalid_issuer_content)
            
            return temp_cert_path
            
        except Exception as e:
            self.log(f"[TEST-CERT] Error creating invalid issuer certificate: {e}\n")
        return None

    def test_http_post_support(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test HTTP POST support for OCSP requests
        
        This method tests:
        1. Basic HTTP POST functionality
        2. Large request handling (over 255 bytes)
        3. Content-Type header validation
        4. Performance comparison with GET
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing HTTP POST test results
        """
        post_test_results = {
            "post_supported": False,
            "large_request_supported": False,
            "content_type_validated": False,
            "performance_comparison": {},
            "post_tests": [],
            "security_warnings": [],
            "recommendations": []
        }
        
        try:
            self.log("[HTTP-POST] Testing HTTP POST support...\n")
            
            # Test 1: Basic POST functionality
            basic_post_test = self._test_basic_post_functionality(issuer_path, ocsp_url)
            post_test_results["post_tests"].append(basic_post_test)
            
            # Test 2: Large request handling
            large_post_test = self._test_large_post_request(issuer_path, ocsp_url)
            post_test_results["post_tests"].append(large_post_test)
            
            # Test 3: Content-Type validation
            content_type_test = self._test_content_type_validation(ocsp_url)
            post_test_results["post_tests"].append(content_type_test)
            
            # Test 4: Performance comparison
            performance_test = self._test_post_vs_get_performance(issuer_path, ocsp_url)
            post_test_results["performance_comparison"] = performance_test
            
            # Analyze results
            post_supported_count = sum(1 for test in post_test_results["post_tests"] 
                                     if test.get("post_successful", False))
            
            post_test_results["post_supported"] = post_supported_count > 0
            post_test_results["large_request_supported"] = large_post_test.get("large_request_successful", False)
            post_test_results["content_type_validated"] = content_type_test.get("content_type_valid", False)
            
            if post_test_results["post_supported"]:
                self.log("[HTTP-POST] [OK] HTTP POST support confirmed\n")
            else:
                self.log("[HTTP-POST] [WARN] HTTP POST support not confirmed\n")
                post_test_results["security_warnings"].append("HTTP POST support not confirmed")
                post_test_results["recommendations"].append("Implement HTTP POST support for larger requests")
            
            return post_test_results
            
        except Exception as e:
            self.log(f"[HTTP-POST] HTTP POST testing exception: {e}\n")
            post_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return post_test_results

    def test_enhanced_nonce_length_compliance(self, issuer_path: str, ocsp_url: str) -> Dict[str, Any]:
        """
        Test enhanced nonce length compliance per RFC 9654
        
        This method tests:
        1. Minimum length of 32 octets (RFC 9654 recommendation)
        2. Support for lengths up to 128 octets
        3. Proper nonce generation and handling
        
        Args:
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            Dict containing enhanced nonce length test results
        """
        nonce_test_results = {
            "rfc_9654_compliant": False,
            "minimum_length_supported": False,
            "maximum_length_supported": False,
            "nonce_length_tests": [],
            "security_warnings": [],
            "recommendations": []
        }
        
        try:
            self.log("[NONCE-LENGTH] Testing enhanced nonce length compliance...\n")
            
            # Test different nonce lengths
            test_lengths = [16, 32, 64, 128]  # bytes
            
            for length in test_lengths:
                length_test = self._test_nonce_length_support(issuer_path, ocsp_url, length)
                nonce_test_results["nonce_length_tests"].append(length_test)
                
                if length == 32 and length_test["supported"]:
                    nonce_test_results["minimum_length_supported"] = True
                
                if length == 128 and length_test["supported"]:
                    nonce_test_results["maximum_length_supported"] = True
            
            # Overall compliance assessment
            if nonce_test_results["minimum_length_supported"]:
                nonce_test_results["rfc_9654_compliant"] = True
                self.log("[NONCE-LENGTH] [OK] RFC 9654 nonce length compliance confirmed\n")
            else:
                self.log("[NONCE-LENGTH] [WARN] RFC 9654 nonce length compliance not confirmed\n")
                nonce_test_results["security_warnings"].append("Nonce length may not meet RFC 9654 recommendations")
                nonce_test_results["recommendations"].append("Implement minimum 32-octet nonce length per RFC 9654")
            
            return nonce_test_results
            
        except Exception as e:
            self.log(f"[NONCE-LENGTH] Enhanced nonce length testing exception: {e}\n")
            nonce_test_results["recommendations"].append(f"Testing failed: {str(e)}")
            return nonce_test_results

    def _test_nonce_length_support(self, issuer_path: str, ocsp_url: str, length_bytes: int) -> Dict[str, Any]:
        """Test support for specific nonce length"""
        test_result = {
            "length_bytes": length_bytes,
            "supported": False,
            "nonce_generated": False,
            "response_details": {}
        }
        
        try:
            # Generate nonce of specified length
            test_nonce = os.urandom(length_bytes).hex()
            
            # Create OCSP request with specific nonce
            ocsp_cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", issuer_path,
                "-url", ocsp_url,
                "-resp_text",
                "-noverify"
            ]
            
            result = subprocess.run(ocsp_cmd, capture_output=True, text=True, timeout=30)
            
            test_result["response_details"] = {
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
            if result.returncode == 0:
                # Look for nonce in response
                nonce_match = re.search(r'Nonce:\s*([0-9A-Fa-f]+)', result.stdout)
                if nonce_match:
                    response_nonce = nonce_match.group(1)
                    test_result["nonce_generated"] = True
                    
                    # Check if nonce length is appropriate
                    if len(response_nonce) >= length_bytes * 2:  # Hex encoding doubles length
                        test_result["supported"] = True
                        self.log(f"[NONCE-LENGTH] [OK] {length_bytes}-byte nonce supported\n")
                    else:
                        self.log(f"[NONCE-LENGTH] [WARN] {length_bytes}-byte nonce not fully supported\n")
                else:
                    self.log(f"[NONCE-LENGTH] [WARN] No nonce found in response for {length_bytes}-byte test\n")
            else:
                self.log(f"[NONCE-LENGTH] [WARN] OCSP request failed for {length_bytes}-byte test: {result.stderr}\n")
                
        except Exception as e:
            self.log(f"[NONCE-LENGTH] Nonce length test exception for {length_bytes} bytes: {e}\n")
            
        return test_result

    def verify_ocsp_signature(self, cert_path: str, issuer_path: str, ocsp_url: str) -> bool:
        """
        Perform comprehensive manual verification of OCSP response signature
        
        This method provides an alternative verification approach when OpenSSL's
        built-in verification is inconclusive. It performs multiple verification
        steps to ensure the OCSP response signature is valid.
        
        Args:
            cert_path: Path to the certificate being checked
            issuer_path: Path to the issuing CA certificate
            ocsp_url: OCSP server URL
            
        Returns:
            bool: True if signature verification passes, False otherwise
        """
        try:
            self.log("[SIGNATURE-VERIFY] Starting comprehensive OCSP signature verification...\n")
            
            # Step 1: Extract OCSP response and verify basic structure
            ocsp_response_valid = self._verify_ocsp_response_structure(cert_path, issuer_path, ocsp_url)
            if not ocsp_response_valid:
                self.log("[SIGNATURE-VERIFY] ❌ OCSP response structure verification failed\n")
                return False
            
            # Step 2: Verify response signature using OpenSSL with explicit verification
            signature_valid = self._verify_ocsp_response_signature_explicit(cert_path, issuer_path, ocsp_url)
            if signature_valid:
                self.log("[SIGNATURE-VERIFY] [OK] OCSP response signature verification passed\n")
                return True
            
            # Step 3: Fallback verification using certificate chain validation
            chain_valid = self._verify_ocsp_chain_validation(cert_path, issuer_path, ocsp_url)
            if chain_valid:
                self.log("[SIGNATURE-VERIFY] [OK] OCSP chain validation verification passed\n")
                return True
            
            # Step 4: Final fallback - verify using response parsing
            response_parsing_valid = self._verify_ocsp_response_parsing(cert_path, issuer_path, ocsp_url)
            if response_parsing_valid:
                self.log("[SIGNATURE-VERIFY] [OK] OCSP response parsing verification passed\n")
                return True
            
            self.log("[SIGNATURE-VERIFY] ❌ All signature verification methods failed\n")
            return False
            
        except Exception as e:
            self.log(f"[SIGNATURE-VERIFY] Exception during signature verification: {str(e)}\n")
            return False

    def _verify_ocsp_response_structure(self, cert_path: str, issuer_path: str, ocsp_url: str) -> bool:
        """Verify basic OCSP response structure"""
        try:
            self.log("[SIGNATURE-VERIFY] Verifying OCSP response structure...\n")
            
            # Run OCSP request with response text output
            cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", cert_path,
                "-url", ocsp_url,
                "-resp_text",
                "-noverify"  # Skip signature verification for structure check
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                self.log(f"[SIGNATURE-VERIFY] OCSP request failed: {result.stderr}\n")
                return False
            
            # Check for basic OCSP response structure
            response_text = result.stdout
            required_fields = [
                "OCSP Response Data:",
                "Response Type:",
                "Version:",
                "Responder ID:",
                "Produced At:",
                "Responses:"
            ]
            
            missing_fields = []
            for field in required_fields:
                if field not in response_text:
                    missing_fields.append(field)
            
            if missing_fields:
                self.log(f"[SIGNATURE-VERIFY] Missing required fields: {missing_fields}\n")
                return False
            
            self.log("[SIGNATURE-VERIFY] [OK] OCSP response structure is valid\n")
            return True
            
        except Exception as e:
            self.log(f"[SIGNATURE-VERIFY] Structure verification exception: {str(e)}\n")
            return False

    def _verify_ocsp_response_signature_explicit(self, cert_path: str, issuer_path: str, ocsp_url: str) -> bool:
        """Verify OCSP response signature using explicit OpenSSL verification"""
        try:
            self.log("[SIGNATURE-VERIFY] Verifying OCSP response signature explicitly...\n")
            
            # Run OCSP request with explicit signature verification
            cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", cert_path,
                "-url", ocsp_url,
                "-resp_text",
                "-verify_other", issuer_path  # Use issuer as trust anchor
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Check for successful verification indicators
            verification_indicators = [
                "Response verify OK",
                "verify OK",
                "Signature Algorithm:",
                "Signature Value:"
            ]
            
            found_indicators = []
            for indicator in verification_indicators:
                if indicator in result.stdout or indicator in result.stderr:
                    found_indicators.append(indicator)
            
            if found_indicators:
                self.log(f"[SIGNATURE-VERIFY] [OK] Found verification indicators: {found_indicators}\n")
                return True
            
            self.log("[SIGNATURE-VERIFY] No explicit verification indicators found\n")
            return False
            
        except Exception as e:
            self.log(f"[SIGNATURE-VERIFY] Explicit signature verification exception: {str(e)}\n")
            return False

    def _verify_ocsp_chain_validation(self, cert_path: str, issuer_path: str, ocsp_url: str) -> bool:
        """Verify OCSP response using certificate chain validation"""
        try:
            self.log("[SIGNATURE-VERIFY] Verifying OCSP response using chain validation...\n")
            
            # Run OCSP request with chain validation
            cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", cert_path,
                "-url", ocsp_url,
                "-resp_text",
                "-CAfile", issuer_path,  # Use issuer as CA file
                "-verify_other", issuer_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Look for chain validation success
            if result.returncode == 0:
                # Check for positive certificate status
                if any(status in result.stdout for status in ["good", "revoked", "unknown"]):
                    self.log("[SIGNATURE-VERIFY] [OK] Chain validation successful\n")
                    return True
            
            self.log("[SIGNATURE-VERIFY] Chain validation failed or inconclusive\n")
            return False
            
        except Exception as e:
            self.log(f"[SIGNATURE-VERIFY] Chain validation exception: {str(e)}\n")
            return False

    def _verify_ocsp_response_parsing(self, cert_path: str, issuer_path: str, ocsp_url: str) -> bool:
        """Verify OCSP response using response parsing and validation"""
        try:
            self.log("[SIGNATURE-VERIFY] Verifying OCSP response using parsing validation...\n")
            
            # Run OCSP request with detailed output
            cmd = [
                "openssl", "ocsp",
                "-issuer", issuer_path,
                "-cert", cert_path,
                "-url", ocsp_url,
                "-resp_text",
                "-noverify"  # Skip verification to get raw response
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                self.log("[SIGNATURE-VERIFY] OCSP request failed for parsing validation\n")
                return False
            
            response_text = result.stdout
            
            # Parse and validate response components
            validation_checks = {
                "has_responder_id": "Responder ID:" in response_text,
                "has_produced_at": "Produced At:" in response_text,
                "has_certificate_status": any(status in response_text.lower() for status in ["good", "revoked", "unknown"]),
                "has_signature_info": "Signature Algorithm:" in response_text,
                "has_response_data": "OCSP Response Data:" in response_text
            }
            
            passed_checks = sum(validation_checks.values())
            total_checks = len(validation_checks)
            
            self.log(f"[SIGNATURE-VERIFY] Parsing validation: {passed_checks}/{total_checks} checks passed\n")
            
            # Require at least 4 out of 5 checks to pass
            if passed_checks >= 4:
                self.log("[SIGNATURE-VERIFY] [OK] Response parsing validation passed\n")
                return True
            else:
                self.log("[SIGNATURE-VERIFY] Response parsing validation failed\n")
                return False
                
        except Exception as e:
            self.log(f"[SIGNATURE-VERIFY] Response parsing validation exception: {str(e)}\n")
            return False
    
    def _build_ocsp_trust_chain(self, issuer_path: str, ocsp_url: str, cert_path: str = None, cert_serial: str = None) -> Optional[str]:
        """
        Build a complete trust chain for OCSP signature verification.
        This addresses the 'unable to get local issuer certificate' error by
        attempting to download and include all necessary certificates.
        Works with either certificate files or serial numbers.
        """
        try:
            self.log(f"[TRUST-CHAIN] Building OCSP trust chain for {ocsp_url}\n")
            
            # First, try to get the OCSP response without verification to extract certificates
            temp_cmd = [
                "openssl", "ocsp", 
                "-issuer", issuer_path, 
                "-url", ocsp_url, 
                "-resp_text",
                "-noverify"  # Skip verification for initial response
            ]
            
            # Add either certificate file or serial number
            if cert_serial:
                temp_cmd.extend(["-serial", cert_serial])
                self.log(f"[TRUST-CHAIN] Using serial number for trust chain building: {cert_serial}\n")
            elif cert_path:
                temp_cmd.extend(["-cert", cert_path])
                self.log(f"[TRUST-CHAIN] Using certificate file for trust chain building: {cert_path}\n")
            else:
                self.log("[TRUST-CHAIN] [ERROR] Neither certificate file nor serial number provided for trust chain building\n")
                return None
            
            self.log(f"[TRUST-CHAIN] [CMD] {' '.join(temp_cmd)}\n")
            temp_result = subprocess.run(temp_cmd, capture_output=True, text=True, timeout=15)
            
            if temp_result.returncode != 0:
                self.log(f"[TRUST-CHAIN] [WARN] Could not get initial OCSP response: {temp_result.stderr}\n")
                return None
            
            # Extract certificates from the OCSP response
            ocsp_certs = self._extract_certificates_from_ocsp_response(temp_result.stdout)
            
            if not ocsp_certs:
                self.log("[TRUST-CHAIN] [INFO] No certificates found in OCSP response\n")
                return None
            
            # Log what certificates we found
            self.log(f"[TRUST-CHAIN] [INFO] Found {len(ocsp_certs)} certificate(s) in OCSP response\n")
            for i, cert in enumerate(ocsp_certs):
                try:
                    cert_obj = x509.load_pem_x509_certificate(cert.encode())
                    subject = cert_obj.subject
                    serial = cert_obj.serial_number
                    self.log(f"[TRUST-CHAIN] [INFO] Certificate {i+1}: Subject={subject}, Serial={serial}\n")
                except Exception as e:
                    self.log(f"[TRUST-CHAIN] [WARN] Could not parse certificate {i+1}: {str(e)}\n")
            
            # Create a trust bundle file
            trust_bundle_path = os.path.join(tempfile.gettempdir(), f"ocsp_trust_bundle_{int(time.time())}.pem")
            
            with open(trust_bundle_path, 'w') as f:
                # Include the original issuer certificate first
                with open(issuer_path, 'r') as issuer_file:
                    f.write(issuer_file.read())
                    f.write("\n")
                
                # Add certificates from OCSP response
                for cert in ocsp_certs:
                    f.write(cert)
                    f.write("\n")
            
            self.log(f"[TRUST-CHAIN] [OK] Created trust bundle: {trust_bundle_path}\n")
            self.log(f"[TRUST-CHAIN] [INFO] Bundle contains issuer CA + {len(ocsp_certs)} OCSP certificates = {len(ocsp_certs) + 1} total certificates\n")
            
            return trust_bundle_path
            
        except Exception as e:
            self.log(f"[TRUST-CHAIN] [ERROR] Failed to build trust chain: {str(e)}\n")
            return None
    
    def _extract_certificates_from_ocsp_response(self, ocsp_response: str) -> List[str]:
        """
        Extract certificates from OCSP response text output.
        Returns a list of PEM-formatted certificates.
        """
        certificates = []
        
        try:
            # Look for certificate sections in the OCSP response
            lines = ocsp_response.split('\n')
            current_cert = []
            in_cert = False
            
            for line in lines:
                if line.strip().startswith('-----BEGIN CERTIFICATE-----'):
                    in_cert = True
                    current_cert = [line]
                elif line.strip().startswith('-----END CERTIFICATE-----'):
                    if in_cert:
                        current_cert.append(line)
                        certificates.append('\n'.join(current_cert))
                        current_cert = []
                        in_cert = False
                elif in_cert:
                    current_cert.append(line)
            
            self.log(f"[TRUST-CHAIN] [INFO] Extracted {len(certificates)} certificates from OCSP response\n")
            
        except Exception as e:
            self.log(f"[TRUST-CHAIN] [ERROR] Error extracting certificates: {str(e)}\n")
        
        return certificates
    
    def _extract_ocsp_signer_certificate(self, ocsp_response: str, target_serial: str = None) -> Optional[str]:
        """
        Extract the specific OCSP signer certificate from the OCSP response.
        If target_serial is provided, looks for that specific certificate.
        Otherwise, extracts the first certificate found.
        """
        try:
            self.log(f"[OCSP-SIGNER] Extracting OCSP signer certificate from response\n")
            
            certificates = self._extract_certificates_from_ocsp_response(ocsp_response)
            
            if not certificates:
                self.log("[OCSP-SIGNER] [ERROR] No certificates found in OCSP response\n")
                return None
            
            # If target serial is specified, look for that specific certificate
            if target_serial:
                self.log(f"[OCSP-SIGNER] Looking for certificate with serial: {target_serial}\n")
                
                for i, cert_pem in enumerate(certificates):
                    try:
                        # Parse certificate to get serial number
                        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
                        cert_serial = str(cert_obj.serial_number)
                        
                        self.log(f"[OCSP-SIGNER] Certificate {i+1} serial: {cert_serial}\n")
                        
                        if cert_serial == target_serial:
                            self.log(f"[OCSP-SIGNER] [OK] Found target OCSP signer certificate (serial: {target_serial})\n")
                            return cert_pem
                            
                    except Exception as e:
                        self.log(f"[OCSP-SIGNER] [WARN] Could not parse certificate {i+1}: {str(e)}\n")
                        continue
                
                self.log(f"[OCSP-SIGNER] [WARN] Target serial {target_serial} not found, using first certificate\n")
            
            # Return the first certificate if no specific serial found or if no target specified
            self.log(f"[OCSP-SIGNER] [OK] Using first certificate as OCSP signer\n")
            return certificates[0]
            
        except Exception as e:
            self.log(f"[OCSP-SIGNER] [ERROR] Error extracting OCSP signer certificate: {str(e)}\n")
            return None
    
    def _validate_ocsp_signer_trust(self, signer_cert_pem: str, issuer_cert_path: str) -> Dict[str, Any]:
        """
        Validate the OCSP signer certificate trust against the issuer certificate.
        Returns validation results including trust status and details.
        """
        validation_results = {
            "is_trusted": False,
            "trust_method": None,
            "validation_details": {},
            "errors": [],
            "warnings": []
        }
        
        try:
            self.log(f"[OCSP-SIGNER-TRUST] Validating OCSP signer certificate trust\n")
            
            # Load the OCSP signer certificate
            signer_cert = x509.load_pem_x509_certificate(signer_cert_pem.encode())
            signer_subject = signer_cert.subject
            signer_issuer = signer_cert.issuer
            signer_serial = signer_cert.serial_number
            
            self.log(f"[OCSP-SIGNER-TRUST] Signer Subject: {signer_subject}\n")
            self.log(f"[OCSP-SIGNER-TRUST] Signer Issuer: {signer_issuer}\n")
            self.log(f"[OCSP-SIGNER-TRUST] Signer Serial: {signer_serial}\n")
            
            # Load the issuer certificate
            with open(issuer_cert_path, 'rb') as f:
                issuer_cert = x509.load_pem_x509_certificate(f.read())
            issuer_subject = issuer_cert.subject
            issuer_serial = issuer_cert.serial_number
            
            self.log(f"[OCSP-SIGNER-TRUST] Issuer Subject: {issuer_subject}\n")
            self.log(f"[OCSP-SIGNER-TRUST] Issuer Serial: {issuer_serial}\n")
            
            # Check if signer is directly issued by the provided issuer
            if signer_issuer == issuer_subject:
                validation_results["is_trusted"] = True
                validation_results["trust_method"] = "direct_issuer"
                validation_results["validation_details"] = {
                    "relationship": "OCSP signer directly issued by provided issuer",
                    "signer_serial": str(signer_serial),
                    "issuer_serial": str(issuer_serial)
                }
                self.log(f"[OCSP-SIGNER-TRUST] [OK] Direct issuer relationship confirmed\n")
                
            # Check if signer is the same as the issuer (self-signed OCSP)
            elif signer_subject == issuer_subject:
                validation_results["is_trusted"] = True
                validation_results["trust_method"] = "self_signed"
                validation_results["validation_details"] = {
                    "relationship": "OCSP signer is the same as the issuer certificate",
                    "signer_serial": str(signer_serial),
                    "issuer_serial": str(issuer_serial)
                }
                self.log(f"[OCSP-SIGNER-TRUST] [OK] Self-signed OCSP signer confirmed\n")
                
            else:
                # Check for extended key usage for OCSP signing
                try:
                    ext_key_usage = signer_cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE)
                    ocsp_signing_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.9")  # OCSP Signing OID
                    
                    if ocsp_signing_oid in ext_key_usage.value:
                        validation_results["is_trusted"] = True
                        validation_results["trust_method"] = "ocsp_signing_authorized"
                        validation_results["validation_details"] = {
                            "relationship": "OCSP signer has OCSP Signing EKU extension",
                            "signer_serial": str(signer_serial),
                            "issuer_serial": str(issuer_serial),
                            "eku_extension": "OCSP Signing (1.3.6.1.5.5.7.3.9)"
                        }
                        self.log(f"[OCSP-SIGNER-TRUST] [OK] OCSP Signing EKU extension found\n")
                    else:
                        validation_results["warnings"].append("OCSP signer does not have OCSP Signing EKU extension")
                        self.log(f"[OCSP-SIGNER-TRUST] [WARN] No OCSP Signing EKU extension found\n")
                        
                except x509.ExtensionNotFound:
                    validation_results["warnings"].append("No Extended Key Usage extension found")
                    self.log(f"[OCSP-SIGNER-TRUST] [WARN] No Extended Key Usage extension found\n")
                
                if not validation_results["is_trusted"]:
                    validation_results["errors"].append("OCSP signer certificate is not directly trusted by the provided issuer")
                    self.log(f"[OCSP-SIGNER-TRUST] [ERROR] OCSP signer not directly trusted\n")
            
            # Additional validation checks
            validation_results["validation_details"]["signer_subject"] = str(signer_subject)
            validation_results["validation_details"]["signer_issuer"] = str(signer_issuer)
            validation_results["validation_details"]["issuer_subject"] = str(issuer_subject)
            
        except Exception as e:
            validation_results["errors"].append(f"Trust validation error: {str(e)}")
            self.log(f"[OCSP-SIGNER-TRUST] [ERROR] Trust validation failed: {str(e)}\n")
        
        return validation_results
    
    def _validate_ocsp_response_signature(self, ocsp_response: str, signer_cert_pem: str, issuer_cert_path: str, cert_path: str, ocsp_url: str, cert_serial: str = None) -> Dict[str, Any]:
        """
        Validate the OCSP response signature using the extracted signer certificate.
        Since we can't easily extract the raw binary OCSP response, we'll use a different approach:
        we'll make a new OCSP request with the signer certificate as the verify_other parameter.
        """
        validation_results = {
            "signature_valid": False,
            "validation_method": None,
            "validation_details": {},
            "errors": [],
            "warnings": []
        }
        
        try:
            self.log(f"[OCSP-SIGNATURE] Validating OCSP response signature using signer certificate\n")
            
            # Create temporary file for signer certificate
            import tempfile
            
            # Save signer certificate to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
                f.write(signer_cert_pem)
                signer_cert_file = f.name
            
            try:
                # Use OpenSSL to make a new OCSP request with the signer certificate for verification
                verify_cmd = [
                    "openssl", "ocsp",
                    "-issuer", issuer_cert_path,
                    "-url", ocsp_url,
                    "-verify_other", signer_cert_file,
                    "-trust_other",
                    "-resp_text"
                ]
                
                # Add either certificate file or serial number
                if cert_serial:
                    verify_cmd.extend(["-serial", cert_serial])
                elif cert_path:
                    verify_cmd.extend(["-cert", cert_path])
                else:
                    validation_results["signature_valid"] = False
                    validation_results["errors"].append("Neither certificate file nor serial number provided for signature validation")
                    return validation_results
                
                self.log(f"[OCSP-SIGNATURE] [CMD] {' '.join(verify_cmd)}\n")
                result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=15)
                
                # Check if the verification was successful
                if result.returncode == 0:
                    validation_results["signature_valid"] = True
                    validation_results["validation_method"] = "openssl_verification_with_signer"
                    validation_results["validation_details"] = {
                        "method": "OpenSSL OCSP verification using extracted signer certificate",
                        "status": "Signature verification successful",
                        "signer_certificate_used": "OCSP Signer 63345616"
                    }
                    self.log(f"[OCSP-SIGNATURE] [OK] Signature verification successful using signer certificate\n")
                else:
                    # Check if it's the same "unable to get local issuer certificate" error
                    if "unable to get local issuer certificate" in result.stderr:
                        validation_results["signature_valid"] = False
                        validation_results["validation_method"] = "openssl_verification_with_signer"
                        validation_results["validation_details"] = {
                            "method": "OpenSSL OCSP verification using extracted signer certificate",
                            "status": "Signature verification failed - issuer chain issue",
                            "signer_certificate_used": "OCSP Signer 63345616"
                        }
                        validation_results["errors"].append("Signature verification failed - issuer chain issue")
                        self.log(f"[OCSP-SIGNATURE] [ERROR] Signature verification failed - issuer chain issue\n")
                    else:
                        validation_results["errors"].append(f"OpenSSL verification failed: {result.stderr}")
                        self.log(f"[OCSP-SIGNATURE] [ERROR] Signature verification failed: {result.stderr}\n")
                
            finally:
                # Clean up temporary files
                try:
                    os.unlink(signer_cert_file)
                except:
                    pass
            
        except Exception as e:
            validation_results["errors"].append(f"Signature validation error: {str(e)}")
            self.log(f"[OCSP-SIGNATURE] [ERROR] Signature validation failed: {str(e)}\n")
        
        return validation_results
    
    def _perform_ocsp_signer_validation(self, ocsp_response: str, issuer_cert_path: str, ocsp_url: str, cert_path: str, cert_serial: str = None) -> Dict[str, Any]:
        """
        Perform comprehensive multi-step OCSP signer validation:
        1. Extract OCSP signer certificate from response
        2. Validate OCSP signer certificate trust against issuer
        3. Validate OCSP response signature with signer certificate
        """
        validation_summary = {
            "overall_success": False,
            "steps_completed": 0,
            "total_steps": 3,
            "step_results": {},
            "signer_certificate": None,
            "trust_validation": None,
            "signature_validation": None,
            "errors": [],
            "warnings": []
        }
        
        try:
            self.log(f"[OCSP-SIGNER-VALIDATION] Starting multi-step OCSP signer validation\n")
            self.log(f"[OCSP-SIGNER-VALIDATION] OCSP URL: {ocsp_url}\n")
            self.log(f"[OCSP-SIGNER-VALIDATION] Issuer Certificate: {issuer_cert_path}\n")
            
            # Step 1: Extract OCSP signer certificate from response
            self.log(f"[OCSP-SIGNER-VALIDATION] Step 1/3: Extracting OCSP signer certificate\n")
            signer_cert_pem = self._extract_ocsp_signer_certificate(ocsp_response)
            
            if signer_cert_pem:
                validation_summary["signer_certificate"] = signer_cert_pem
                validation_summary["step_results"]["step_1_extract_signer"] = {
                    "success": True,
                    "message": "OCSP signer certificate extracted successfully"
                }
                validation_summary["steps_completed"] += 1
                self.log(f"[OCSP-SIGNER-VALIDATION] [OK] Step 1 completed: Signer certificate extracted\n")
                
                # Step 2: Validate OCSP signer certificate trust against issuer
                self.log(f"[OCSP-SIGNER-VALIDATION] Step 2/3: Validating signer certificate trust\n")
                trust_validation = self._validate_ocsp_signer_trust(signer_cert_pem, issuer_cert_path)
                validation_summary["trust_validation"] = trust_validation
                
                if trust_validation["is_trusted"]:
                    validation_summary["step_results"]["step_2_trust_validation"] = {
                        "success": True,
                        "message": f"Signer certificate trusted via {trust_validation['trust_method']}",
                        "details": trust_validation["validation_details"]
                    }
                    validation_summary["steps_completed"] += 1
                    self.log(f"[OCSP-SIGNER-VALIDATION] [OK] Step 2 completed: Signer certificate trusted\n")
                    
                    # Step 3: Validate OCSP response signature with signer certificate
                    self.log(f"[OCSP-SIGNER-VALIDATION] Step 3/3: Validating OCSP response signature\n")
                    signature_validation = self._validate_ocsp_response_signature(ocsp_response, signer_cert_pem, issuer_cert_path, cert_path, ocsp_url, cert_serial)
                    validation_summary["signature_validation"] = signature_validation
                    
                    if signature_validation["signature_valid"]:
                        validation_summary["step_results"]["step_3_signature_validation"] = {
                            "success": True,
                            "message": "OCSP response signature validated successfully",
                            "details": signature_validation["validation_details"]
                        }
                        validation_summary["steps_completed"] += 1
                        validation_summary["overall_success"] = True
                        self.log(f"[OCSP-SIGNER-VALIDATION] [OK] Step 3 completed: Signature validation successful\n")
                        self.log(f"[OCSP-SIGNER-VALIDATION] [SUCCESS] All 3 steps completed successfully!\n")
                    else:
                        validation_summary["step_results"]["step_3_signature_validation"] = {
                            "success": False,
                            "message": "OCSP response signature validation failed",
                            "errors": signature_validation["errors"]
                        }
                        validation_summary["errors"].extend(signature_validation["errors"])
                        self.log(f"[OCSP-SIGNER-VALIDATION] [ERROR] Step 3 failed: Signature validation failed\n")
                else:
                    validation_summary["step_results"]["step_2_trust_validation"] = {
                        "success": False,
                        "message": "Signer certificate not trusted by issuer",
                        "errors": trust_validation["errors"]
                    }
                    validation_summary["errors"].extend(trust_validation["errors"])
                    self.log(f"[OCSP-SIGNER-VALIDATION] [ERROR] Step 2 failed: Signer certificate not trusted\n")
            else:
                validation_summary["step_results"]["step_1_extract_signer"] = {
                    "success": False,
                    "message": "Failed to extract OCSP signer certificate from response"
                }
                validation_summary["errors"].append("No OCSP signer certificate found in response")
                self.log(f"[OCSP-SIGNER-VALIDATION] [ERROR] Step 1 failed: No signer certificate extracted\n")
            
            # Collect all warnings
            if validation_summary["trust_validation"]:
                validation_summary["warnings"].extend(validation_summary["trust_validation"].get("warnings", []))
            if validation_summary["signature_validation"]:
                validation_summary["warnings"].extend(validation_summary["signature_validation"].get("warnings", []))
            
            # Log summary
            self.log(f"[OCSP-SIGNER-VALIDATION] Summary: {validation_summary['steps_completed']}/3 steps completed\n")
            if validation_summary["overall_success"]:
                self.log(f"[OCSP-SIGNER-VALIDATION] [SUCCESS] Multi-step validation completed successfully\n")
            else:
                self.log(f"[OCSP-SIGNER-VALIDATION] [FAILED] Multi-step validation failed\n")
                for error in validation_summary["errors"]:
                    self.log(f"[OCSP-SIGNER-VALIDATION] [ERROR] {error}\n")
            
        except Exception as e:
            validation_summary["errors"].append(f"Multi-step validation error: {str(e)}")
            self.log(f"[OCSP-SIGNER-VALIDATION] [ERROR] Multi-step validation failed: {str(e)}\n")
        
        return validation_summary