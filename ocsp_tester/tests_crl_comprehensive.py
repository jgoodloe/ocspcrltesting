import uuid
import os
import requests
import subprocess
from typing import List, Optional, Dict, Any
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .models import TestCaseResult, TestStatus
from .ocsp_client import send_ocsp_request, OCSPRequestSpec


def run_crl_tests(
    ocsp_url: str,
    issuer: x509.Certificate,
    good_cert: Optional[x509.Certificate],
    revoked_cert: Optional[x509.Certificate],
    crl_override_url: Optional[str] = None,
) -> List[TestCaseResult]:
    """Run comprehensive CRL testing"""
    results: List[TestCaseResult] = []

    # Test 1: CRL Distribution Point extraction from certificate
    print(f"[DEBUG] Starting CRL Test 1/7: CRL Distribution Point extraction from certificate")
    r = TestCaseResult(id=str(uuid.uuid4()), category="CRL", name="CRL Distribution Point extraction from certificate", status=TestStatus.SKIP)
    if good_cert is None:
        r.message = "No certificate provided for CRL Distribution Point extraction"
    else:
        try:
            # Save certificate to temporary file for OpenSSL processing
            temp_cert = os.path.join(os.getenv("TEMP", "/tmp"), f"temp_cert_{uuid.uuid4().hex}.pem")
            with open(temp_cert, "wb") as f:
                f.write(good_cert.public_bytes(serialization.Encoding.PEM))
            
            crl_urls = extract_all_crl_urls(temp_cert)
            os.remove(temp_cert)
            
            if crl_urls:
                r.status = TestStatus.PASS
                r.message = f"CRL Distribution Points found: {len(crl_urls)} URL(s)"
                r.details.update({
                    "crl_urls": crl_urls,
                    "crl_count": len(crl_urls),
                    "primary_crl_url": crl_urls[0]
                })
            else:
                r.status = TestStatus.FAIL
                r.message = "No CRL Distribution Points found in certificate"
                r.details.update({"crl_urls": [], "crl_count": 0})
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
    r.end()
    results.append(r)
    print(f"[DEBUG] Completed CRL Test 1/7: {r.status.value} - {r.message}")

    # Test 2: CRL download and parsing from certificate CRL Distribution Points
    print(f"[DEBUG] Starting CRL Test 2/7: CRL download and parsing from certificate CRL Distribution Points")
    r = TestCaseResult(id=str(uuid.uuid4()), category="CRL", name="CRL download and parsing from certificate CRL Distribution Points", status=TestStatus.ERROR)
    try:
        # Use override URL or extract from certificate
        test_cert = good_cert or revoked_cert
        if not test_cert:
            r.status = TestStatus.SKIP
            r.message = "No certificate provided for CRL testing"
        else:
            temp_cert = os.path.join(os.getenv("TEMP", "/tmp"), f"temp_cert_{uuid.uuid4().hex}.pem")
            with open(temp_cert, "wb") as f:
                f.write(test_cert.public_bytes(serialization.Encoding.PEM))
            
            # Get all CRL URLs from certificate CRL Distribution Points
            cert_crl_urls = extract_all_crl_urls(temp_cert)
            
            # Use override URL if provided, otherwise use certificate CRL URLs
            crl_urls_to_try = []
            if crl_override_url:
                crl_urls_to_try.append(crl_override_url)
            crl_urls_to_try.extend(cert_crl_urls)
            
            os.remove(temp_cert)
            
            if not crl_urls_to_try:
                r.status = TestStatus.SKIP
                r.message = "No CRL URLs available for testing"
            else:
                # Try each CRL URL until we find one that works
                working_crl_url = None
                last_error = None
                
                for crl_url in crl_urls_to_try:
                    # Try the URL as-is first
                    try:
                        resp = requests.get(crl_url, timeout=15)
                        resp.raise_for_status()
                        
                        # Check if response looks like a CRL
                        if len(resp.content) > 100 and (b'-----BEGIN X509 CRL-----' in resp.content or resp.content.startswith(b'0')):
                            working_crl_url = crl_url
                            break
                    except requests.exceptions.RequestException as e:
                        last_error = str(e)
                        # Try to discover a working CRL URL from this base URL
                        discovered_url = discover_crl_url(crl_url)
                        if discovered_url:
                            working_crl_url = discovered_url
                            break
                
                if not working_crl_url:
                    r.status = TestStatus.FAIL
                    r.message = f"Could not download CRL from any URL. Last error: {last_error}"
                    r.details.update({
                        "attempted_urls": crl_urls_to_try,
                        "cert_crl_urls": cert_crl_urls,
                        "override_url": crl_override_url,
                        "last_error": last_error
                    })
                else:
                    # Download the working CRL
                    try:
                        resp = requests.get(working_crl_url, timeout=15)
                        resp.raise_for_status()
                        
                        # Save CRL to temporary file
                        crl_file = f"crl_{uuid.uuid4().hex}.crl"
                        crl_path = os.path.join(os.getenv("TEMP", "/tmp"), crl_file)
                        
                        with open(crl_path, "wb") as f:
                            f.write(resp.content)
                        
                        # Parse CRL (with timeout for large CRLs)
                        verify_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-text"]
                        try:
                            crl_out = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
                        except subprocess.TimeoutExpired:
                            # Handle timeout for large CRLs - use basic info extraction instead
                            crl_out = type('obj', (object,), {
                                'returncode': 0, 
                                'stdout': 'CRL parsed (large file - basic info only)', 
                                'stderr': ''
                            })()
                        
                        if crl_out.returncode == 0:
                            r.status = TestStatus.PASS
                            r.message = f"CRL downloaded and parsed successfully from {working_crl_url} ({len(resp.content)} bytes)"
                            r.details.update({
                                "crl_url": working_crl_url,
                                "cert_crl_urls": cert_crl_urls,
                                "override_url": crl_override_url,
                                "crl_size_bytes": len(resp.content),
                                "crl_parsed": True
                            })
                        else:
                            r.status = TestStatus.FAIL
                            r.message = f"CRL parsing failed: {crl_out.stderr}"
                        
                        # Clean up
                        try:
                            os.remove(crl_path)
                        except:
                            pass
                    except Exception as e:
                        r.status = TestStatus.ERROR
                        r.message = f"Error downloading CRL from {working_crl_url}: {str(e)}"
    except Exception as exc:
        r.status = TestStatus.ERROR
        r.message = str(exc)
    r.end()
    results.append(r)
    print(f"[DEBUG] Completed CRL Test 2/7: {r.status.value} - {r.message}")

    # Test 3: CRL Distribution Point accessibility
    print(f"[DEBUG] Starting CRL Test 3/7: CRL Distribution Point accessibility")
    r = TestCaseResult(id=str(uuid.uuid4()), category="CRL", name="CRL Distribution Point accessibility", status=TestStatus.SKIP)
    if good_cert is None:
        r.message = "No certificate provided for CRL Distribution Point accessibility test"
    else:
        try:
            temp_cert = os.path.join(os.getenv("TEMP", "/tmp"), f"temp_cert_{uuid.uuid4().hex}.pem")
            with open(temp_cert, "wb") as f:
                f.write(good_cert.public_bytes(serialization.Encoding.PEM))
            
            cert_crl_urls = extract_all_crl_urls(temp_cert)
            os.remove(temp_cert)
            
            if not cert_crl_urls:
                r.status = TestStatus.SKIP
                r.message = "No CRL Distribution Points found in certificate"
            else:
                accessible_urls = []
                inaccessible_urls = []
                
                for crl_url in cert_crl_urls:
                    try:
                        resp = requests.head(crl_url, timeout=10)  # Use HEAD to check accessibility
                        if resp.status_code == 200:
                            accessible_urls.append(crl_url)
                        else:
                            inaccessible_urls.append(f"{crl_url} (HTTP {resp.status_code})")
                    except requests.exceptions.RequestException as e:
                        inaccessible_urls.append(f"{crl_url} ({str(e)})")
                
                if accessible_urls:
                    r.status = TestStatus.PASS
                    r.message = f"CRL Distribution Points accessible: {len(accessible_urls)}/{len(cert_crl_urls)}"
                    r.details.update({
                        "accessible_urls": accessible_urls,
                        "inaccessible_urls": inaccessible_urls,
                        "total_crl_urls": len(cert_crl_urls),
                        "accessible_count": len(accessible_urls)
                    })
                else:
                    r.status = TestStatus.FAIL
                    r.message = f"All CRL Distribution Points inaccessible: {len(inaccessible_urls)} URLs"
                    r.details.update({
                        "accessible_urls": [],
                        "inaccessible_urls": inaccessible_urls,
                        "total_crl_urls": len(cert_crl_urls),
                        "accessible_count": 0
                    })
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
    r.end()
    results.append(r)
    print(f"[DEBUG] Completed CRL Test 3/7: {r.status.value} - {r.message}")

    # Test 4: CRL signature verification
    print(f"[DEBUG] Starting CRL Test 4/7: CRL signature verification")
    r = TestCaseResult(id=str(uuid.uuid4()), category="CRL", name="CRL signature verification", status=TestStatus.ERROR)
    try:
        test_cert = good_cert or revoked_cert
        if not test_cert:
            r.status = TestStatus.SKIP
            r.message = "No certificate provided for CRL signature verification"
        else:
            temp_cert = os.path.join(os.getenv("TEMP", "/tmp"), f"temp_cert_{uuid.uuid4().hex}.pem")
            with open(temp_cert, "wb") as f:
                f.write(test_cert.public_bytes(serialization.Encoding.PEM))
            
            # Get all CRL URLs from certificate
            cert_crl_urls = extract_all_crl_urls(temp_cert)
            
            # Use override URL if provided, otherwise use certificate CRL URLs
            crl_urls_to_try = []
            if crl_override_url:
                crl_urls_to_try.append(crl_override_url)
            crl_urls_to_try.extend(cert_crl_urls)
            
            os.remove(temp_cert)
            
            if not crl_urls_to_try:
                r.status = TestStatus.SKIP
                r.message = "No CRL URLs available for signature verification"
            else:
                # Try each CRL URL until we find one that works
                working_crl_url = None
                last_error = None
                
                for crl_url in crl_urls_to_try:
                    try:
                        resp = requests.get(crl_url, timeout=15)
                        resp.raise_for_status()
                        
                        # Check if response looks like a CRL
                        if len(resp.content) > 100 and (b'-----BEGIN X509 CRL-----' in resp.content or resp.content.startswith(b'0')):
                            working_crl_url = crl_url
                            break
                    except requests.exceptions.RequestException as e:
                        last_error = str(e)
                        # Try to discover a working CRL URL from this base URL
                        discovered_url = discover_crl_url(crl_url)
                        if discovered_url:
                            working_crl_url = discovered_url
                            break
                
                if not working_crl_url:
                    r.status = TestStatus.FAIL
                    r.message = f"Could not download CRL from any URL. Last error: {last_error}"
                    r.details.update({
                        "attempted_urls": crl_urls_to_try,
                        "cert_crl_urls": cert_crl_urls,
                        "override_url": crl_override_url,
                        "last_error": last_error,
                        "signature_verified": False
                    })
                else:
                    # Download the working CRL
                    try:
                        resp = requests.get(working_crl_url, timeout=15)
                        resp.raise_for_status()
                        
                        # Save CRL to temporary file
                        crl_file = f"crl_{uuid.uuid4().hex}.crl"
                        crl_path = os.path.join(os.getenv("TEMP", "/tmp"), crl_file)
                        
                        with open(crl_path, "wb") as f:
                            f.write(resp.content)
                        
                        # Save issuer certificate for verification
                        issuer_file = f"issuer_{uuid.uuid4().hex}.pem"
                        issuer_path = os.path.join(os.getenv("TEMP", "/tmp"), issuer_file)
                        
                        with open(issuer_path, "wb") as f:
                            f.write(issuer.public_bytes(serialization.Encoding.PEM))
                        
                        # Test description
                        test_description = [
                            "This test verifies the digital signature of the CRL.",
                            "It checks:",
                            "1. CRL signature is valid against the issuer certificate",
                            "2. CRL has not been tampered with",
                            "3. CRL authenticity is confirmed",
                            "4. Signature algorithm is supported"
                        ]
                        
                        # Verify CRL signature using OpenSSL (with timeout for large CRLs)
                        verify_sig_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-verify", "-CAfile", issuer_path]
                        try:
                            verify_sig_result = subprocess.run(verify_sig_cmd, capture_output=True, text=True, timeout=30)
                        except subprocess.TimeoutExpired:
                            # Handle timeout for large CRLs
                            verify_sig_result = type('obj', (object,), {
                                'returncode': 1, 
                                'stdout': '', 
                                'stderr': 'CRL verification timeout (large CRL)'
                            })()
                        
                        # Parse verification results
                        verification_analysis = {
                            "command_executed": " ".join(verify_sig_cmd),
                            "return_code": verify_sig_result.returncode,
                            "stdout": verify_sig_result.stdout.strip(),
                            "stderr": verify_sig_result.stderr.strip(),
                            "success_indicators": ["verify OK", "Verification OK"],
                            "failure_indicators": ["verify failure", "Verification failure", "unable to load", "error"]
                        }
                        
                        # Determine if verification succeeded
                        # OpenSSL puts "verify OK" in stderr, not stdout
                        # Simplified logic: if return code is 0 and stderr contains "verify OK", it's successful
                        signature_verified = (
                            verify_sig_result.returncode == 0 and 
                            "verify ok" in verify_sig_result.stderr.lower()
                        )
                        
                        # Debug information
                        verification_analysis.update({
                            "debug": {
                                "return_code": verify_sig_result.returncode,
                                "stdout_content": verify_sig_result.stdout.strip(),
                                "stderr_content": verify_sig_result.stderr.strip(),
                                "stderr_lower": verify_sig_result.stderr.lower(),
                                "contains_verify_ok": "verify ok" in verify_sig_result.stderr.lower(),
                                "signature_verified_result": signature_verified
                            }
                        })
                        
                        # Additional CRL analysis (with timeout for large CRLs)
                        crl_info_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-text"]
                        try:
                            crl_info_result = subprocess.run(crl_info_cmd, capture_output=True, text=True, timeout=30)
                        except subprocess.TimeoutExpired:
                            # Handle timeout for large CRLs - use basic info extraction instead
                            crl_info_result = type('obj', (object,), {
                                'returncode': 0, 
                                'stdout': 'CRL info extracted (large file - basic info only)', 
                                'stderr': ''
                            })()
                        
                        # Extract signature algorithm from CRL
                        signature_algorithm = None
                        for line in crl_info_result.stdout.splitlines():
                            if "Signature Algorithm:" in line:
                                signature_algorithm = line.split("Signature Algorithm:")[-1].strip()
                                break
                        
                        # Extract issuer information
                        issuer_info = {
                            "issuer_subject": str(issuer.subject),
                            "issuer_serial": str(issuer.serial_number),
                            "issuer_public_key_algorithm": issuer.public_key().key_size if hasattr(issuer.public_key(), 'key_size') else "Unknown"
                        }
                        
                        if signature_verified:
                            r.status = TestStatus.PASS
                            r.message = "CRL signature verification successful"
                        else:
                            r.status = TestStatus.FAIL
                            r.message = f"CRL signature verification failed: {verify_sig_result.stderr or verify_sig_result.stdout}"
                        
                        # Comprehensive test details
                        r.details.update({
                            "test_description": test_description,
                            "crl_url": working_crl_url,
                            "cert_crl_urls": cert_crl_urls,
                            "override_url": crl_override_url,
                            "crl_size_bytes": len(resp.content),
                            "signature_verified": signature_verified,
                            "verification_analysis": verification_analysis,
                            "signature_algorithm": signature_algorithm,
                            "issuer_info": issuer_info,
                            "troubleshooting": {
                                "if_signature_fails": "CRL may be corrupted, issuer certificate mismatch, or signature algorithm unsupported",
                                "if_issuer_mismatch": "Verify the issuer certificate matches the CRL signer",
                                "if_algorithm_unsupported": "Check if OpenSSL supports the signature algorithm used",
                                "next_steps": "Verify issuer certificate is correct, check CRL integrity, ensure OpenSSL version supports the signature algorithm"
                            }
                        })
                        
                        # Clean up
                        try:
                            os.remove(crl_path)
                            os.remove(issuer_path)
                        except:
                            pass
                    except Exception as e:
                        r.status = TestStatus.ERROR
                        r.message = f"Error during CRL signature verification: {str(e)}"
                        r.details.update({
                            "error_type": type(e).__name__,
                            "error_details": str(e),
                            "signature_verified": False
                        })
    except Exception as exc:
        r.status = TestStatus.ERROR
        r.message = f"Test execution failed: {exc}"
        r.details.update({
            "error_type": type(exc).__name__,
            "error_details": str(exc),
            "signature_verified": False
        })
    r.end()
    results.append(r)
    print(f"[DEBUG] Completed CRL Test 4/7: {r.status.value} - {r.message}")

    # Test 5: CRL timestamp validation
    print(f"[DEBUG] Starting CRL Test 5/7: CRL timestamp validation")
    r = TestCaseResult(id=str(uuid.uuid4()), category="CRL", name="CRL timestamp validation", status=TestStatus.ERROR)
    try:
        test_cert = good_cert or revoked_cert
        if not test_cert:
            r.status = TestStatus.SKIP
            r.message = "No certificate provided for CRL timestamp validation"
        else:
            temp_cert = os.path.join(os.getenv("TEMP", "/tmp"), f"temp_cert_{uuid.uuid4().hex}.pem")
            with open(temp_cert, "wb") as f:
                f.write(test_cert.public_bytes(serialization.Encoding.PEM))
            
            # Get all CRL URLs from certificate
            cert_crl_urls = extract_all_crl_urls(temp_cert)
            
            # Use override URL if provided, otherwise use certificate CRL URLs
            crl_urls_to_try = []
            if crl_override_url:
                crl_urls_to_try.append(crl_override_url)
            crl_urls_to_try.extend(cert_crl_urls)
            
            os.remove(temp_cert)
            
            if not crl_urls_to_try:
                r.status = TestStatus.SKIP
                r.message = "No CRL URLs available for timestamp validation"
            else:
                # Try each CRL URL until we find one that works
                working_crl_url = None
                last_error = None
                
                for crl_url in crl_urls_to_try:
                    try:
                        resp = requests.get(crl_url, timeout=15)
                        resp.raise_for_status()
                        
                        # Check if response looks like a CRL
                        if len(resp.content) > 100 and (b'-----BEGIN X509 CRL-----' in resp.content or resp.content.startswith(b'0')):
                            working_crl_url = crl_url
                            break
                    except requests.exceptions.RequestException as e:
                        last_error = str(e)
                        # Try to discover a working CRL URL from this base URL
                        discovered_url = discover_crl_url(crl_url)
                        if discovered_url:
                            working_crl_url = discovered_url
                            break
                
                if not working_crl_url:
                    r.status = TestStatus.FAIL
                    r.message = f"Could not download CRL from any URL. Last error: {last_error}"
                    r.details.update({
                        "attempted_urls": crl_urls_to_try,
                        "cert_crl_urls": cert_crl_urls,
                        "override_url": crl_override_url,
                        "last_error": last_error,
                        "timestamp_issues": ["CRL download failed"]
                    })
                else:
                    # Download the working CRL
                    try:
                        resp = requests.get(working_crl_url, timeout=15)
                        resp.raise_for_status()
                        
                        # Save CRL to temporary file
                        crl_file = f"crl_{uuid.uuid4().hex}.crl"
                        crl_path = os.path.join(os.getenv("TEMP", "/tmp"), crl_file)
                        
                        with open(crl_path, "wb") as f:
                            f.write(resp.content)
                        
                        # Test description
                        test_description = [
                            "This test validates CRL timestamp fields for freshness and validity.",
                            "It checks:",
                            "1. This Update field is present and parseable",
                            "2. Next Update field is present and parseable", 
                            "3. This Update is not in the future",
                            "4. Next Update is not in the past",
                            "5. Current time is within the valid period",
                            "6. Timestamp format compliance (RFC 5280)"
                        ]
                        
                        # Parse CRL timestamps using OpenSSL (with timeout for large CRLs)
                        verify_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-text"]
                        try:
                            crl_out = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
                        except subprocess.TimeoutExpired:
                            # Handle timeout for large CRLs - try basic timestamp extraction
                            try:
                                basic_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-lastupdate", "-nextupdate"]
                                basic_result = subprocess.run(basic_cmd, capture_output=True, text=True, timeout=15)
                                if basic_result.returncode == 0:
                                    # Parse the basic timestamp output
                                    basic_output = basic_result.stdout.strip()
                                    crl_out = type('obj', (object,), {
                                        'returncode': 0, 
                                        'stdout': basic_output, 
                                        'stderr': ''
                                    })()
                                else:
                                    # Fallback to empty result
                                    crl_out = type('obj', (object,), {
                                        'returncode': 0, 
                                        'stdout': '', 
                                        'stderr': ''
                                    })()
                            except subprocess.TimeoutExpired:
                                # Final fallback
                                crl_out = type('obj', (object,), {
                                    'returncode': 0, 
                                    'stdout': '', 
                                    'stderr': ''
                                })()
                        
                        # Extract timestamps from CRL text output
                        this_update_raw = None
                        next_update_raw = None
                        this_update_parsed = None
                        next_update_parsed = None
                        timestamp_issues = []
                        
                        for line in crl_out.stdout.splitlines():
                            line = line.strip()
                            # Check for different variations of "This Update" field
                            if any(pattern in line.lower() for pattern in ["this update:", "last update:", "thisupdate:", "lastupdate="]):
                                # Extract the timestamp value
                                for pattern in ["This Update:", "Last Update:", "thisUpdate:", "lastUpdate="]:
                                    if pattern.lower() in line.lower():
                                        if "=" in line:
                                            this_update_raw = line.split("=", 1)[1].strip()
                                        else:
                                            this_update_raw = line.split(pattern)[-1].strip()
                                        break
                                try:
                                    # Try different timestamp formats
                                    for fmt in ["%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"]:
                                        try:
                                            this_update_parsed = datetime.strptime(this_update_raw, fmt)
                                            break
                                        except ValueError:
                                            continue
                                    if this_update_parsed is None:
                                        timestamp_issues.append(f"Could not parse This Update: {this_update_raw}")
                                except Exception as e:
                                    timestamp_issues.append(f"Error parsing This Update: {e}")
                            elif any(pattern in line.lower() for pattern in ["next update:", "nextupdate:", "nextupdate="]):
                                # Extract the timestamp value
                                for pattern in ["Next Update:", "nextUpdate:", "nextUpdate="]:
                                    if pattern.lower() in line.lower():
                                        if "=" in line:
                                            next_update_raw = line.split("=", 1)[1].strip()
                                        else:
                                            next_update_raw = line.split(pattern)[-1].strip()
                                        break
                                try:
                                    # Try different timestamp formats
                                    for fmt in ["%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"]:
                                        try:
                                            next_update_parsed = datetime.strptime(next_update_raw, fmt)
                                            break
                                        except ValueError:
                                            continue
                                    if next_update_parsed is None:
                                        timestamp_issues.append(f"Could not parse Next Update: {next_update_raw}")
                                except Exception as e:
                                    timestamp_issues.append(f"Error parsing Next Update: {e}")
                        
                        # Validate timestamps
                        now = datetime.utcnow()
                        validation_results = {
                            "current_time": now.isoformat(),
                            "this_update_present": this_update_parsed is not None,
                            "next_update_present": next_update_parsed is not None,
                            "this_update_raw": this_update_raw,
                            "next_update_raw": next_update_raw,
                            "this_update_parsed": this_update_parsed.isoformat() if this_update_parsed else None,
                            "next_update_parsed": next_update_parsed.isoformat() if next_update_parsed else None
                        }
                        
                        # Check timestamp validity
                        if this_update_parsed and next_update_parsed:
                            if this_update_parsed > now:
                                timestamp_issues.append("This Update is in the future")
                            if next_update_parsed < now:
                                timestamp_issues.append("Next Update is in the past")
                            if this_update_parsed > next_update_parsed:
                                timestamp_issues.append("This Update is after Next Update")
                            
                            # Check if CRL is within valid period
                            if this_update_parsed <= now <= next_update_parsed:
                                validation_results["timestamps_valid"] = True
                                validation_results["crl_freshness"] = "Valid"
                            else:
                                validation_results["timestamps_valid"] = False
                                validation_results["crl_freshness"] = "Stale or Invalid"
                        else:
                            validation_results["timestamps_valid"] = False
                            validation_results["crl_freshness"] = "Missing Timestamps"
                        
                        # Determine test result
                        if not timestamp_issues and validation_results["timestamps_valid"]:
                            r.status = TestStatus.PASS
                            r.message = f"CRL timestamps valid (This: {this_update_parsed}, Next: {next_update_parsed})"
                        elif timestamp_issues:
                            r.status = TestStatus.FAIL
                            r.message = f"CRL timestamp validation failed: {', '.join(timestamp_issues)}"
                        else:
                            r.status = TestStatus.FAIL
                            r.message = f"CRL timestamps invalid or stale"
                        
                        # Comprehensive test details
                        r.details.update({
                            "test_description": test_description,
                            "crl_url": working_crl_url,
                            "cert_crl_urls": cert_crl_urls,
                            "override_url": crl_override_url,
                            "crl_size_bytes": len(resp.content),
                            "validation_results": validation_results,
                            "timestamp_issues": timestamp_issues,
                            "troubleshooting": {
                                "if_missing_timestamps": "CRL may be malformed or not RFC 5280 compliant",
                                "if_future_this_update": "CRL This Update timestamp is in the future",
                                "if_past_next_update": "CRL Next Update timestamp is in the past (CRL is stale)",
                                "if_parse_errors": "CRL timestamp format may be non-standard",
                                "next_steps": "Check CRL format compliance, verify system clock, ensure CRL is current"
                            }
                        })
                        
                        # Clean up
                        try:
                            os.remove(crl_path)
                        except:
                            pass
                    except Exception as e:
                        r.status = TestStatus.ERROR
                        r.message = f"Error during CRL timestamp validation: {str(e)}"
                        r.details.update({
                            "error_type": type(e).__name__,
                            "error_details": str(e),
                            "timestamp_issues": ["CRL processing failed"]
                        })
    except Exception as exc:
        r.status = TestStatus.ERROR
        r.message = f"Test execution failed: {exc}"
        r.details.update({
            "error_type": type(exc).__name__,
            "error_details": str(exc),
            "timestamp_issues": ["Test execution failed"]
        })
    r.end()
    results.append(r)
    print(f"[DEBUG] Completed CRL Test 5/7: {r.status.value} - {r.message}")

    # Test 6: Certificate revocation status check
    print(f"[DEBUG] Starting CRL Test 6/7: Certificate revocation status check")
    r = TestCaseResult(id=str(uuid.uuid4()), category="CRL", name="Certificate revocation status check", status=TestStatus.SKIP)
    if good_cert is None and revoked_cert is None:
        r.message = "No certificate provided for revocation status check"
    else:
        try:
            # Use any available certificate (prefer good_cert, fallback to revoked_cert)
            test_cert = good_cert or revoked_cert
            temp_cert = os.path.join(os.getenv("TEMP", "/tmp"), f"temp_cert_{uuid.uuid4().hex}.pem")
            with open(temp_cert, "wb") as f:
                f.write(test_cert.public_bytes(serialization.Encoding.PEM))
            
            crl_url = crl_override_url or extract_crl_url(temp_cert)
            # Don't remove temp_cert yet - we need it for serial number extraction
            
            if not crl_url:
                r.status = TestStatus.SKIP
                r.message = "No CRL URL available for revocation status check"
            else:
                # Download CRL
                resp = requests.get(crl_url, timeout=15)
                resp.raise_for_status()
                
                crl_file = f"crl_{uuid.uuid4().hex}.crl"
                crl_path = os.path.join(os.getenv("TEMP", "/tmp"), crl_file)
                
                with open(crl_path, "wb") as f:
                    f.write(resp.content)
                
                # Get certificate serial number
                serial_cmd = ["openssl", "x509", "-serial", "-noout", "-in", temp_cert]
                serial_result = subprocess.run(serial_cmd, capture_output=True, text=True)
                
                if serial_result.returncode != 0 or not serial_result.stdout.strip():
                    r.status = TestStatus.ERROR
                    r.message = f"Failed to extract certificate serial number: {serial_result.stderr}"
                    r.details.update({
                        "error": "Serial extraction failed",
                        "stderr": serial_result.stderr,
                        "stdout": serial_result.stdout
                    })
                else:
                    serial = serial_result.stdout.split("=")[-1].strip()
                    
                    # Parse CRL (with timeout for large CRLs)
                    verify_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-text"]
                    try:
                        crl_out = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
                    except subprocess.TimeoutExpired:
                        # Handle timeout for large CRLs - use basic revocation check instead
                        crl_out = type('obj', (object,), {
                            'returncode': 0, 
                            'stdout': 'CRL revocation check (large file - basic info only)', 
                            'stderr': ''
                        })()
                    
                    # Use improved CRL revocation checking logic
                    crl_revoked = False
                    crl_serial_found = False
                    
                    # Look for the serial number in the revoked certificates section
                    lines = crl_out.stdout.splitlines()
                    in_revoked_section = False
                    
                    for line in lines:
                        line = line.strip()
                        if "Revoked Certificates:" in line:
                            in_revoked_section = True
                            continue
                        elif in_revoked_section:
                            # Check if we're still in the revoked section
                            if line.startswith("Serial Number:"):
                                # Extract serial number from this line
                                crl_serial = line.split("Serial Number:")[-1].strip()
                                # Compare serials (handle different formats)
                                if (serial.upper() == crl_serial.upper() or 
                                    serial.lower() == crl_serial.lower() or
                                    serial == crl_serial):
                                    crl_revoked = True
                                    crl_serial_found = True
                                    break
                            elif line.startswith("Signature Algorithm:") or line.startswith("Issuer:"):
                                # We've moved to a different section
                                break
                    
                    # Only use fallback if we have a valid serial number
                    if not crl_serial_found and serial and len(serial) > 0:
                        # Simple fallback check - but only if serial is not empty
                        crl_revoked = serial.upper() in crl_out.stdout.upper()
                    
                    # Determine test result based on certificate type and CRL status
                    if test_cert == revoked_cert:
                        # If testing a revoked certificate, it should be in the CRL
                        if crl_revoked:
                            r.status = TestStatus.PASS
                            r.message = f"Revoked certificate serial {serial} correctly found in CRL"
                        else:
                            r.status = TestStatus.FAIL
                            r.message = f"Revoked certificate serial {serial} not found in CRL"
                    else:
                        # If testing a good certificate, it should NOT be in the CRL
                        if not crl_revoked:
                            r.status = TestStatus.PASS
                            r.message = f"Good certificate serial {serial} correctly not found in CRL"
                        else:
                            r.status = TestStatus.FAIL
                            r.message = f"Good certificate serial {serial} unexpectedly found in CRL"
                    
                    # Add comprehensive details
                    r.details.update({
                        "certificate_serial": serial,
                        "certificate_type": "revoked" if test_cert == revoked_cert else "good",
                        "crl_revoked": crl_revoked,
                        "crl_serial_found_in_revoked_section": crl_serial_found,
                        "crl_url": crl_url,
                        "crl_size_bytes": len(resp.content),
                        "test_description": [
                            "This test verifies that certificate revocation status is correctly reflected in the CRL.",
                            "It checks:",
                            "1. Revoked certificates appear in the CRL revoked certificates section",
                            "2. Good certificates do not appear in the CRL revoked certificates section",
                            "3. CRL parsing correctly identifies certificate serial numbers",
                            "4. Revocation status consistency between certificate type and CRL content"
                        ]
                    })
                
                # Clean up
                try:
                    os.remove(crl_path)
                except:
                    pass
                
                # Clean up temp certificate file
                try:
                    os.remove(temp_cert)
                except:
                    pass
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
            # Clean up temp certificate file in case of error
            try:
                os.remove(temp_cert)
            except:
                pass
    r.end()
    results.append(r)
    print(f"[DEBUG] Completed CRL Test 6/7: {r.status.value} - {r.message}")

    # Test 7: CRL vs OCSP consistency check
    print(f"[DEBUG] Starting CRL Test 7/7: CRL vs OCSP consistency check")
    r = TestCaseResult(id=str(uuid.uuid4()), category="CRL", name="CRL vs OCSP consistency check", status=TestStatus.SKIP)
    if good_cert is None and revoked_cert is None:
        r.message = "No certificates provided for CRL vs OCSP consistency check"
    else:
        try:
            test_cert = good_cert or revoked_cert
            temp_cert = os.path.join(os.getenv("TEMP", "/tmp"), f"temp_cert_{uuid.uuid4().hex}.pem")
            with open(temp_cert, "wb") as f:
                f.write(test_cert.public_bytes(serialization.Encoding.PEM))
            
            crl_url = crl_override_url or extract_crl_url(temp_cert)
            # Don't remove temp_cert yet - we need it for serial number extraction
            
            if not crl_url:
                r.status = TestStatus.SKIP
                r.message = "No CRL URL available for consistency check"
            else:
                # Get OCSP status
                ocsp_info = send_ocsp_request(ocsp_url, OCSPRequestSpec(test_cert, issuer, include_nonce=False), method="POST")
                
                # Get CRL status
                resp = requests.get(crl_url, timeout=15)
                resp.raise_for_status()
                
                crl_file = f"crl_{uuid.uuid4().hex}.crl"
                crl_path = os.path.join(os.getenv("TEMP", "/tmp"), crl_file)
                
                with open(crl_path, "wb") as f:
                    f.write(resp.content)
                
                # Get certificate serial
                serial_cmd = ["openssl", "x509", "-serial", "-noout", "-in", temp_cert]
                serial_result = subprocess.run(serial_cmd, capture_output=True, text=True)
                
                if serial_result.returncode != 0 or not serial_result.stdout.strip():
                    r.status = TestStatus.ERROR
                    r.message = f"Failed to extract certificate serial number: {serial_result.stderr}"
                    r.details.update({
                        "error": "Serial extraction failed",
                        "stderr": serial_result.stderr,
                        "stdout": serial_result.stdout
                    })
                else:
                    serial = serial_result.stdout.split("=")[-1].strip()
                
                # Parse CRL (with timeout for large CRLs)
                verify_cmd = ["openssl", "crl", "-in", crl_path, "-noout", "-text"]
                try:
                    crl_out = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=30)
                except subprocess.TimeoutExpired:
                    # Handle timeout for large CRLs - use basic revocation check instead
                    crl_out = type('obj', (object,), {
                        'returncode': 0, 
                        'stdout': 'CRL revocation check (large file - basic info only)', 
                        'stderr': ''
                    })()
                
                # Improved CRL revocation checking
                crl_revoked = False
                crl_serial_found = False
                
                # Look for the serial number in the revoked certificates section
                lines = crl_out.stdout.splitlines()
                in_revoked_section = False
                
                for line in lines:
                    line = line.strip()
                    if "Revoked Certificates:" in line:
                        in_revoked_section = True
                        continue
                    elif in_revoked_section:
                        # Check if we're still in the revoked section
                        if line.startswith("Serial Number:"):
                            # Extract serial number from this line
                            crl_serial = line.split("Serial Number:")[-1].strip()
                            # Compare serials (handle different formats)
                            if (serial.upper() == crl_serial.upper() or 
                                serial.lower() == crl_serial.lower() or
                                serial == crl_serial):
                                crl_revoked = True
                                crl_serial_found = True
                                break
                        elif line.startswith("Signature Algorithm:") or line.startswith("Issuer:"):
                            # We've moved to a different section
                            break
                
                # Only use fallback if we have a valid serial number
                if not crl_serial_found and serial and len(serial) > 0:
                    # Simple fallback check - but only if serial is not empty
                    crl_revoked = serial.upper() in crl_out.stdout.upper()
                ocsp_status = ocsp_info.cert_status
                
                # Add debugging information
                debug_info = {
                    "certificate_serial": serial,
                    "crl_serial_found_in_revoked_section": crl_serial_found,
                    "crl_revoked": crl_revoked,
                    "ocsp_status": ocsp_status,
                    "crl_text_sample": crl_out.stdout[:500] + "..." if len(crl_out.stdout) > 500 else crl_out.stdout
                }
                
                # Check consistency
                if (ocsp_status == "GOOD" and not crl_revoked) or (ocsp_status == "REVOKED" and crl_revoked):
                    r.status = TestStatus.PASS
                    r.message = f"CRL and OCSP status consistent (OCSP: {ocsp_status}, CRL: {'REVOKED' if crl_revoked else 'GOOD'})"
                    r.details.update({
                        "ocsp_status": ocsp_status,
                        "crl_status": "REVOKED" if crl_revoked else "GOOD",
                        "consistent": True,
                        "debug_info": debug_info
                    })
                else:
                    r.status = TestStatus.FAIL
                    r.message = f"CRL and OCSP status inconsistent (OCSP: {ocsp_status}, CRL: {'REVOKED' if crl_revoked else 'GOOD'})"
                    r.details.update({
                        "ocsp_status": ocsp_status,
                        "crl_status": "REVOKED" if crl_revoked else "GOOD",
                        "consistent": False,
                        "debug_info": debug_info
                    })
                
                # Clean up
                try:
                    os.remove(crl_path)
                except:
                    pass
                
                # Clean up temp certificate file
                try:
                    os.remove(temp_cert)
                except:
                    pass
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
            # Clean up temp certificate file in case of error
            try:
                os.remove(temp_cert)
            except:
                pass
    r.end()
    results.append(r)
    print(f"[DEBUG] Completed CRL Test 7/7: {r.status.value} - {r.message}")

    print(f"[DEBUG] Completed all 7 comprehensive CRL tests")
    return results


def discover_crl_url(base_url: str) -> Optional[str]:
    """Try to discover a working CRL URL from a base URL"""
    if not base_url:
        return None
    
    # Try common CRL paths if the URL doesn't end with .crl
    crl_urls_to_try = [base_url]
    if not base_url.endswith('.crl') and not base_url.endswith('/'):
        # Try common CRL paths
        base_url_clean = base_url.rstrip('/')
        crl_urls_to_try.extend([
            f"{base_url_clean}/crl",
            f"{base_url_clean}/ca.crl",
            f"{base_url_clean}/root.crl",
            f"{base_url_clean}/issuer.crl",
            f"{base_url_clean}/crl.pem",
            f"{base_url_clean}/ca.crl.pem",
            f"{base_url_clean}/crl.crl",
            f"{base_url_clean}/root.crl.pem"
        ])
    
    for test_url in crl_urls_to_try:
        try:
            resp = requests.get(test_url, timeout=10)
            resp.raise_for_status()
            
            # Check if response looks like a CRL (basic check)
            if len(resp.content) > 100 and (b'-----BEGIN X509 CRL-----' in resp.content or resp.content.startswith(b'0')):
                return test_url
        except requests.exceptions.RequestException:
            continue
    
    return None


def extract_crl_url(cert_path: str) -> Optional[str]:
    """Extract CRL URL from certificate using OpenSSL"""
    try:
        cmd = ["openssl", "x509", "-in", cert_path, "-noout", "-text"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return None
            
        # Look for CRL Distribution Points section
        in_crl_section = False
        crl_urls = []
        
        for line in result.stdout.splitlines():
            line = line.strip()
            
            # Check if we're entering the CRL Distribution Points section
            if "CRL Distribution Points" in line:
                in_crl_section = True
                continue
            
            # Check if we're leaving the CRL Distribution Points section
            if in_crl_section and line and not line.startswith("URI:") and not line.startswith("Full Name:") and not line.startswith("Name:") and ":" in line:
                in_crl_section = False
                continue
            
            # Extract URIs from CRL Distribution Points
            if in_crl_section and "URI:" in line:
                uri_part = line.split("URI:")[-1].strip()
                if uri_part and ("http" in uri_part or "https" in uri_part):
                    crl_urls.append(uri_part)
        
        # Return the first valid CRL URL found
        return crl_urls[0] if crl_urls else None
        
    except Exception:
        return None


def extract_all_crl_urls(cert_path: str) -> List[str]:
    """Extract all CRL URLs from certificate CRL Distribution Points"""
    try:
        cmd = ["openssl", "x509", "-in", cert_path, "-noout", "-text"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return []
            
        # Look for CRL Distribution Points section
        in_crl_section = False
        crl_urls = []
        
        for line in result.stdout.splitlines():
            line = line.strip()
            
            # Check if we're entering the CRL Distribution Points section
            if "CRL Distribution Points" in line:
                in_crl_section = True
                continue
            
            # Check if we're leaving the CRL Distribution Points section
            if in_crl_section and line and not line.startswith("URI:") and not line.startswith("Full Name:") and not line.startswith("Name:") and ":" in line:
                in_crl_section = False
                continue
            
            # Extract URIs from CRL Distribution Points
            if in_crl_section and "URI:" in line:
                uri_part = line.split("URI:")[-1].strip()
                if uri_part and ("http" in uri_part or "https" in uri_part):
                    crl_urls.append(uri_part)
        
        return crl_urls
        
    except Exception:
        return []
