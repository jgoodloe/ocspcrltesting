import os
import uuid
from dataclasses import dataclass
from typing import List, Optional, Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .models import TestCaseResult, TestStatus
from .tests_protocol import run_protocol_tests
from .tests_status import run_status_tests
from .tests_security import run_security_tests
from .tests_performance import run_perf_tests
from .tests_ikev2 import run_ikev2_tests
from .tests_crl import run_crl_tests
from .tests_crl_comprehensive import run_crl_tests as run_crl_comprehensive_tests
from .tests_federal import run_federal_tests
from .tests_path_validation import run_path_validation_tests


@dataclass
class TestInputs:
    ocsp_url: str
    issuer_path: str
    known_good_cert_path: Optional[str] = None
    known_revoked_cert_path: Optional[str] = None
    unknown_ca_cert_path: Optional[str] = None
    client_sign_cert_path: Optional[str] = None
    client_sign_key_path: Optional[str] = None
    latency_samples: int = 5
    enable_load_test: bool = False
    load_concurrency: int = 5
    load_requests: int = 50
    crl_override_url: Optional[str] = None
    trust_anchor_path: Optional[str] = None
    trust_anchor_type: str = "root"
    require_explicit_policy: bool = False
    inhibit_policy_mapping: bool = False
    config: Optional[Any] = None


def _load_cert(path: str) -> x509.Certificate:
    if not path or not path.strip():
        raise ValueError("Certificate path is empty")
    
    if not os.path.exists(path):
        raise FileNotFoundError(f"Certificate file not found: {path}")
    
    try:
        with open(path, "rb") as f:
            data = f.read()
        
        if not data:
            raise ValueError("Certificate file is empty")
            
        try:
            return x509.load_pem_x509_certificate(data)
        except Exception:
            return x509.load_der_x509_certificate(data)
    except Exception as e:
        raise Exception(f"Failed to load certificate from {path}: {str(e)}")


class TestRunner:
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
    
    def _log(self, message: str):
        """Log a message using the callback if available"""
        if self.log_callback:
            self.log_callback(message)
    
    def run_all(self, inputs: TestInputs, test_categories: Optional[dict] = None) -> List[TestCaseResult]:
        results: List[TestCaseResult] = []
        
        self._log("[DEBUG] TestRunner.run_all() starting\n")
        self._log(f"[DEBUG] Test categories enabled: {test_categories}\n")
        self._log(f"[DEBUG] Input validation starting - OCSP URL: {inputs.ocsp_url}, Issuer: {inputs.issuer_path}\n")

        # Validate inputs first
        if not inputs.ocsp_url or not inputs.ocsp_url.strip():
            self._log("[DEBUG] Input validation failed - OCSP URL is empty\n")
            r = TestCaseResult(id=str(uuid.uuid4()), category="Setup", name="Validate inputs", status=TestStatus.ERROR, message="OCSP URL is required")
            r.end()
            return [r]
        
        if not inputs.issuer_path or not inputs.issuer_path.strip():
            self._log("[DEBUG] Input validation failed - Issuer path is empty\n")
            r = TestCaseResult(id=str(uuid.uuid4()), category="Setup", name="Validate inputs", status=TestStatus.ERROR, message="Issuer certificate path is required")
            r.end()
            return [r]
        
        self._log("[DEBUG] Input validation passed\n")

        # Load required certs
        self._log("[DEBUG] Loading issuer certificate...\n")
        try:
            issuer = _load_cert(inputs.issuer_path)
            self._log(f"[DEBUG] Issuer certificate loaded successfully - Subject: {issuer.subject}\n")
        except Exception as exc:
            self._log(f"[DEBUG] Failed to load issuer certificate: {str(exc)}\n")
            r = TestCaseResult(id=str(uuid.uuid4()), category="Setup", name="Load issuer certificate", status=TestStatus.ERROR, message=str(exc))
            r.end()
            return [r]

        good = None
        revoked = None
        unknown_ca = None
        
        self._log("[DEBUG] Loading additional certificates...\n")
        
        # Handle known-good certificate (file only)
        if inputs.known_good_cert_path:
            self._log(f"[DEBUG] Loading known-good certificate from: {inputs.known_good_cert_path}\n")
            try:
                good = _load_cert(inputs.known_good_cert_path)
                self._log(f"[DEBUG] Known-good certificate loaded successfully - Subject: {good.subject}\n")
            except Exception as exc:
                self._log(f"[DEBUG] Failed to load known-good certificate: {str(exc)}\n")
                results.append(self._err("Setup", "Load known-good certificate", str(exc)))
            
        # Handle known-revoked certificate (file only)
        if inputs.known_revoked_cert_path:
            self._log(f"[DEBUG] Loading known-revoked certificate from: {inputs.known_revoked_cert_path}\n")
            try:
                revoked = _load_cert(inputs.known_revoked_cert_path)
                self._log(f"[DEBUG] Known-revoked certificate loaded successfully - Subject: {revoked.subject}\n")
            except Exception as exc:
                self._log(f"[DEBUG] Failed to load known-revoked certificate: {str(exc)}\n")
                results.append(self._err("Setup", "Load known-revoked certificate", str(exc)))
            
        if inputs.unknown_ca_cert_path:
            self._log(f"[DEBUG] Loading unknown-CA certificate from: {inputs.unknown_ca_cert_path}\n")
            try:
                unknown_ca = _load_cert(inputs.unknown_ca_cert_path)
                self._log(f"[DEBUG] Unknown-CA certificate loaded successfully - Subject: {unknown_ca.subject}\n")
            except Exception as exc:
                self._log(f"[DEBUG] Failed to load unknown-CA certificate: {str(exc)}\n")
                results.append(self._err("Setup", "Load unknown-CA certificate", str(exc)))

        # Choose sample cert for protocol/perf (prefer good -> revoked -> issuer self check)
        sample = good or revoked or issuer
        self._log(f"[DEBUG] Sample certificate selected for testing - Subject: {sample.subject}\n")

        # Protocol tests (requires a leaf cert ideally)
        if not test_categories or test_categories.get('ocsp_tests', True):
            self._log("[DEBUG] Starting OCSP protocol tests...\n")
            try:
                protocol_results = run_protocol_tests(inputs.ocsp_url, issuer, sample)
                self._log(f"[DEBUG] OCSP protocol tests completed - {len(protocol_results)} results\n")
                results.extend(protocol_results)
            except Exception as exc:
                self._log(f"[DEBUG] OCSP protocol tests failed: {str(exc)}\n")
                results.append(self._err("Protocol", "Run protocol tests", str(exc)))
        else:
            self._log("[DEBUG] OCSP protocol tests skipped (disabled)\n")

        # Status tests
        if not test_categories or test_categories.get('ocsp_tests', True):
            self._log("[DEBUG] Starting OCSP status tests...\n")
            try:
                status_results = run_status_tests(inputs.ocsp_url, issuer, good, revoked, unknown_ca)
                self._log(f"[DEBUG] OCSP status tests completed - {len(status_results)} results\n")
                results.extend(status_results)
            except Exception as exc:
                self._log(f"[DEBUG] OCSP status tests failed: {str(exc)}\n")
                results.append(self._err("Status", "Run status tests", str(exc)))
        else:
            self._log("[DEBUG] OCSP status tests skipped (disabled)\n")

        # Security tests
        if not test_categories or test_categories.get('ocsp_tests', True):
            self._log("[DEBUG] Starting OCSP security tests...\n")
            try:
                security_results = run_security_tests(inputs.ocsp_url, issuer, good or sample, inputs.client_sign_cert_path, inputs.client_sign_key_path, inputs.config)
                self._log(f"[DEBUG] OCSP security tests completed - {len(security_results)} results\n")
                results.extend(security_results)
            except Exception as exc:
                self._log(f"[DEBUG] OCSP security tests failed: {str(exc)}\n")
                results.append(self._err("Security", "Run security tests", str(exc)))
        else:
            self._log("[DEBUG] OCSP security tests skipped (disabled)\n")

        # Performance tests
        if not test_categories or test_categories.get('performance_tests', False):
            self._log("[DEBUG] Starting performance tests...\n")
            try:
                perf_results = run_perf_tests(inputs.ocsp_url, issuer, sample, inputs.latency_samples, inputs.enable_load_test, inputs.load_concurrency, inputs.load_requests)
                self._log(f"[DEBUG] Performance tests completed - {len(perf_results)} results\n")
                results.extend(perf_results)
            except Exception as exc:
                self._log(f"[DEBUG] Performance tests failed: {str(exc)}\n")
                results.append(self._err("Performance", "Run performance tests", str(exc)))
        else:
            self._log("[DEBUG] Performance tests skipped (disabled)\n")

        # CRL signature validation tests
        if not test_categories or test_categories.get('crl_tests', True):
            self._log("[DEBUG] Starting CRL tests...\n")
            try:
                crl_results = run_crl_tests(inputs.ocsp_url, issuer, good, revoked)
                self._log(f"[DEBUG] CRL tests completed - {len(crl_results)} results\n")
                results.extend(crl_results)
            except Exception as exc:
                self._log(f"[DEBUG] CRL tests failed: {str(exc)}\n")
                results.append(self._err("CRL", "Run CRL tests", str(exc)))
        else:
            self._log("[DEBUG] CRL tests skipped (disabled)\n")

        # Comprehensive CRL tests
        if not test_categories or test_categories.get('crl_tests', True):
            self._log("[DEBUG] Starting comprehensive CRL tests...\n")
            try:
                crl_comp_results = run_crl_comprehensive_tests(inputs.ocsp_url, issuer, good, revoked, inputs.crl_override_url)
                self._log(f"[DEBUG] Comprehensive CRL tests completed - {len(crl_comp_results)} results\n")
                results.extend(crl_comp_results)
            except Exception as exc:
                self._log(f"[DEBUG] Comprehensive CRL tests failed: {str(exc)}\n")
                results.append(self._err("CRL", "Run comprehensive CRL tests", str(exc)))
        else:
            self._log("[DEBUG] Comprehensive CRL tests skipped (disabled)\n")

        # IKEv2 placeholders
        if not test_categories or test_categories.get('ikev2_tests', False):
            self._log("[DEBUG] Starting IKEv2 tests...\n")
            try:
                ikev2_results = run_ikev2_tests()
                self._log(f"[DEBUG] IKEv2 tests completed - {len(ikev2_results)} results\n")
                results.extend(ikev2_results)
            except Exception as exc:
                self._log(f"[DEBUG] IKEv2 tests failed: {str(exc)}\n")
                results.append(self._err("IKEv2", "Run IKEv2 tests", str(exc)))
        else:
            self._log("[DEBUG] IKEv2 tests skipped (disabled)\n")

        # Federal PKI / Federal Bridge tests
        if test_categories and test_categories.get('federal_tests', False):
            self._log("[DEBUG] Starting Federal PKI tests...\n")
            try:
                federal_results = run_federal_tests(
                    inputs.ocsp_url,
                    inputs.issuer_path,
                    inputs.known_good_cert_path or inputs.known_revoked_cert_path,
                    config=inputs.config,
                    log_callback=self.log_callback,
                )
                self._log(f"[DEBUG] Federal PKI tests completed - {len(federal_results)} results\n")
                results.extend(federal_results)
            except Exception as exc:
                self._log(f"[DEBUG] Federal PKI tests failed: {str(exc)}\n")
                results.append(self._err("Federal PKI", "Run Federal PKI tests", str(exc)))
        else:
            self._log("[DEBUG] Federal PKI tests skipped (disabled)\n")

        # Certificate Path Validation tests
        if not test_categories or test_categories.get('path_validation_tests', True):
            self._log("[DEBUG] Starting certificate path validation tests...\n")
            try:
                # Prepare test inputs for path validation
                path_validation_inputs = {
                    'ocsp_url': inputs.ocsp_url,
                    'issuer_path': inputs.issuer_path,
                    'good_cert_path': inputs.known_good_cert_path,
                    'revoked_cert_path': inputs.known_revoked_cert_path,
                    'unknown_ca_cert_path': inputs.unknown_ca_cert_path,
                    'crl_override_url': inputs.crl_override_url,
                    'client_cert_path': inputs.client_sign_cert_path,
                    'client_key_path': inputs.client_sign_key_path,
                    'trust_anchor_path': inputs.trust_anchor_path,
                    'trust_anchor_type': inputs.trust_anchor_type,
                    'require_explicit_policy': inputs.require_explicit_policy,
                    'inhibit_policy_mapping': inputs.inhibit_policy_mapping
                }
                path_results = run_path_validation_tests(path_validation_inputs)
                self._log(f"[DEBUG] Certificate path validation tests completed - {len(path_results)} results\n")
                results.extend(path_results)
            except Exception as exc:
                self._log(f"[DEBUG] Certificate path validation tests failed: {str(exc)}\n")
                results.append(self._err("Path Validation", "Run certificate path validation tests", str(exc)))
        else:
            self._log("[DEBUG] Certificate path validation tests skipped (disabled)\n")

        self._log(f"[DEBUG] TestRunner.run_all() completed - Total results: {len(results)}\n")
        self._log(f"[DEBUG] Test execution summary:\n")
        self._log(f"[DEBUG] - Protocol tests: {len([r for r in results if r.category == 'Protocol'])} results\n")
        self._log(f"[DEBUG] - Status tests: {len([r for r in results if r.category == 'Status'])} results\n")
        self._log(f"[DEBUG] - Security tests: {len([r for r in results if r.category == 'Security'])} results\n")
        self._log(f"[DEBUG] - Performance tests: {len([r for r in results if r.category == 'Performance'])} results\n")
        self._log(f"[DEBUG] - CRL tests: {len([r for r in results if r.category == 'CRL'])} results\n")
        self._log(f"[DEBUG] - IKEv2 tests: {len([r for r in results if r.category == 'IKEv2'])} results\n")
        self._log(f"[DEBUG] - Path Validation tests: {len([r for r in results if r.category == 'Path Validation'])} results\n")
        return results

    @staticmethod
    def _err(category: str, name: str, msg: str) -> TestCaseResult:
        r = TestCaseResult(id=str(uuid.uuid4()), category=category, name=name, status=TestStatus.ERROR, message=msg)
        r.end()
        return r
    
    @staticmethod
    def _create_skip_result(category: str, name: str, msg: str) -> TestCaseResult:
        r = TestCaseResult(id=str(uuid.uuid4()), category=category, name=name, status=TestStatus.SKIP, message=msg)
        r.end()
        return r