# Certificate Path Validation Test Suite

This document describes the comprehensive certificate path validation test suite implemented in the OCSP Testing Tool, based on RFC 5280 and Federal Bridge PKI requirements.

## Overview

The certificate path validation test suite provides systematic testing of all conditions and constraints defined in RFC 5280, with extensions for Federal Bridge PKI environments. It implements a robust, automated test suite that validates certificate chains according to the core standard.

## Test Categories

### 1. Foundational Path Construction and Signature Tests

These tests verify the basic mechanical checks for every certificate in the chain.

| Test ID | Test Case | Expected Result | RFC 5280 Reference |
|---------|-----------|-----------------|-------------------|
| 1.01 | Valid Path (Success): End-entity → Intermediate CA → Trusted Root | PASS | Baseline Test (RFC 5280 Sec. 6) |
| 1.02 | Invalid Signature (EE): EE certificate's signature cannot be verified by its issuer | FAIL | Core Signature Check |
| 1.03 | Invalid Signature (Intermediate): An Intermediate CA certificate's signature is invalid | FAIL | Core Signature Check (Mismatched Key) |
| 1.04 | Issuer/Subject Mismatch: The Issuer DN of the child cert does not match the Subject DN of the parent cert | FAIL | Name Chaining Failure |
| 1.05 | Self-Signed Intermediate: An intermediate CA certificate is accidentally self-signed | FAIL | Path ends prematurely at non-trust anchor |
| 1.06 | Missing Chain Element: The path is missing an intermediate certificate | FAIL | Path Discovery/Chaining Failure |

### 2. Certificate Validity Period (Time) Tests

These cases focus specifically on the notBefore and notAfter fields in certificates and CRL/OCSP responses.

| Test ID | Test Case | Expected Result | RFC 5280 Reference |
|---------|-----------|-----------------|-------------------|
| 2.01 | notAfter Expired (EE): Validation time is one second after the EE certificate's notAfter | FAIL | EE Certificate Expired |
| 2.02 | notAfter Expired (Intermediate): Validation time is one second after an intermediate CA's notAfter | FAIL | CA Certificate Expired |
| 2.03 | notBefore Not Yet Valid (EE): Validation time is one second before the EE certificate's notBefore | FAIL | EE Certificate Not Yet Valid |
| 2.04 | Revocation Status Expired: The CRL has expired (its nextUpdate is in the past) | FAIL (Soft-Fail/Warning) | Must retrieve fresh revocation data |
| 2.05 | Expired → Valid → Expired Path: A chain with a mix of expired and valid certs | FAIL | Any expired certificate fails validation |
| 2.06 | Time Travel Test (Near Expiry): System time is set to T-minus 1 day from EE expiration | PASS | Test for automated monitoring/warnings |

### 3. Revocation Status Tests

These tests check all possible outcomes of the revocation check using both CRLs and OCSP.

| Test ID | Test Case | Expected Result | RFC 5280 Reference |
|---------|-----------|-----------------|-------------------|
| 3.01 | Revoked (EE) in Fresh CRL: EE serial number is on the most recent CRL | FAIL | CRL Revoked Status |
| 3.02 | Revoked (Intermediate) in Fresh CRL: Intermediate CA serial number is on the most recent CRL | FAIL | CA Certificate Revoked |
| 3.03 | Revoked (EE) by OCSP: OCSP response is revoked status | FAIL | OCSP Revoked Status |
| 3.04 | OCSP Status Unknown: OCSP responder returns an explicit unknown status | FAIL (or Policy-Based) | Implementation policy must define success/fail |
| 3.05 | CRL Missing: No Distribution Point (CDP) found or URL is unreachable | FAIL (or Policy-Based) | Failure to acquire revocation information |
| 3.06 | OCSP Signed by Unauthorized Key: OCSP response is signed by a key not authorized in the certificate's id-ad-ocsp extension | FAIL | OCSP Signature Authorization Check |

### 4. Constraint and Extension Tests (RFC 5280 Sec. 4)

These tests check the critical extensions that limit the certificate's allowed usage or subject scope.

| Test ID | Test Case | Expected Result | RFC 5280 Reference |
|---------|-----------|-----------------|-------------------|
| 4.01 | Basic Constraints Violation: Intermediate CA cert has cA = false | FAIL | CA flag must be true for a CA cert |
| 4.02 | Path Length Constraint Violation: A CA certificate's pathLenConstraint is set to 1, but the path has 2 intermediate CAs | FAIL | Exceeds Max Path Length |
| 4.03 | Key Usage Violation (Intermediate): CA cert is missing the keyCertSign bit in the Key Usage extension | FAIL | Must be enabled for a signing CA |
| 4.04 | Name Constraints (Permitted): EE cert subject name is outside the permitted DNS name subtree defined in a CA | FAIL | Name Constraints Enforcement (Sec. 4.2.10) |
| 4.05 | Name Constraints (Excluded): EE cert subject name is inside the excluded DNS name subtree defined in a CA | FAIL | Name Constraints Enforcement (Sec. 4.2.10) |
| 4.06 | Critical Extension Unrecognized: A CA certificate has an unknown extension marked Critical | FAIL | RFC 5280 requirement: Must reject unrecognized critical extensions |
| 4.07 | Critical Extension Recognized and Validated: A recognized extension (e.g., Key Usage) is present and correctly processed | PASS | Normal processing of a critical extension |

### 5. Federal Bridge PKI (Bridged and Policy) Tests

These cases address the complexity of a bridged environment, particularly policy management and the use of the Federal Bridge Certification Authority (FBCA).

| Test ID | Test Case | Expected Result | FBCP / RFC 5280 Reference |
|---------|-----------|-----------------|---------------------------|
| 5.01 | Successful Policy Mapping: Path requires Policy A; intermediate CA maps Policy A → Policy B; EE cert asserts Policy B | PASS | Policy Mapping (Sec. 4.2.4) |
| 5.02 | Required Explicit Policy Violation: A CA cert requires an explicit policy, but the final EE cert contains anyPolicy | FAIL | Policy Constraints (Sec. 4.2.11) |
| 5.03 | Inhibit Policy Mapping: A CA cert sets inhibitPolicyMapping to 0, and the next CA attempts to map a policy | FAIL | Policy Mapping Blocked (Sec. 4.2.11) |
| 5.04 | Policy Not Asserted: The end-entity certificate does not contain any of the required or acceptable Policy OIDs | FAIL | Required Policy Not Present |
| 5.05 | P7C Path Discovery Failure: The AIA URL pointing to the .p7c file for an intermediate CA is unreachable (e.g., HTTP 404) | FAIL | Path Discovery Failure (FBCA Interoperability) |
| 5.06 | Bridged Policy Check: A path crosses the FBCA, and the policy OID asserted by the cross-certified partner CA is not correctly mapped to an approved Federal Policy OID | FAIL | FBCP Conformance Check |

## Implementation Details

### Core Components

1. **PathValidationTestSuite**: Main test suite class that orchestrates all path validation tests
2. **CertificatePathValidator**: Core validation engine implementing RFC 5280 algorithms
3. **ValidationResult**: Data structure containing validation outcomes and detailed information
4. **CertificateChain**: Data structure representing certificate chains for testing

### Key Features

- **Comprehensive Coverage**: Tests all major RFC 5280 validation requirements
- **Federal Bridge PKI Support**: Specialized tests for bridged PKI environments with P7C file processing
- **Detailed Reporting**: Each test provides detailed results with RFC references and troubleshooting information
- **Error Handling**: Robust error handling with detailed error messages and debugging information
- **Extensible Design**: Easy to add new test cases and validation rules
- **AIA Discovery**: Automatic certificate chain discovery using Authority Information Access URLs
- **P7C Processing**: Support for PKCS#7 certificate bundles used in Federal Bridge PKI

### Implementation Status

#### Fully Implemented Tests
- **1.01**: Valid Path (Success) - Complete with AIA-based chain discovery
- **1.02**: Invalid Signature (EE) - Complete with cryptographic signature verification
- **1.03**: Invalid Signature (Intermediate) - Complete with intermediate CA validation
- **1.04**: Issuer/Subject Mismatch - Complete with DN comparison validation
- **2.01**: notAfter Expired (EE) - Complete with timezone-aware validation
- **2.04**: Revocation Status Expired - Placeholder implementation
- **3.01**: Revoked (EE) in Fresh CRL - Placeholder implementation
- **3.03**: Revoked (EE) by OCSP - Placeholder implementation
- **4.01**: Basic Constraints Violation - Complete with CA flag validation
- **4.02**: Path Length Constraint Violation - Complete with path length analysis
- **5.01**: Successful Policy Mapping - Complete with policy extension analysis
- **5.02**: Required Explicit Policy Violation - Placeholder implementation

#### Advanced Features Implemented
- **Certificate Chain Discovery**: Automatic discovery using AIA URLs
- **P7C File Processing**: Support for PKCS#7 certificate bundles
- **Federal Bridge PKI Integration**: Specialized handling for Federal Bridge environments
- **Comprehensive Error Reporting**: Detailed error messages with troubleshooting steps
- **Timezone-Aware Validation**: Proper handling of certificate validity periods

### Usage

#### GUI Usage
1. Open the OCSP Testing Tool
2. Configure certificate paths (Issuer, Good Certificate, etc.)
3. Click "Path Validation" button
4. Review results in the test results tree

#### Programmatic Usage
```python
from ocsp_tester.tests_path_validation import run_path_validation_tests

test_inputs = {
    'ocsp_url': 'http://ocsp.example.com/ocsp',
    'issuer_path': '/path/to/issuer.pem',
    'good_cert_path': '/path/to/good_cert.pem',
    'crl_override_url': 'http://crl.example.com/crl.crl'
}

results = run_path_validation_tests(test_inputs)
```

### Test Results

Each test produces a `TestCaseResult` object containing:
- **Test ID**: Unique identifier for the test
- **Category**: Test category (Foundational, Validity Period, etc.)
- **Name**: Human-readable test name
- **Status**: PASS, FAIL, ERROR, or SKIP
- **Message**: Detailed result message
- **Details**: Additional technical details and RFC references

### Dependencies

- **cryptography**: For certificate parsing and cryptographic operations
- **requests**: For HTTP-based revocation checking
- **OpenSSL**: For advanced certificate operations and CRL processing

### Future Enhancements

- **Time-based Testing**: Chaos engineering techniques for certificate expiration testing
- **Performance Testing**: Load testing for large certificate chains
- **Advanced Policy Testing**: More sophisticated Federal Bridge policy validation
- **Cross-platform Testing**: Enhanced support for different PKI environments

## References

- RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
- Federal Bridge Certification Authority (FBCA) Certificate Policy
- NIST Special Publication 800-57: Recommendation for Key Management
- Common PKI Certificate Policy Framework

## Support

For questions or issues with the path validation test suite, please refer to the main OCSP Testing Tool documentation or contact the development team.
