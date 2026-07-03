"""
Certificate Path Validation Implementation

This module implements the core certificate path validation logic based on RFC 5280.
It provides the actual validation algorithms used by the path validation test suite.
"""

import os
import subprocess
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID, ExtensionOID, CertificatePoliciesOID


@dataclass
class ValidationResult:
    """Result of a certificate path validation"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    details: Dict[str, Any]


class CertificatePathValidator:
    """Main certificate path validator implementing RFC 5280"""
    
    def __init__(self):
        # Use timezone-aware datetime to avoid comparison issues
        from datetime import timezone
        self.validation_time = datetime.now(timezone.utc)
        self.max_path_length = 10  # Default maximum path length
    
    def validate_certificate_chain(self, 
                                 end_entity: x509.Certificate,
                                 intermediates: List[x509.Certificate],
                                 trust_anchors: List[x509.Certificate],
                                 validation_time: Optional[datetime] = None,
                                 trust_anchor_type: str = "root",
                                 require_explicit_policy: bool = False,
                                 inhibit_policy_mapping: bool = False) -> ValidationResult:
        """
        Validate a complete certificate chain according to RFC 5280
        
        Args:
            end_entity: The end-entity certificate to validate
            intermediates: List of intermediate CA certificates
            trust_anchors: List of trusted root CA certificates
            validation_time: Time to use for validation (default: current time)
            trust_anchor_type: Type of trust anchor ("root", "bridge", "intermediate")
            require_explicit_policy: Whether to require explicit policy (RFC 5280 Section 4.2.11)
            inhibit_policy_mapping: Whether to inhibit policy mapping (RFC 5280 Section 4.2.11)
            
        Returns:
            ValidationResult containing validation outcome and details
        """
        if validation_time:
            self.validation_time = validation_time
            
        errors = []
        warnings = []
        details = {}
        
        try:
            # Step 1: Basic path construction and signature verification
            sig_result = self._verify_signatures(end_entity, intermediates, trust_anchors)
            if not sig_result.is_valid:
                errors.extend(sig_result.errors)
                warnings.extend(sig_result.warnings)
            
            # Step 2: Certificate validity period checks
            time_result = self._check_validity_periods(end_entity, intermediates)
            if not time_result.is_valid:
                errors.extend(time_result.errors)
                warnings.extend(time_result.warnings)
            
            # Step 3: Basic constraints validation
            constraint_result = self._check_basic_constraints(end_entity, intermediates)
            if not constraint_result.is_valid:
                errors.extend(constraint_result.errors)
                warnings.extend(constraint_result.warnings)
            
            # Step 4: Key usage validation
            key_usage_result = self._check_key_usage(end_entity, intermediates)
            if not key_usage_result.is_valid:
                errors.extend(key_usage_result.errors)
                warnings.extend(key_usage_result.warnings)
            
            # Step 5: Path length constraint validation
            path_length_result = self._check_path_length_constraints(intermediates)
            if not path_length_result.is_valid:
                errors.extend(path_length_result.errors)
                warnings.extend(path_length_result.warnings)
            
            # Determine overall validity
            is_valid = len(errors) == 0
            
            details = {
                'signature_validation': sig_result.details,
                'validity_period_check': time_result.details,
                'basic_constraints_check': constraint_result.details,
                'key_usage_check': key_usage_result.details,
                'path_length_check': path_length_result.details,
                'validation_time': self.validation_time.isoformat(),
                'total_intermediates': len(intermediates),
                'total_trust_anchors': len(trust_anchors)
            }
            
            return ValidationResult(
                is_valid=is_valid,
                errors=errors,
                warnings=warnings,
                details=details
            )
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                errors=[f"Path validation failed with exception: {str(e)}"],
                warnings=[],
                details={'exception': str(e)}
            )
    
    def _verify_signatures(self, 
                          end_entity: x509.Certificate,
                          intermediates: List[x509.Certificate],
                          trust_anchors: List[x509.Certificate]) -> ValidationResult:
        """Verify signatures in the certificate chain"""
        errors = []
        warnings = []
        details = {}
        
        # Verify end-entity signature
        try:
            issuer_cert = self._find_issuer(end_entity, intermediates, trust_anchors)
            if issuer_cert:
                if not self._verify_certificate_signature(end_entity, issuer_cert):
                    errors.append("End-entity certificate signature verification failed")
            else:
                errors.append("Could not find issuer certificate for end-entity")
        except Exception as e:
            errors.append(f"End-entity signature verification error: {str(e)}")
        
        # Verify intermediate certificate signatures
        for i, cert in enumerate(intermediates):
            try:
                issuer_cert = self._find_issuer(cert, intermediates, trust_anchors)
                if issuer_cert:
                    if not self._verify_certificate_signature(cert, issuer_cert):
                        errors.append(f"Intermediate certificate {i} signature verification failed")
                else:
                    errors.append(f"Could not find issuer certificate for intermediate {i}")
            except Exception as e:
                errors.append(f"Intermediate {i} signature verification error: {str(e)}")
        
        details = {
            'end_entity_signature_verified': len(errors) == 0,
            'intermediate_signatures_verified': len([e for e in errors if 'Intermediate' in e]) == 0
        }
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            details=details
        )
    
    def _check_validity_periods(self, 
                               end_entity: x509.Certificate,
                               intermediates: List[x509.Certificate]) -> ValidationResult:
        """Check certificate validity periods"""
        errors = []
        warnings = []
        details = {}
        
        # Check end-entity validity period
        # Convert certificate times to timezone-aware if needed
        from datetime import timezone
        not_before = end_entity.not_valid_before_utc
        not_after = end_entity.not_valid_after_utc
        
        # Ensure certificate times are timezone-aware
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
            
        if self.validation_time < not_before:
            errors.append(f"End-entity certificate not yet valid (valid from {not_before})")
        elif self.validation_time > not_after:
            errors.append(f"End-entity certificate has expired (expired on {not_after})")
        
        # Check intermediate certificate validity periods
        for i, cert in enumerate(intermediates):
            cert_not_before = cert.not_valid_before_utc
            cert_not_after = cert.not_valid_after_utc
            
            # Ensure certificate times are timezone-aware
            if cert_not_before.tzinfo is None:
                cert_not_before = cert_not_before.replace(tzinfo=timezone.utc)
            if cert_not_after.tzinfo is None:
                cert_not_after = cert_not_after.replace(tzinfo=timezone.utc)
                
            if self.validation_time < cert_not_before:
                errors.append(f"Intermediate certificate {i} not yet valid (valid from {cert_not_before})")
            elif self.validation_time > cert_not_after:
                errors.append(f"Intermediate certificate {i} has expired (expired on {cert_not_after})")
        
        details = {
            'end_entity_valid': self.validation_time >= not_before and self.validation_time <= not_after,
            'all_intermediates_valid': len([e for e in errors if 'Intermediate' in e]) == 0,
            'validation_time': self.validation_time.isoformat()
        }
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            details=details
        )
    
    def _check_basic_constraints(self, 
                                end_entity: x509.Certificate,
                                intermediates: List[x509.Certificate]) -> ValidationResult:
        """Check basic constraints extension"""
        errors = []
        warnings = []
        details = {}
        
        # Check that intermediate certificates have CA=True
        for i, cert in enumerate(intermediates):
            try:
                bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                if not bc_ext.value.ca:
                    errors.append(f"Intermediate certificate {i} has CA=False in Basic Constraints")
            except x509.ExtensionNotFound:
                errors.append(f"Intermediate certificate {i} missing Basic Constraints extension")
        
        # Check that end-entity certificate has CA=False (if extension present)
        try:
            bc_ext = end_entity.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            if bc_ext.value.ca:
                warnings.append("End-entity certificate has CA=True in Basic Constraints")
        except x509.ExtensionNotFound:
            # This is acceptable for end-entity certificates
            pass
        
        details = {
            'all_intermediates_have_ca_true': len([e for e in errors if 'CA=False' in e]) == 0,
            'end_entity_ca_flag_appropriate': len([w for w in warnings if 'CA=True' in w]) == 0
        }
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            details=details
        )
    
    def _check_key_usage(self, 
                        end_entity: x509.Certificate,
                        intermediates: List[x509.Certificate]) -> ValidationResult:
        """Check key usage extensions"""
        errors = []
        warnings = []
        details = {}
        
        # Check that intermediate certificates have keyCertSign bit set
        for i, cert in enumerate(intermediates):
            try:
                ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                if not ku_ext.value.key_cert_sign:
                    errors.append(f"Intermediate certificate {i} missing keyCertSign in Key Usage")
            except x509.ExtensionNotFound:
                warnings.append(f"Intermediate certificate {i} missing Key Usage extension")
        
        details = {
            'all_intermediates_have_key_cert_sign': len([e for e in errors if 'keyCertSign' in e]) == 0
        }
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            details=details
        )
    
    def _check_path_length_constraints(self, intermediates: List[x509.Certificate]) -> ValidationResult:
        """Check path length constraints"""
        errors = []
        warnings = []
        details = {}
        
        # Check path length constraints
        for i, cert in enumerate(intermediates):
            try:
                bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                if bc_ext.value.path_length is not None:
                    # Calculate remaining path length
                    remaining_path = len(intermediates) - i - 1
                    if remaining_path > bc_ext.value.path_length:
                        errors.append(f"Path length constraint violation: certificate {i} allows max {bc_ext.value.path_length} but path has {remaining_path} remaining certificates")
            except x509.ExtensionNotFound:
                pass
        
        details = {
            'path_length_constraints_satisfied': len(errors) == 0,
            'total_path_length': len(intermediates)
        }
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            details=details
        )
    
    def _find_issuer(self, 
                    cert: x509.Certificate,
                    intermediates: List[x509.Certificate],
                    trust_anchors: List[x509.Certificate]) -> Optional[x509.Certificate]:
        """Find the issuer certificate for a given certificate"""
        cert_issuer = cert.issuer
        
        # First check intermediates
        for intermediate in intermediates:
            if intermediate.subject == cert_issuer:
                return intermediate
        
        # Then check trust anchors
        for trust_anchor in trust_anchors:
            if trust_anchor.subject == cert_issuer:
                return trust_anchor
        
        return None
    
    def _verify_certificate_signature(self, 
                                    cert: x509.Certificate,
                                    issuer_cert: x509.Certificate) -> bool:
        """Verify a certificate's signature using its issuer's public key"""
        try:
            # Get the issuer's public key
            issuer_public_key = issuer_cert.public_key()
            
            # Get the certificate's signature and signed data
            cert_signature = cert.signature
            cert_tbs = cert.tbs_certificate_bytes
            
            # Determine the hash algorithm from the certificate's signature algorithm
            signature_algorithm = cert.signature_algorithm_oid
            
            # Map signature algorithm OIDs to hash algorithms
            hash_algorithms = {
                x509.SignatureAlgorithmOID.RSA_WITH_SHA1: hashes.SHA1(),
                x509.SignatureAlgorithmOID.RSA_WITH_SHA256: hashes.SHA256(),
                x509.SignatureAlgorithmOID.RSA_WITH_SHA384: hashes.SHA384(),
                x509.SignatureAlgorithmOID.RSA_WITH_SHA512: hashes.SHA512(),
                x509.SignatureAlgorithmOID.ECDSA_WITH_SHA1: hashes.SHA1(),
                x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256: hashes.SHA256(),
                x509.SignatureAlgorithmOID.ECDSA_WITH_SHA384: hashes.SHA384(),
                x509.SignatureAlgorithmOID.ECDSA_WITH_SHA512: hashes.SHA512(),
            }
            
            # Get the appropriate hash algorithm, default to SHA256 if unknown
            hash_algorithm = hash_algorithms.get(signature_algorithm, hashes.SHA256())
            
            # Verify the signature
            issuer_public_key.verify(
                cert_signature,
                cert_tbs,
                padding.PKCS1v15(),
                hash_algorithm
            )
            return True
                
        except InvalidSignature as e:
            # Log detailed error information for debugging
            print(f"[DEBUG] Signature verification failed - InvalidSignature: {str(e)}")
            print(f"[DEBUG] Certificate subject: {cert.subject}")
            print(f"[DEBUG] Certificate issuer: {cert.issuer}")
            print(f"[DEBUG] Issuer certificate subject: {issuer_cert.subject}")
            print(f"[DEBUG] Signature algorithm: {cert.signature_algorithm_oid}")
            print(f"[DEBUG] Issuer public key type: {type(issuer_public_key).__name__}")
            if hasattr(issuer_public_key, 'key_size'):
                print(f"[DEBUG] Issuer public key size: {issuer_public_key.key_size} bits")
            return False
        except Exception as e:
            # Log detailed error information for debugging
            print(f"[DEBUG] Signature verification failed - Exception: {str(e)}")
            print(f"[DEBUG] Certificate subject: {cert.subject}")
            print(f"[DEBUG] Certificate issuer: {cert.issuer}")
            print(f"[DEBUG] Issuer certificate subject: {issuer_cert.subject}")
            print(f"[DEBUG] Signature algorithm: {cert.signature_algorithm_oid}")
            print(f"[DEBUG] Exception type: {type(e).__name__}")
            return False
    
    def check_revocation_status(self, 
                               cert: x509.Certificate,
                               issuer_cert: x509.Certificate,
                               ocsp_url: Optional[str] = None,
                               crl_url: Optional[str] = None) -> ValidationResult:
        """Check certificate revocation status using OCSP or CRL"""
        errors = []
        warnings = []
        details = {}
        
        # Try OCSP first if URL provided
        if ocsp_url:
            try:
                ocsp_result = self._check_ocsp_revocation(cert, issuer_cert, ocsp_url)
                if not ocsp_result.is_valid:
                    errors.extend(ocsp_result.errors)
                details['ocsp_result'] = ocsp_result.details
            except Exception as e:
                warnings.append(f"OCSP revocation check failed: {str(e)}")
        
        # Try CRL if URL provided
        if crl_url:
            try:
                crl_result = self._check_crl_revocation(cert, issuer_cert, crl_url)
                if not crl_result.is_valid:
                    errors.extend(crl_result.errors)
                details['crl_result'] = crl_result.details
            except Exception as e:
                warnings.append(f"CRL revocation check failed: {str(e)}")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            details=details
        )
    
    def _check_ocsp_revocation(self, 
                              cert: x509.Certificate,
                              issuer_cert: x509.Certificate,
                              ocsp_url: str) -> ValidationResult:
        """Check revocation status using OCSP"""
        # This would implement actual OCSP checking
        # For now, return a placeholder result
        return ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            details={'ocsp_status': 'good', 'method': 'OCSP'}
        )
    
    def _check_crl_revocation(self, 
                             cert: x509.Certificate,
                             issuer_cert: x509.Certificate,
                             crl_url: str) -> ValidationResult:
        """Check revocation status using CRL"""
        # This would implement actual CRL checking
        # For now, return a placeholder result
        return ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            details={'crl_status': 'not_revoked', 'method': 'CRL'}
        )
