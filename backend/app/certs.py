"""Certificate parsing, validation and metadata extraction for uploads."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from .schemas import CertExtensions, CertMetadata


class CertificateError(ValueError):
    """Uploaded data is not a usable certificate."""


def load_certificate(data: bytes) -> x509.Certificate:
    """Load a single PEM or DER certificate, with useful error messages."""
    if not data or not data.strip():
        raise CertificateError("Uploaded certificate file is empty")
    if b"PRIVATE KEY" in data:
        raise CertificateError("File contains private key material, not a certificate")
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        pass
    try:
        return x509.load_der_x509_certificate(data)
    except Exception:
        raise CertificateError(
            "File is not a valid PEM or DER encoded X.509 certificate"
        ) from None


def load_certificate_chain(data: bytes) -> List[x509.Certificate]:
    """Load one or more certificates (PEM bundle, single PEM, or single DER)."""
    if not data or not data.strip():
        raise CertificateError("Uploaded certificate file is empty")
    if b"BEGIN CERTIFICATE" in data:
        try:
            certs = x509.load_pem_x509_certificates(data)
        except Exception as exc:
            raise CertificateError(f"Invalid PEM certificate bundle: {exc}") from None
        if not certs:
            raise CertificateError("PEM bundle contains no certificates")
        return certs
    return [load_certificate(data)]


def load_certificates_any(data: bytes) -> List[x509.Certificate]:
    """Load certificates from PEM/DER/PEM-bundle or a PKCS#7 (.p7c/.p7b)
    bundle — the formats CA repositories publish (FPKI AIA files are P7C)."""
    try:
        return load_certificate_chain(data)
    except CertificateError:
        pass
    try:
        from asn1crypto import cms

        content_info = cms.ContentInfo.load(data)
        if content_info["content_type"].dotted != "1.2.840.113549.1.7.2":
            raise ValueError("not a PKCS#7 SignedData structure")
        certificates = content_info["content"]["certificates"]
        certs = [x509.load_der_x509_certificate(c.dump()) for c in certificates or []]
        if not certs:
            raise ValueError("PKCS#7 bundle contains no certificates")
        return certs
    except Exception:
        raise CertificateError(
            "Data is not a valid X.509 certificate, PEM bundle, or PKCS#7 certificate bundle"
        ) from None


def to_pem(certs: List[x509.Certificate]) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def validate_private_key_pem(data: bytes) -> None:
    """Sanity-check an uploaded TLS client key without ever logging content."""
    if not data or not data.strip():
        raise CertificateError("Uploaded key file is empty")
    if b"PRIVATE KEY" not in data:
        raise CertificateError("Client key must be a PEM encoded private key")


def _key_algorithm(cert: x509.Certificate) -> str:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC-{key.curve.name}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(key, dsa.DSAPublicKey):
        return f"DSA-{key.key_size}"
    return type(key).__name__


def _hex_keyid(value: Optional[bytes]) -> Optional[str]:
    if not value:
        return None
    return ":".join(f"{b:02x}" for b in value)


def extract_metadata(cert: x509.Certificate) -> CertMetadata:
    ski = aki = None
    aia_ocsp: List[str] = []
    aia_issuers: List[str] = []
    cdps: List[str] = []
    is_ca = False

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        ski = _hex_keyid(ext.value.digest)
    except x509.ExtensionNotFound:
        pass
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        aki = _hex_keyid(ext.value.key_identifier)
    except x509.ExtensionNotFound:
        pass
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        for desc in aia:
            if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                if desc.access_method == AuthorityInformationAccessOID.OCSP:
                    aia_ocsp.append(desc.access_location.value)
                elif desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    aia_issuers.append(desc.access_location.value)
    except x509.ExtensionNotFound:
        pass
    try:
        cdp = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        for dp in cdp:
            for name in dp.full_name or []:
                if isinstance(name, x509.UniformResourceIdentifier):
                    cdps.append(name.value)
    except x509.ExtensionNotFound:
        pass
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        is_ca = bc.ca
    except x509.ExtensionNotFound:
        pass

    try:
        sig_name = cert.signature_algorithm_oid._name  # noqa: SLF001 - best-effort display name
    except Exception:
        sig_name = cert.signature_algorithm_oid.dotted_string

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    return CertMetadata(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=hex(cert.serial_number),
        not_before=not_before,
        not_after=not_after,
        key_algorithm=_key_algorithm(cert),
        signature_algorithm=sig_name,
        signature_algorithm_oid=cert.signature_algorithm_oid.dotted_string,
        ski=ski,
        aki=aki,
        aia_ocsp_urls=aia_ocsp,
        aia_ca_issuers=aia_issuers,
        crl_distribution_points=cdps,
        is_ca=is_ca,
        expired=not_after < datetime.now(timezone.utc),
        self_signed=cert.subject == cert.issuer,
    )


def _oid_label(oid: x509.ObjectIdentifier) -> str:
    """Human name + dotted OID when a friendly name is known, else the OID."""
    name = getattr(oid, "_name", None)
    if name and name != "Unknown OID":
        return f"{name} ({oid.dotted_string})"
    return oid.dotted_string


def _general_name(gn: x509.GeneralName) -> str:
    if isinstance(gn, x509.DNSName):
        return f"DNS:{gn.value}"
    if isinstance(gn, x509.RFC822Name):
        return f"email:{gn.value}"
    if isinstance(gn, x509.UniformResourceIdentifier):
        return f"URI:{gn.value}"
    if isinstance(gn, x509.IPAddress):
        return f"IP:{gn.value}"
    if isinstance(gn, x509.DirectoryName):
        return f"DirName:{gn.value.rfc4514_string()}"
    if isinstance(gn, x509.RegisteredID):
        return f"RID:{gn.value.dotted_string}"
    try:
        return str(gn.value)
    except Exception:
        return str(gn)


def certificate_extensions(cert: x509.Certificate) -> CertExtensions:
    """Extract the commonly-inspected X.509 v3 extensions for display: SAN, key
    usage, extended key usage, certificate policies, AIA, CRL distribution
    points, and the subject/authority key identifiers. Missing extensions yield
    empty values rather than errors."""
    ext = cert.extensions

    def _get(oid):
        try:
            return ext.get_extension_for_oid(oid).value
        except x509.ExtensionNotFound:
            return None

    san: List[str] = []
    san_val = _get(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if san_val is not None:
        san = [_general_name(gn) for gn in san_val]

    key_usage: List[str] = []
    ku = _get(ExtensionOID.KEY_USAGE)
    if ku is not None:
        for attr, label in (
            ("digital_signature", "digitalSignature"),
            ("content_commitment", "contentCommitment (nonRepudiation)"),
            ("key_encipherment", "keyEncipherment"),
            ("data_encipherment", "dataEncipherment"),
            ("key_agreement", "keyAgreement"),
            ("key_cert_sign", "keyCertSign"),
            ("crl_sign", "cRLSign"),
        ):
            if getattr(ku, attr, False):
                key_usage.append(label)
        if ku.key_agreement:  # encipher/decipher_only only valid with key_agreement
            if ku.encipher_only:
                key_usage.append("encipherOnly")
            if ku.decipher_only:
                key_usage.append("decipherOnly")

    eku: List[str] = []
    eku_val = _get(ExtensionOID.EXTENDED_KEY_USAGE)
    if eku_val is not None:
        eku = [_oid_label(oid) for oid in eku_val]

    policies: List[str] = []
    pol_val = _get(ExtensionOID.CERTIFICATE_POLICIES)
    if pol_val is not None:
        policies = [_oid_label(pi.policy_identifier) for pi in pol_val]

    aia_ocsp: List[str] = []
    aia_issuers: List[str] = []
    aia = _get(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    if aia is not None:
        for desc in aia:
            if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                if desc.access_method == AuthorityInformationAccessOID.OCSP:
                    aia_ocsp.append(desc.access_location.value)
                elif desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    aia_issuers.append(desc.access_location.value)

    cdps: List[str] = []
    cdp = _get(ExtensionOID.CRL_DISTRIBUTION_POINTS)
    if cdp is not None:
        for dp in cdp:
            for name in dp.full_name or []:
                if isinstance(name, x509.UniformResourceIdentifier):
                    cdps.append(name.value)

    ski = aki = None
    ski_val = _get(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    if ski_val is not None:
        ski = _hex_keyid(ski_val.digest)
    aki_val = _get(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    if aki_val is not None:
        aki = _hex_keyid(aki_val.key_identifier)

    return CertExtensions(
        subject_alt_names=san,
        key_usage=key_usage,
        extended_key_usage=eku,
        certificate_policies=policies,
        aia_ocsp_urls=aia_ocsp,
        aia_ca_issuers=aia_issuers,
        crl_distribution_points=cdps,
        subject_key_identifier=ski,
        authority_key_identifier=aki,
    )
