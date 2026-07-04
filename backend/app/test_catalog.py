"""Static catalog of the individual tests each engine category can run.

The catalog is the source of truth for fine-grained test selection: the UI
renders it, run configurations reference tests by their exact name, and the
worker restricts execution to the selected names via
``ocsp_tester.selection``.

Names must match the ``TestCaseResult.name`` literals in the engine modules.
Tests that produce a dynamic suffix at runtime (e.g. one result per supplied
CRL URL) are listed by their stable prefix and flagged ``dynamic``.
"""

from __future__ import annotations

from typing import Dict, List, Optional, TypedDict


class CatalogTest(TypedDict):
    name: str
    description: str
    dynamic: bool
    scope: str  # what the test exercises: ocsp | crl | crl+ocsp | path | ikev2


def _t(name: str, description: str, dynamic: bool = False, scope: str = "ocsp") -> CatalogTest:
    return {"name": name, "description": description, "dynamic": dynamic, "scope": scope}


# Keyed by the RunConfig category keys (schemas.CATEGORY_KEYS).
TEST_CATALOG: Dict[str, List[CatalogTest]] = {
    "protocol": [
        _t("HTTP GET transport", "Responder accepts RFC 6960 base64 GET requests"),
        _t("HTTP POST transport", "Responder accepts DER POST requests"),
        _t(
            "DER encoding and basic response fields",
            "Response parses as DER with version, producedAt, responderID and signature algorithm present",
        ),
        _t("CertID SHA-1 for issuer hashes", "Responder accepts SHA-1 CertID hashes"),
        _t("Serial number handling", "Serial number formats are handled consistently"),
    ],
    "status": [
        _t("Known valid certificate returns good", "Known-good leaf is reported as good"),
        _t("Known revoked certificate returns revoked", "Known-revoked leaf is reported as revoked"),
        _t("Unknown CA returns unknown", "Certificate from an unknown CA is reported unknown/unauthorized"),
        _t("Non-issued certificate handling", "Never-issued serial is not reported good (RFC 6960 §2.2)"),
        _t(
            "thisUpdate/nextUpdate/producedAt present and plausible",
            "Response time fields are present, ordered and current",
        ),
    ],
    "crl": [
        _t("OCSP response signature validation", "OCSP response signature verifies against the issuer"),
        _t("Signature algorithm validation", "Response signature algorithm is acceptable"),
        _t("Response timestamp validation", "Response timestamps are internally consistent"),
        _t(
            "CRL Distribution Point extraction from certificate",
            "CDP URLs can be extracted from the certificate under test", scope="crl"),
        _t(
            "CRL download and parsing from certificate CRL Distribution Points",
            "CRLs referenced by the certificate download and parse", scope="crl"),
        _t("CRL Distribution Point accessibility", "Each CDP URL is reachable", scope="crl"),
        _t("CRL signature verification", "Downloaded CRL signature verifies against the issuer", scope="crl"),
        _t("CRL timestamp validation", "CRL thisUpdate/nextUpdate are present and current", scope="crl"),
        _t("Certificate revocation status check", "Certificate serial checked against the CRL entries", scope="crl"),
        _t("CRL vs OCSP consistency check", "CRL and OCSP agree on revocation status", scope="crl+ocsp"),
        _t(
            "Fetch and parse CRL",
            "Fetch/parse checks for each explicitly supplied CRL URL",
            dynamic=True, scope="crl"),
    ],
    "path_validation": [
        _t(
            "Valid Path (Success): End-entity -> Intermediate CA -> Trusted Root",
            "Baseline chain builds and validates to the trust anchor", scope="path"),
        _t(
            "Invalid Signature (EE): EE certificate's signature cannot be verified",
            "Tampered end-entity signature is rejected", scope="path"),
        _t(
            "Invalid Signature (Intermediate): Intermediate CA certificate's signature is invalid",
            "Tampered intermediate signature is rejected", scope="path"),
        _t(
            "Issuer/Subject Mismatch: The Issuer DN of the child cert does not match the Subject DN of the parent cert",
            "Broken issuer/subject chaining is rejected", scope="path"),
        _t(
            "notAfter Expired (EE): Validation time after EE certificate's notAfter",
            "Expired end-entity certificate is rejected", scope="path"),
        _t(
            "Revocation Status Expired: CRL has expired (nextUpdate in past)",
            "Stale CRL is not accepted as current revocation data", scope="crl"),
        _t(
            "Revoked (EE) in Fresh CRL: EE serial number on most recent CRL",
            "Revoked end-entity via CRL is rejected", scope="crl"),
        _t(
            "Revoked (EE) by OCSP: OCSP response is revoked status",
            "Revoked end-entity via OCSP is rejected", scope="ocsp"),
        _t(
            "Basic Constraints Violation: Intermediate CA cert has cA = false",
            "Non-CA intermediate is rejected", scope="path"),
        _t(
            "Path Length Constraint Violation: Path exceeds pathLenConstraint",
            "pathLenConstraint violations are rejected", scope="path"),
        _t(
            "Successful Policy Mapping: Path requires Policy A; CA maps A → B; EE asserts B",
            "Policy mapping across a bridge validates", scope="path"),
        _t(
            "Required Explicit Policy Violation: CA requires explicit policy, EE contains anyPolicy",
            "requireExplicitPolicy violations are rejected", scope="path"),
    ],
    "ikev2": [
        _t("OCSP Content extension (type 14) support", "RFC 4806 OCSP Content certificate encoding", scope="ikev2"),
        _t("CERTREQ with encoding 14 elicits CERT with OCSP", "Responder participates in IKEv2 OCSP exchange", scope="ikev2"),
        _t("Trusted responder identification", "Trusted responder configuration is identified", scope="ikev2"),
        _t("Configuration mapping (request/reply/both)", "IKEv2 OCSP request/reply configuration mapping", scope="ikev2"),
    ],
    "federal": [
        _t("Federal PKI environment detection", "Detect Federal PKI agency/CA indicators in the response"),
        _t("Batch OCSP response handling (DHS CA4 style)", "Multi-certificate batch responses are parsed"),
        _t(
            "OCSP signer signature verification (trust chain)",
            "Response signature verifies via a built trust chain",
        ),
        _t(
            "Delegated responder EKU (id-kp-OCSPSigning)",
            "Delegated responder certificate carries the OCSP signing EKU",
        ),
        _t("Response validity interval (freshness)", "thisUpdate/nextUpdate meet FPKI freshness expectations"),
    ],
    "performance": [
        _t("Latency baseline", "Sampled request latency (median/min/max)"),
        _t("Load test", "Concurrent request load test (when enabled)"),
        _t("Caching behavior observation", "Cache-related response header observation"),
    ],
    "security": [
        _t("Malformed request rejected", "Garbage request bodies are rejected cleanly"),
        _t("Operational error signaling", "tryLater/internalError signalling behaves correctly"),
        _t("Unauthorized query handling", "Queries outside the responder's scope are answered safely"),
        _t("sigRequired when unsigned", "Responder policy on unsigned requests"),
        _t("Nonce echo in response", "RFC 9654 nonce is echoed back"),
        _t(
            "Signature algorithm present and response SUCCESSFUL",
            "Response is signed with an identified algorithm",
        ),
        _t("Cryptographic preference negotiation", "Responder honours requested hash preferences"),
    ],
}


def catalog_names(category: str) -> List[str]:
    return [t["name"] for t in TEST_CATALOG.get(category, [])]


def validate_selection(tests: Dict[str, List[str]]) -> Optional[str]:
    """Return an error message when the selection references unknown
    categories or test names, else None."""
    for category, names in tests.items():
        if category not in TEST_CATALOG:
            return f"Unknown test category: {category!r}"
        known = set(catalog_names(category))
        for name in names:
            if name not in known:
                return f"Unknown test in category {category!r}: {name!r}"
    return None
