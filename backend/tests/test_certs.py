from __future__ import annotations

import pytest

from backend.app.certs import (
    CertificateError,
    extract_metadata,
    load_certificate,
    load_certificate_chain,
    validate_private_key_pem,
)


def test_load_pem_and_der(cert_fixtures):
    pem = load_certificate(cert_fixtures["leaf_pem"])
    der = load_certificate(cert_fixtures["leaf_der"])
    assert pem.serial_number == der.serial_number


def test_load_rejects_garbage():
    with pytest.raises(CertificateError):
        load_certificate(b"this is not a certificate")
    with pytest.raises(CertificateError):
        load_certificate(b"")


def test_load_rejects_private_key(cert_fixtures):
    with pytest.raises(CertificateError, match="private key"):
        load_certificate(cert_fixtures["key_pem"])


def test_chain_loading(cert_fixtures):
    bundle = cert_fixtures["ca_pem"] + cert_fixtures["leaf_pem"]
    certs = load_certificate_chain(bundle)
    assert len(certs) == 2


def test_key_validation(cert_fixtures):
    validate_private_key_pem(cert_fixtures["key_pem"])
    with pytest.raises(CertificateError):
        validate_private_key_pem(cert_fixtures["leaf_pem"])


def test_metadata_extraction(cert_fixtures):
    meta = extract_metadata(load_certificate(cert_fixtures["leaf_pem"]))
    assert meta.subject == "CN=Test Leaf"
    assert meta.issuer == "CN=Test CA"
    assert meta.key_algorithm == "RSA-2048"
    assert meta.signature_algorithm_oid == "1.2.840.113549.1.1.11"
    assert meta.ski and meta.aki
    assert meta.aia_ocsp_urls == ["http://ocsp.test.example"]
    assert meta.crl_distribution_points == ["http://crl.test.example/ca.crl"]
    assert meta.is_ca is False
    assert meta.expired is False
    assert meta.self_signed is False


def test_metadata_ca_self_signed(cert_fixtures):
    meta = extract_metadata(load_certificate(cert_fixtures["ca_pem"]))
    assert meta.is_ca is True
    assert meta.self_signed is True


def test_inspect_endpoint(app_client, cert_fixtures):
    response = app_client.post(
        "/api/certificates/inspect", files={"file": ("leaf.pem", cert_fixtures["leaf_pem"])}
    )
    assert response.status_code == 200
    assert response.json()["subject"] == "CN=Test Leaf"


def test_inspect_endpoint_rejects_garbage(app_client):
    response = app_client.post("/api/certificates/inspect", files={"file": ("x.pem", b"garbage")})
    assert response.status_code == 400
    assert "not a valid" in response.json()["detail"]


def test_inspect_endpoint_size_limit(app_client):
    from backend.app.settings import get_settings

    settings = get_settings()
    original = settings.max_upload_bytes
    settings.max_upload_bytes = 64
    try:
        response = app_client.post(
            "/api/certificates/inspect", files={"file": ("big.pem", b"A" * 1000)}
        )
        assert response.status_code == 413
    finally:
        settings.max_upload_bytes = original
