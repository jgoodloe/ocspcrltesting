from __future__ import annotations

import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

FAKE_WORKER = REPO_ROOT / "backend" / "tests" / "fake_worker.py"


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    """A TestClient wired to a temp data dir, temp DB and a fake fast worker."""
    monkeypatch.setenv("OCSPWEB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("OCSPWEB_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'test.sqlite3'}")
    monkeypatch.setenv("OCSPWEB_WORKER_PYTHON", str(FAKE_WORKER))
    monkeypatch.setenv("OCSPWEB_AUTH_PASSWORD", "")
    monkeypatch.setenv("OCSPWEB_MAX_CONCURRENT_RUNS", "4")

    from backend.app import db, jobs, settings

    settings.get_settings.cache_clear()
    jobs.reset_job_manager()
    # Force a fresh engine bound to this test's database.
    db._engine = None
    db._session_factory = None

    from fastapi.testclient import TestClient

    from backend.app.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client

    settings.get_settings.cache_clear()
    jobs.reset_job_manager()
    db._engine = None
    db._session_factory = None


def _make_cert_pair():
    """Self-signed CA + leaf with AIA/CDP/SKI extensions for metadata tests."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)

    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Leaf")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("http://ocsp.test.example"),
                    )
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("http://crl.test.example/ca.crl")],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return ca, leaf, leaf_key


@pytest.fixture(scope="session")
def cert_fixtures():
    from cryptography.hazmat.primitives import serialization

    ca, leaf, leaf_key = _make_cert_pair()
    return {
        "ca_pem": ca.public_bytes(serialization.Encoding.PEM),
        "leaf_pem": leaf.public_bytes(serialization.Encoding.PEM),
        "leaf_der": leaf.public_bytes(serialization.Encoding.DER),
        "key_pem": leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    }


def base_run_config(**overrides):
    config = {
        "ocsp_url": "http://8.8.8.8/ocsp",  # public IP literal: passes policy, never contacted
        "categories": {
            "protocol": True,
            "status": True,
            "crl": False,
            "path_validation": False,
            "ikev2": False,
            "federal": False,
            "performance": False,
            "security": False,
        },
    }
    config.update(overrides)
    return config
