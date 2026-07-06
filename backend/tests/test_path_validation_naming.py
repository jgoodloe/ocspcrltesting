"""Issuer/Subject name-chaining test now reports the DNs and a clear verdict
(regression for issue #24: it previously showed a confusing 'incorrectly
passed' for a correctly-chaining pair)."""

from __future__ import annotations

from ocsp_tester.tests_path_validation import PathValidationTestSuite


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_matching_pair_reports_chain_ok(tmp_path, cert_fixtures):
    suite = PathValidationTestSuite()
    inputs = {
        "issuer_path": _write(tmp_path, "ca.pem", cert_fixtures["ca_pem"]),
        "good_cert_path": _write(tmp_path, "leaf.pem", cert_fixtures["leaf_pem"]),
    }
    result = suite._test_issuer_subject_mismatch(inputs)
    assert result["available"] is True
    assert result["names_chain"] is True
    # DNs are surfaced for manual verification.
    assert "Test CA" in result["parent_subject"]
    assert "Test CA" in result["child_issuer"]
    assert "Test Leaf" in result["child_subject"]


def test_mismatched_pair_is_detected(tmp_path, cert_fixtures):
    suite = PathValidationTestSuite()
    # Use the leaf as the "issuer": its subject ("Test Leaf") does not match the
    # leaf's issuer DN ("Test CA"), so name chaining must be reported as broken.
    inputs = {
        "issuer_path": _write(tmp_path, "leaf.pem", cert_fixtures["leaf_pem"]),
        "good_cert_path": _write(tmp_path, "leaf2.pem", cert_fixtures["leaf_pem"]),
    }
    result = suite._test_issuer_subject_mismatch(inputs)
    assert result["available"] is True
    assert result["names_chain"] is False


def test_missing_certs_report_unavailable(tmp_path, cert_fixtures):
    suite = PathValidationTestSuite()
    result = suite._test_issuer_subject_mismatch({})
    assert result["available"] is False
    assert "error" in result
