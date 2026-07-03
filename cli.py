#!/usr/bin/env python3
"""Headless CLI for the OCSP test engine.

Runs the same ``ocsp_tester`` engine as the web application (and as the
original Tkinter GUI in jgoodloe/OCSPTesting) without any UI, and exports
JSON/CSV results. Example:

    python cli.py --ocsp-url http://ocsp.example.com \
        --issuer issuer.pem --good good.pem --revoked revoked.pem \
        --categories protocol,status,crl --json-out results.json
"""

from __future__ import annotations

import argparse
import sys

from ocsp_tester.exporters import export_results_csv, export_results_json
from ocsp_tester.models import TestStatus
from ocsp_tester.runner import TestInputs, TestRunner

CATEGORY_FLAGS = {
    "protocol": "ocsp_tests",
    "status": "ocsp_tests",
    "security": "ocsp_tests",
    "crl": "crl_tests",
    "path_validation": "path_validation_tests",
    "ikev2": "ikev2_tests",
    "federal": "federal_tests",
    "performance": "performance_tests",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="OCSP responder test suite (headless)")
    parser.add_argument("--ocsp-url", required=True)
    parser.add_argument("--issuer", required=True, help="Issuer certificate (PEM/DER)")
    parser.add_argument("--good", help="Known-good certificate")
    parser.add_argument("--revoked", help="Known-revoked certificate")
    parser.add_argument("--unknown-ca", help="Certificate from a CA unknown to the responder")
    parser.add_argument("--trust-anchor", help="Trust anchor / intermediate chain (PEM)")
    parser.add_argument("--client-cert", help="TLS client certificate")
    parser.add_argument("--client-key", help="TLS client key")
    parser.add_argument("--crl-url", help="CRL override URL")
    parser.add_argument("--latency-samples", type=int, default=5)
    parser.add_argument("--load-test", action="store_true")
    parser.add_argument("--load-concurrency", type=int, default=5)
    parser.add_argument("--load-requests", type=int, default=50)
    parser.add_argument(
        "--categories",
        default="protocol,status,security,crl,path_validation",
        help="Comma list of: " + ",".join(sorted(set(CATEGORY_FLAGS))),
    )
    parser.add_argument("--json-out", help="Write JSON results to this path")
    parser.add_argument("--csv-out", help="Write CSV results to this path")
    parser.add_argument("--quiet", action="store_true", help="Suppress engine logs")
    args = parser.parse_args()

    selected = {c.strip() for c in args.categories.split(",") if c.strip()}
    unknown = selected - set(CATEGORY_FLAGS)
    if unknown:
        parser.error(f"Unknown categories: {', '.join(sorted(unknown))}")
    toggles = {flag: False for flag in set(CATEGORY_FLAGS.values())}
    for cat in selected:
        toggles[CATEGORY_FLAGS[cat]] = True

    inputs = TestInputs(
        ocsp_url=args.ocsp_url,
        issuer_path=args.issuer,
        known_good_cert_path=args.good,
        known_revoked_cert_path=args.revoked,
        unknown_ca_cert_path=args.unknown_ca,
        client_sign_cert_path=args.client_cert,
        client_sign_key_path=args.client_key,
        latency_samples=args.latency_samples,
        enable_load_test=args.load_test,
        load_concurrency=args.load_concurrency,
        load_requests=args.load_requests,
        crl_override_url=args.crl_url,
        trust_anchor_path=args.trust_anchor,
    )

    log = (lambda _msg: None) if args.quiet else (lambda msg: print(msg, end=""))
    runner = TestRunner(log_callback=log)
    results = runner.run_all(inputs, toggles)

    counts = {status.value: 0 for status in TestStatus}
    for result in results:
        counts[result.status.value] += 1
        marker = {"PASS": "+", "FAIL": "x", "WARN": "!", "SKIP": "-", "ERROR": "E"}[result.status.value]
        print(f"[{marker}] {result.status.value:5s} {result.category}: {result.name} — {result.message}")

    print(
        f"\nTotal: {len(results)}  "
        + "  ".join(f"{k}: {v}" for k, v in counts.items() if v)
    )

    if args.json_out:
        export_results_json(results, args.json_out)
        print(f"JSON written to {args.json_out}")
    if args.csv_out:
        export_results_csv(results, args.csv_out)
        print(f"CSV written to {args.csv_out}")

    return 1 if (counts["FAIL"] or counts["ERROR"]) else 0


if __name__ == "__main__":
    sys.exit(main())
