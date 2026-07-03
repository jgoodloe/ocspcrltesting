"""Post-processing of engine results: freshness/nonce/algorithm warnings and
RFC cross-references (RFC 6960, RFC 5019, RFC 4806, RFC 9654).

The engine reports PASS/FAIL/SKIP/ERROR; this layer adds the WARN dimension
for conditions that are technically successful but operationally suspect
(stale nextUpdate, nonce not echoed, deprecated signature algorithms).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

DEPRECATED_SIG_OIDS = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.10040.4.3": "dsaWithSHA1",
    "1.2.840.10045.4.1": "ecdsaWithSHA1",
}

CATEGORY_RFC_REFS = {
    "Protocol": ["RFC 6960 (OCSP)", "RFC 5019 (lightweight OCSP profile)"],
    "Status": ["RFC 6960 §2.2 (response statuses)"],
    "Security": ["RFC 6960 §5 (security considerations)"],
    "CRL": ["RFC 5280 §5 (CRL profile)"],
    "IKEv2": ["RFC 4806 (OCSP extensions to IKEv2)"],
    "Federal PKI": ["Federal PKI X.509 certificate policy", "RFC 6960"],
    "Path Validation": ["RFC 5280 §6 (path validation)"],
    "Performance": ["RFC 5019 §6 (caching recommendations)"],
}


def _find_keys(obj: Any, wanted: Tuple[str, ...]) -> Iterator[Tuple[str, Any]]:
    """Yield (key, value) for every occurrence of the wanted keys, recursively."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in wanted and value is not None:
                yield key, value
            yield from _find_keys(value, wanted)
    elif isinstance(obj, list):
        for item in obj:
            yield from _find_keys(item, wanted)


def _parse_ts(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def enrich_result(result: Dict[str, Any], run_config: Dict[str, Any]) -> Dict[str, Any]:
    """Mutates and returns the serialized result dict."""
    details = result.setdefault("details", {})
    warnings: List[str] = list(details.get("warnings", []))
    now = datetime.now(timezone.utc)
    max_age = timedelta(hours=int(run_config.get("max_age_hours", 24)))

    # Freshness: thisUpdate/nextUpdate sanity wherever they appear in details.
    for key, value in _find_keys(details, ("next_update", "nextUpdate")):
        ts = _parse_ts(value if not isinstance(value, dict) else value.get("value"))
        if ts and ts < now:
            warnings.append(
                f"nextUpdate {value} is in the past — the responder is serving expired status data (RFC 6960 §4.2.2.1)"
            )
            break
    for key, value in _find_keys(details, ("this_update", "thisUpdate")):
        raw = value if not isinstance(value, dict) else value.get("value")
        ts = _parse_ts(raw)
        if not ts:
            continue
        if ts > now + timedelta(minutes=5):
            warnings.append(f"thisUpdate {raw} is in the future — check responder clock (RFC 6960 §4.2.2.1)")
        elif now - ts > max_age:
            warnings.append(
                f"thisUpdate {raw} is older than the configured maximum age of {run_config.get('max_age_hours', 24)}h"
            )
        break

    # Nonce compliance (RFC 9654 recommends >=32-byte nonces and echoing).
    if run_config.get("nonce_enabled", True):
        for _, value in _find_keys(details, ("nonce_echoed",)):
            if value is False:
                warnings.append(
                    "Requested nonce was not echoed in the response — replay protection is not effective (RFC 9654)"
                )
            break
    nonce_len = int(run_config.get("nonce_length", 32))
    if run_config.get("nonce_enabled", True) and nonce_len < 32 and "nonce" in result.get("name", "").lower():
        warnings.append(f"Configured nonce length {nonce_len} is below the 32 bytes recommended by RFC 9654")

    # Deprecated signature algorithms.
    for _, value in _find_keys(details, ("signature_algorithm_oid",)):
        oid = value if isinstance(value, str) else None
        if oid and oid in DEPRECATED_SIG_OIDS:
            warnings.append(
                f"Response signed with deprecated algorithm {DEPRECATED_SIG_OIDS[oid]} ({oid})"
            )
        break

    if warnings:
        details["warnings"] = warnings
        if result.get("status") == "PASS":
            result["status"] = "WARN"

    refs = list(details.get("rfc_refs", []))
    for ref in CATEGORY_RFC_REFS.get(result.get("category", ""), []):
        if ref not in refs:
            refs.append(ref)
    if refs:
        details["rfc_refs"] = refs

    return result
