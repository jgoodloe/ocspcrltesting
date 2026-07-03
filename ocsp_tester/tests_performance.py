import statistics
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from cryptography import x509

from .models import TestCaseResult, TestStatus
from .ocsp_client import send_ocsp_request, OCSPRequestSpec


def run_perf_tests(
    ocsp_url: str,
    issuer: x509.Certificate,
    sample_cert: x509.Certificate,
    latency_samples: int,
    enable_load: bool,
    load_concurrency: int,
    load_requests: int,
) -> List[TestCaseResult]:
    results: List[TestCaseResult] = []

    # 1. Latency baseline
    r = TestCaseResult(id=str(uuid.uuid4()), category="Performance", name="Latency baseline", status=TestStatus.ERROR)
    try:
        latencies = []
        for _ in range(max(1, latency_samples)):
            info = send_ocsp_request(ocsp_url, OCSPRequestSpec(sample_cert, issuer, include_nonce=False), method="POST")
            latencies.append(info.latency_ms)
        r.status = TestStatus.PASS
        r.message = f"median={int(statistics.median(latencies))}ms p95={int(statistics.quantiles(latencies, n=20)[18])}ms"
        r.details.update({"latencies_ms": latencies})
    except Exception as exc:
        r.status = TestStatus.ERROR
        r.message = str(exc)
    r.end()
    results.append(r)

    # 2. Load test (optional)
    r = TestCaseResult(id=str(uuid.uuid4()), category="Performance", name="Load test", status=TestStatus.SKIP)
    if enable_load:
        try:
            latencies = []
            with ThreadPoolExecutor(max_workers=max(1, load_concurrency)) as ex:
                futs = [
                    ex.submit(send_ocsp_request, ocsp_url, OCSPRequestSpec(sample_cert, issuer, include_nonce=False), "POST")
                    for _ in range(max(1, load_requests))
                ]
                for fut in as_completed(futs):
                    latencies.append(fut.result().latency_ms)
            r.status = TestStatus.PASS
            r.message = f"requests={len(latencies)} median={int(statistics.median(latencies))}ms"
            r.details.update({"latencies_ms": latencies})
        except Exception as exc:
            r.status = TestStatus.ERROR
            r.message = str(exc)
    else:
        r.message = "Disabled"
    r.end()
    results.append(r)

    # 3. Caching behavior (observational)
    r = TestCaseResult(id=str(uuid.uuid4()), category="Performance", name="Caching behavior observation", status=TestStatus.ERROR)
    try:
        a = send_ocsp_request(ocsp_url, OCSPRequestSpec(sample_cert, issuer, include_nonce=False), method="GET")
        b = send_ocsp_request(ocsp_url, OCSPRequestSpec(sample_cert, issuer, include_nonce=False), method="GET")
        stable = (a.this_update == b.this_update) and (a.next_update == b.next_update)
        r.status = TestStatus.PASS
        r.message = f"Stable fields across two GETs: {bool(stable)}"
        r.details.update({"a_latency_ms": a.latency_ms, "b_latency_ms": b.latency_ms})
    except Exception as exc:
        r.status = TestStatus.ERROR
        r.message = str(exc)
    r.end()
    results.append(r)

    return results
