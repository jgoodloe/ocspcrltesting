"""Worker-process diagnostics recorder.

Captures every external action the test engine performs — outbound HTTP
exchanges (patched at ``requests.Session.send``, layered on top of the
netguard patch) and external commands (patched at ``subprocess.run``, which
is how the engine invokes OpenSSL) — so users can see exactly what was run
and reproduce it when troubleshooting.

Each record carries naive-UTC timestamps matching ``TestCaseResult``'s
clock; the executor attaches records to individual test results by time
window and emits one DEBUG log line per record for the live log stream.

This module is only ever installed inside the per-run worker subprocess.
"""

from __future__ import annotations

import base64
import shlex
import subprocess
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

Log = Callable[[str, str], None]

MAX_TEXT_EXCERPT = 2000  # chars of stdout/stderr kept per command
MAX_BODY_BYTES = 4096  # request/response bodies larger than this are size-only
MAX_RECORDS = 400  # hard cap so load tests don't balloon memory/DB

_records: List[Dict[str, Any]] = []
_suppressed = 0
_installed = False


def records() -> List[Dict[str, Any]]:
    return _records


def suppressed_count() -> int:
    return _suppressed


def _now() -> datetime:
    # Naive UTC to match ocsp_tester.models.TestCaseResult timestamps.
    return datetime.utcnow()


def _iso(dt: datetime) -> str:
    return dt.isoformat() + "Z"


def _scrub(text: str) -> str:
    if "PRIVATE KEY" in text:
        return "[REDACTED: private key material]"
    return text[:MAX_TEXT_EXCERPT]


def _append(entry: Dict[str, Any]) -> bool:
    global _suppressed
    if len(_records) >= MAX_RECORDS:
        _suppressed += 1
        return False
    _records.append(entry)
    return True


def _b64_body(body: Any) -> Dict[str, Any]:
    if body is None:
        return {}
    data = body.encode("utf-8", errors="replace") if isinstance(body, str) else bytes(body)
    out: Dict[str, Any] = {"request_bytes": len(data)}
    if len(data) <= MAX_BODY_BYTES:
        out["request_body_b64"] = base64.b64encode(data).decode("ascii")
    return out


def _curl_hint(method: str, url: str, content_type: str, has_small_body: bool) -> str:
    if method.upper() == "GET":
        return f"curl -sS -o response.bin '{url}'"
    body_src = (
        "printf '%s' \"$REQ_B64\" | base64 -d > request.der && "
        if has_small_body
        else "# write the original request bytes to request.der, then: "
    )
    ct = content_type or "application/ocsp-request"
    return f"{body_src}curl -sS -X {method.upper()} -H 'Content-Type: {ct}' --data-binary @request.der -o response.bin '{url}'"


def install(log: Optional[Log] = None) -> None:
    """Patch subprocess and requests for the lifetime of the worker process.

    Must be called *after* ``netguard.install`` so recorded HTTP behaviour
    (timeout caps, size caps, blocks) matches what the engine experienced.
    """
    global _installed
    if _installed:
        return
    _installed = True
    _patch_subprocess(log)
    _patch_requests(log)


def _patch_subprocess(log: Optional[Log]) -> None:
    original_run = subprocess.run

    def recording_run(*args: Any, **kwargs: Any):
        argv = args[0] if args else kwargs.get("args")
        if isinstance(argv, (list, tuple)):
            command = " ".join(shlex.quote(str(a)) for a in argv)
        else:
            command = str(argv)
        started = _now()
        t0 = time.perf_counter()
        entry: Dict[str, Any] = {
            "kind": "command",
            "command": command,
            "started_at": _iso(started),
        }
        try:
            proc = original_run(*args, **kwargs)
        except Exception as exc:
            entry.update(
                {
                    "error": f"{type(exc).__name__}: {exc}",
                    "duration_ms": int((time.perf_counter() - t0) * 1000),
                    "ended_at": _iso(_now()),
                    "_started": started,
                }
            )
            if _append(entry) and log:
                log("DEBUG", f"[CMD] {command} -> {type(exc).__name__}: {exc}")
            raise
        duration_ms = int((time.perf_counter() - t0) * 1000)
        entry.update(
            {
                "returncode": proc.returncode,
                "duration_ms": duration_ms,
                "ended_at": _iso(_now()),
                "_started": started,
            }
        )
        for stream_name in ("stdout", "stderr"):
            value = getattr(proc, stream_name, None)
            if value is None:
                continue
            text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
            if text:
                entry[f"{stream_name}_excerpt"] = _scrub(text)
        if _append(entry) and log:
            log("DEBUG", f"[CMD] {command} -> exit {proc.returncode} ({duration_ms} ms)")
        return proc

    subprocess.run = recording_run  # type: ignore[assignment]


def _patch_requests(log: Optional[Log]) -> None:
    import requests

    original_send = requests.Session.send

    def recording_send(self: requests.Session, request: requests.PreparedRequest, **kwargs: Any):
        method = (request.method or "GET").upper()
        url = request.url or ""
        content_type = str(request.headers.get("Content-Type", "")) if request.headers else ""
        started = _now()
        t0 = time.perf_counter()
        entry: Dict[str, Any] = {
            "kind": "http",
            "method": method,
            "url": url,
            "started_at": _iso(started),
        }
        entry.update(_b64_body(request.body))
        entry["curl"] = _curl_hint(method, url, content_type, "request_body_b64" in entry)
        try:
            response = original_send(self, request, **kwargs)
        except Exception as exc:
            duration_ms = int((time.perf_counter() - t0) * 1000)
            entry.update(
                {
                    "error": f"{type(exc).__name__}: {exc}",
                    "duration_ms": duration_ms,
                    "ended_at": _iso(_now()),
                    "_started": started,
                }
            )
            if _append(entry) and log:
                log("DEBUG", f"[HTTP] {method} {url} -> {type(exc).__name__}: {exc} ({duration_ms} ms)")
            raise
        duration_ms = int((time.perf_counter() - t0) * 1000)
        entry.update(
            {
                "status_code": response.status_code,
                "reason": response.reason,
                "duration_ms": duration_ms,
                "ended_at": _iso(_now()),
                "_started": started,
            }
        )
        try:
            body = response.content  # netguard has already materialized this
            entry["response_bytes"] = len(body)
            resp_type = str(response.headers.get("Content-Type", ""))
            if resp_type:
                entry["response_content_type"] = resp_type
            if len(body) <= MAX_BODY_BYTES:
                entry["response_body_b64"] = base64.b64encode(body).decode("ascii")
        except Exception:
            pass
        if _append(entry) and log:
            log(
                "DEBUG",
                f"[HTTP] {method} {url} -> {response.status_code} "
                f"({entry.get('response_bytes', '?')} bytes, {duration_ms} ms)",
            )
        return response

    requests.Session.send = recording_send  # type: ignore[method-assign]
