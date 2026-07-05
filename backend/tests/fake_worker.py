#!/usr/bin/env python3
"""Stand-in for the real run worker used by the API lifecycle tests.

Invoked exactly like the real worker (``<python> -m backend.app.worker
<run_dir>``); it ignores the ``-m backend.app.worker`` arguments, reads the
job manifest, and emits a deterministic JSONL event sequence.
"""

import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def emit(**record):
    print(json.dumps(record), flush=True)


def main() -> int:
    run_dir = Path(sys.argv[-1])
    manifest = json.loads((run_dir / "job.json").read_text())
    behavior = manifest["config"].get("name") or "ok"
    now = datetime.now(timezone.utc).isoformat()

    emit(type="log", level="INFO", message="fake worker starting")
    emit(
        type="progress",
        current_activity="Running fake tests",
        categories_done=0,
        categories_total=1,
        percent=0,
    )

    if behavior == "hang":
        time.sleep(300)

    # "dupid" reuses a fixed result id to exercise the supervisor's global
    # primary-key de-duplication (path validation once emitted deterministic
    # ids that collided across runs and aborted the whole run).
    first_id = "fixed-result-id" if behavior == "dupid" else str(uuid.uuid4())
    emit(
        type="result",
        result={
            "id": first_id,
            "category": "Protocol",
            "name": "HTTP GET transport",
            "status": "PASS",
            "message": "GET accepted",
            "details": {"latency_ms": 42, "signature_algorithm_oid": "1.2.840.113549.1.1.11"},
            "started_at": now,
            "ended_at": now,
            "duration_ms": 42,
        },
    )
    emit(
        type="result",
        result={
            "id": str(uuid.uuid4()),
            "category": "Status",
            "name": "Known revoked certificate returns revoked",
            "status": "FAIL",
            "message": "Unexpected status: SUCCESSFUL/good",
            "details": {},
            "started_at": now,
            "ended_at": now,
            "duration_ms": 17,
        },
    )
    emit(type="log", level="INFO", message="fake worker finishing")

    if behavior == "crash":
        emit(type="fatal", error="simulated crash")
        return 1

    emit(
        type="done",
        status="completed",
        latency={"median_ms": 42, "min_ms": 40, "max_ms": 45, "samples": 3},
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
