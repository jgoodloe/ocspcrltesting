"""JSON and CSV export builders for completed (or in-flight) runs."""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List

from .orm import Result, Run, RunEvent

CSV_COLUMNS = [
    "id",
    "category",
    "name",
    "status",
    "message",
    "duration_ms",
    "started_at",
    "ended_at",
    "details",
]


def build_json_export(run: Run, results: List[Result], events: List[RunEvent]) -> Dict[str, Any]:
    return {
        "run": {
            "id": run.id,
            "name": run.name,
            "ocsp_url": run.ocsp_url,
            "status": run.status,
            "created_at": run.created_at.isoformat() if run.created_at else None,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            "totals": run.totals,
            "latency": json.loads(run.latency_json) if run.latency_json else None,
            "error": run.error,
            "config": run.config,
        },
        "results": [
            {
                "id": r.id,
                "category": r.category,
                "name": r.name,
                "status": r.status,
                "message": r.message,
                "details": r.details,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "ended_at": r.ended_at.isoformat() if r.ended_at else None,
                "duration_ms": r.duration_ms,
            }
            for r in results
        ],
        "logs": [
            {"seq": e.seq, "ts": e.ts.isoformat() if e.ts else None, **e.payload}
            for e in events
            if e.type == "log"
        ],
    }


def build_csv_export(results: List[Result]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for r in results:
        writer.writerow(
            {
                "id": r.id,
                "category": r.category,
                "name": r.name,
                "status": r.status,
                "message": r.message,
                "duration_ms": r.duration_ms,
                "started_at": r.started_at.isoformat() if r.started_at else "",
                "ended_at": r.ended_at.isoformat() if r.ended_at else "",
                "details": json.dumps(r.details, default=str),
            }
        )
    return buffer.getvalue()
