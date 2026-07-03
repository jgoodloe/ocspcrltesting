import csv
import json
from typing import List
from .models import TestCaseResult


def export_results_json(results: List[TestCaseResult], path: str) -> None:
    payload = []
    for r in results:
        payload.append({
            "id": r.id,
            "name": r.name,
            "category": r.category,
            "status": r.status.value,
            "message": r.message,
            "details": r.details,
            "started_at": r.started_at.isoformat() + "Z",
            "ended_at": r.ended_at.isoformat() + "Z" if r.ended_at else None,
            "duration_ms": r.duration_ms,
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def export_results_csv(results: List[TestCaseResult], path: str) -> None:
    cols = ["id", "category", "name", "status", "message", "duration_ms", "details"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in results:
            w.writerow({
                "id": r.id,
                "category": r.category,
                "name": r.name,
                "status": r.status.value,
                "message": r.message,
                "duration_ms": r.duration_ms,
                "details": json.dumps(r.details),
            })
