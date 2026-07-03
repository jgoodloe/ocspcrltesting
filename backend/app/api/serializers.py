"""ORM -> schema converters shared by routers and the job manager."""

from __future__ import annotations

import json
from typing import Any, Dict

from ..orm import Result, Run
from ..schemas import LatencySummary, RunDetail, RunSummary, TestResultOut

SENSITIVE_CONFIG_KEYS = ("client_key",)


def sanitize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = dict(config)
    files = dict(cleaned.get("files", {}))
    for key in SENSITIVE_CONFIG_KEYS:
        if key in files and files[key]:
            files[key] = "<provided>"
    if files:
        cleaned["files"] = files
    return cleaned


def run_to_summary(run: Run) -> RunSummary:
    latency = None
    if run.latency_json:
        try:
            latency = LatencySummary(**json.loads(run.latency_json))
        except (ValueError, TypeError):
            latency = None
    config = run.config
    categories = [k for k, v in (config.get("categories") or {}).items() if v]
    return RunSummary(
        id=run.id,
        name=run.name,
        ocsp_url=run.ocsp_url,
        status=run.status,  # type: ignore[arg-type]
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
        totals=run.totals,
        latency=latency,
        categories=categories,
        current_activity=run.current_activity,
        error=run.error,
    )


def run_to_detail(run: Run) -> RunDetail:
    summary = run_to_summary(run)
    return RunDetail(**summary.model_dump(), config=sanitize_config(run.config))


def result_to_schema(result: Result) -> TestResultOut:
    return TestResultOut(
        id=result.id,
        category=result.category,
        name=result.name,
        status=result.status,  # type: ignore[arg-type]
        message=result.message,
        details=result.details,
        started_at=result.started_at,
        ended_at=result.ended_at,
        duration_ms=result.duration_ms,
    )
