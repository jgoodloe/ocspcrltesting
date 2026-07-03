from __future__ import annotations

import json
import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Response, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..certs import (
    CertificateError,
    load_certificate,
    load_certificate_chain,
    to_pem,
    validate_private_key_pem,
)
from ..db import get_session
from ..exports import build_csv_export, build_json_export
from ..jobs import TERMINAL_STATUSES, get_job_manager
from ..orm import Result, Run, RunEvent
from ..schemas import LogLine, LogList, ResultList, RunConfig, RunDetail, RunList, RunSummary
from ..ssrf import BlockedTargetError, NetworkPolicy, validate_url
from ..storage import RunWorkspace
from ..settings import get_settings
from .certs import read_limited_upload
from .serializers import result_to_schema, run_to_detail, run_to_summary

logger = logging.getLogger("ocspweb.api.runs")

router = APIRouter(tags=["test-runs"])

# (slot, single_cert_expected, is_private_key)
OPTIONAL_CERT_SLOTS = (
    ("good_cert", True),
    ("revoked_cert", True),
    ("unknown_ca_cert", True),
)


async def _get_run_or_404(session: AsyncSession, run_id: str) -> Run:
    run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Test run not found")
    return run


@router.post("/test-runs", response_model=RunSummary, status_code=201)
async def create_run(
    config: str = Form(...),
    issuer_cert: UploadFile = ...,
    good_cert: Optional[UploadFile] = None,
    revoked_cert: Optional[UploadFile] = None,
    unknown_ca_cert: Optional[UploadFile] = None,
    trust_anchor: Optional[UploadFile] = None,
    client_cert: Optional[UploadFile] = None,
    client_key: Optional[UploadFile] = None,
    session: AsyncSession = Depends(get_session),
) -> RunSummary:
    settings = get_settings()

    try:
        run_config = RunConfig.model_validate_json(config)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid run configuration: {exc.errors()}") from exc

    # SSRF policy applies at submission time (and again inside the worker for
    # every actual request, including AIA/CDP URLs discovered later).
    policy = NetworkPolicy.from_settings(settings)
    try:
        validate_url(run_config.ocsp_url, policy)
        for crl_url in run_config.crl_urls:
            validate_url(crl_url, policy)
    except BlockedTargetError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    manager = get_job_manager()
    if await manager.active_run_count() >= settings.max_concurrent_runs:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum of {settings.max_concurrent_runs} concurrent runs reached; try again later",
        )

    run_id = str(uuid.uuid4())
    workspace = RunWorkspace(settings, run_id).create()
    stored_files: dict[str, str] = {}
    file_names: dict[str, str] = {}

    async def _store_cert(slot: str, upload: Optional[UploadFile], chain: bool = False) -> None:
        if upload is None:
            return
        data = await read_limited_upload(upload)
        try:
            certs = load_certificate_chain(data) if chain else [load_certificate(data)]
        except CertificateError as exc:
            raise HTTPException(status_code=400, detail=f"{slot}: {exc}") from exc
        path = workspace.save_upload(slot, to_pem(certs))
        stored_files[slot] = str(path)
        file_names[slot] = upload.filename or slot

    try:
        await _store_cert("issuer_cert", issuer_cert)
        await _store_cert("good_cert", good_cert)
        await _store_cert("revoked_cert", revoked_cert)
        await _store_cert("unknown_ca_cert", unknown_ca_cert)
        await _store_cert("trust_anchor", trust_anchor, chain=True)
        await _store_cert("client_cert", client_cert, chain=True)
        if client_key is not None:
            key_data = await read_limited_upload(client_key)
            try:
                validate_private_key_pem(key_data)
            except CertificateError as exc:
                raise HTTPException(status_code=400, detail=f"client_key: {exc}") from exc
            path = workspace.save_upload("client_key", key_data, sensitive=True)
            stored_files["client_key"] = str(path)
            file_names["client_key"] = client_key.filename or "client_key"
    except HTTPException:
        workspace.delete()
        raise

    stored_config = run_config.model_dump()
    stored_config["files"] = file_names

    run = Run(
        id=run_id,
        name=run_config.name,
        ocsp_url=run_config.ocsp_url,
        status="queued",
        config_json=json.dumps(stored_config),
    )
    session.add(run)
    await session.commit()

    workspace.write_job_manifest(
        {
            "run_id": run_id,
            "config": run_config.model_dump(),
            "files": stored_files,
            "policy": {
                "allow_private": policy.allow_private,
                "allow_redirects": policy.allow_redirects,
                "max_response_bytes": policy.max_response_bytes,
                "max_timeout_seconds": policy.max_timeout_seconds,
                "blocked_hosts": list(policy.blocked_hosts),
            },
        }
    )

    await manager.start_run(run_id)
    await session.refresh(run)
    logger.info("created run %s -> %s", run_id, run_config.ocsp_url)
    return run_to_summary(run)


@router.get("/test-runs", response_model=RunList)
async def list_runs(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
) -> RunList:
    stmt = select(Run)
    count_stmt = select(func.count(Run.id))
    if status:
        statuses = [s.strip() for s in status.split(",") if s.strip()]
        stmt = stmt.where(Run.status.in_(statuses))
        count_stmt = count_stmt.where(Run.status.in_(statuses))
    total = int((await session.execute(count_stmt)).scalar_one())
    rows = (
        (await session.execute(stmt.order_by(Run.created_at.desc()).limit(limit).offset(offset)))
        .scalars()
        .all()
    )
    return RunList(items=[run_to_summary(r) for r in rows], total=total)


@router.get("/test-runs/{run_id}", response_model=RunDetail)
async def get_run(run_id: str, session: AsyncSession = Depends(get_session)) -> RunDetail:
    run = await _get_run_or_404(session, run_id)
    return run_to_detail(run)


@router.get("/test-runs/{run_id}/results", response_model=ResultList)
async def get_results(
    run_id: str,
    category: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
) -> ResultList:
    await _get_run_or_404(session, run_id)
    stmt = select(Result).where(Result.run_id == run_id)
    if category:
        stmt = stmt.where(Result.category.in_([c.strip() for c in category.split(",") if c.strip()]))
    if status:
        stmt = stmt.where(Result.status.in_([s.strip().upper() for s in status.split(",") if s.strip()]))
    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(Result.name.like(pattern) | Result.message.like(pattern))
    rows = (await session.execute(stmt.order_by(Result.started_at))).scalars().all()
    return ResultList(items=[result_to_schema(r) for r in rows], total=len(rows))


@router.get("/test-runs/{run_id}/logs", response_model=LogList)
async def get_logs(
    run_id: str,
    after_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=1000, ge=1, le=10000),
    session: AsyncSession = Depends(get_session),
) -> LogList:
    run = await _get_run_or_404(session, run_id)
    stmt = (
        select(RunEvent)
        .where(RunEvent.run_id == run_id, RunEvent.type == "log", RunEvent.seq > after_seq)
        .order_by(RunEvent.seq)
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()
    items = [
        LogLine(
            seq=e.seq,
            ts=e.ts,
            level=str(e.payload.get("level", "INFO")),
            message=str(e.payload.get("message", "")),
        )
        for e in rows
    ]
    return LogList(items=items, last_seq=run.last_seq)


@router.get("/test-runs/{run_id}/export/json")
async def export_json(run_id: str, session: AsyncSession = Depends(get_session)) -> JSONResponse:
    run = await _get_run_or_404(session, run_id)
    results = (
        (await session.execute(select(Result).where(Result.run_id == run_id).order_by(Result.started_at)))
        .scalars()
        .all()
    )
    events = (
        (await session.execute(select(RunEvent).where(RunEvent.run_id == run_id).order_by(RunEvent.seq)))
        .scalars()
        .all()
    )
    payload = build_json_export(run, results, events)
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": f'attachment; filename="ocsp-run-{run_id}.json"'},
    )


@router.get("/test-runs/{run_id}/export/csv")
async def export_csv(run_id: str, session: AsyncSession = Depends(get_session)) -> PlainTextResponse:
    await _get_run_or_404(session, run_id)
    results = (
        (await session.execute(select(Result).where(Result.run_id == run_id).order_by(Result.started_at)))
        .scalars()
        .all()
    )
    return PlainTextResponse(
        content=build_csv_export(results),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="ocsp-run-{run_id}.csv"'},
    )


@router.post("/test-runs/{run_id}/cancel", response_model=RunSummary)
async def cancel_run(run_id: str, session: AsyncSession = Depends(get_session)) -> RunSummary:
    run = await _get_run_or_404(session, run_id)
    if run.status in TERMINAL_STATUSES:
        raise HTTPException(status_code=409, detail=f"Run already finished with status {run.status}")
    await get_job_manager().cancel_run(run_id)
    await session.refresh(run)
    return run_to_summary(run)


@router.delete("/test-runs/{run_id}", status_code=204)
async def delete_run(run_id: str, session: AsyncSession = Depends(get_session)) -> Response:
    run = await _get_run_or_404(session, run_id)
    if run.status not in TERMINAL_STATUSES:
        await get_job_manager().cancel_run(run_id)
    await session.delete(run)
    await session.commit()
    RunWorkspace(get_settings(), run_id).delete()
    return Response(status_code=204)
