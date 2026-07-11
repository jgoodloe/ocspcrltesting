from __future__ import annotations

import json
import logging
import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Path, Query, Response, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import Principal, Role, WorkspaceContext, active_workspace, current_principal
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
from ..orm import CACertificate, Profile, Result, Run, RunEvent
from ..schemas import (
    LogLine,
    LogList,
    ProfileOut,
    ResultList,
    RunConfig,
    RunDetail,
    RunList,
    RunProfileIn,
    RunSummary,
)
from ..ssrf import BlockedTargetError, NetworkPolicy, validate_url
from ..storage import UPLOAD_SLOTS, RunWorkspace
from ..settings import get_settings
from ..test_catalog import validate_selection
from .catalog import load_global_selection
from .certs import read_limited_upload
from .serializers import result_to_schema, run_to_detail, run_to_summary

logger = logging.getLogger("ocspweb.api.runs")

router = APIRouter(tags=["test-runs"])

# Run ids are always generated server-side as uuid4 (see create_run/rerun_run).
# Validating the path parameter against that shape rejects malformed ids with
# a 422 at the boundary, so an attacker-shaped run_id can never reach handler
# code, logs, or filesystem-path construction.
RunID = Annotated[str, Path(pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]

# (slot, single_cert_expected, is_private_key)
OPTIONAL_CERT_SLOTS = (
    ("good_cert", True),
    ("revoked_cert", True),
    ("unknown_ca_cert", True),
)


async def _get_run_or_404(session: AsyncSession, run_id: str, ctx: WorkspaceContext) -> Run:
    run = await session.get(Run, run_id)
    if run is None or run.workspace_id != ctx.workspace.id:
        raise HTTPException(status_code=404, detail="Test run not found")
    # "own" visibility: non-privileged members only see runs they created.
    if (
        ctx.workspace.run_visibility == "own"
        and ctx.role < Role.admin
        and not ctx.principal.is_global_admin
        and run.created_by_user_id
        and run.created_by_user_id != ctx.principal.user.id
    ):
        raise HTTPException(status_code=404, detail="Test run not found")
    return run


def _workspace_policy(ctx: WorkspaceContext) -> NetworkPolicy:
    """Network policy for this workspace: the deployment settings, with
    private-target access gated by the workspace's own (ceiling-capped) flag."""
    settings = get_settings()
    policy = NetworkPolicy.from_settings(settings)
    policy.allow_private = bool(settings.allow_private_targets and ctx.workspace.allow_private_targets)
    return policy


async def _active_run_count(session: AsyncSession, workspace_id: int) -> int:
    """Number of not-yet-finished runs in a workspace (for concurrency caps)."""
    return int(
        (
            await session.execute(
                select(func.count(Run.id)).where(
                    Run.workspace_id == workspace_id,
                    Run.status.notin_(list(TERMINAL_STATUSES)),
                )
            )
        ).scalar_one()
    )


def _visibility_filter(stmt, ctx: WorkspaceContext):
    """Restrict a Run query to the caller when the workspace hides others' runs."""
    if (
        ctx.workspace.run_visibility == "own"
        and ctx.role < Role.admin
        and not ctx.principal.is_global_admin
    ):
        stmt = stmt.where(Run.created_by_user_id == ctx.principal.user.id)
    return stmt


@router.post("/test-runs", response_model=RunSummary, status_code=201)
async def create_run(
    config: str = Form(...),
    issuer_cert: Optional[UploadFile] = None,
    good_cert: Optional[UploadFile] = None,
    revoked_cert: Optional[UploadFile] = None,
    unknown_ca_cert: Optional[UploadFile] = None,
    trust_anchor: Optional[UploadFile] = None,
    client_cert: Optional[UploadFile] = None,
    client_key: Optional[UploadFile] = None,
    ctx: WorkspaceContext = Depends(active_workspace(Role.member)),
    session: AsyncSession = Depends(get_session),
) -> RunSummary:
    settings = get_settings()

    try:
        run_config = RunConfig.model_validate_json(config)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid run configuration: {exc.errors()}") from exc

    # SSRF policy applies at submission time (and again inside the worker for
    # every actual request, including AIA/CDP URLs discovered later). Private
    # targets are gated by the workspace's own policy.
    policy = _workspace_policy(ctx)
    try:
        validate_url(run_config.ocsp_url, policy)
        for crl_url in run_config.crl_urls:
            validate_url(crl_url, policy)
    except BlockedTargetError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    # Resolve the fine-grained test selection now so the run records exactly
    # what was applied (the global default may change later).
    selection = run_config.test_selection
    resolved_tests: Optional[dict] = None
    if selection.mode == "custom":
        error = validate_selection(selection.tests)
        if error:
            raise HTTPException(status_code=400, detail=error)
        resolved_tests = selection.tests
    elif selection.mode == "global":
        resolved_tests = await load_global_selection(session)

    manager = get_job_manager()
    ws_limit = min(ctx.workspace.max_concurrent_runs, settings.max_concurrent_runs)
    if await _active_run_count(session, ctx.workspace.id) >= ws_limit:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum of {ws_limit} concurrent runs reached for this workspace; try again later",
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

    async def _store_saved_certs() -> None:
        """Materialize saved CA-library references into the workspace, the
        same way uploaded files are stored."""
        for slot, cert_id in run_config.saved_certs.items():
            if slot in stored_files:
                raise HTTPException(
                    status_code=400,
                    detail=f"{slot}: both an uploaded file and a saved certificate were provided",
                )
            saved = await session.get(CACertificate, cert_id)
            if saved is None or saved.workspace_id != ctx.workspace.id:
                raise HTTPException(
                    status_code=400,
                    detail=f"{slot}: saved certificate #{cert_id} not found in this workspace's CA library",
                )
            path = workspace.save_upload(slot, saved.pem.encode("ascii"))
            stored_files[slot] = str(path)
            file_names[slot] = f"{saved.name} (saved CA)"

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
        await _store_saved_certs()
        if "issuer_cert" not in stored_files:
            raise HTTPException(
                status_code=400,
                detail="issuer_cert is required: upload a file or select a saved CA certificate",
            )
    except HTTPException:
        workspace.delete()
        raise

    stored_config = run_config.model_dump()
    stored_config["files"] = file_names
    stored_config["resolved_test_selection"] = resolved_tests

    run = Run(
        id=run_id,
        workspace_id=ctx.workspace.id,
        created_by_user_id=ctx.principal.user.id or None,
        name=run_config.name,
        ocsp_url=run_config.ocsp_url,
        status="queued",
        config_json=json.dumps(stored_config),
    )
    session.add(run)
    await session.commit()

    manifest_config = run_config.model_dump()
    manifest_config["resolved_test_selection"] = resolved_tests
    workspace.write_job_manifest(
        {
            "run_id": run_id,
            "config": manifest_config,
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
    logger.info("created run %s -> %s", run_id, str(run_config.ocsp_url).replace("\r", "\\r").replace("\n", "\\n"))
    return run_to_summary(run)


@router.post("/test-runs/{run_id}/rerun", response_model=RunSummary, status_code=201)
async def rerun_run(
    run_id: RunID,
    ctx: WorkspaceContext = Depends(active_workspace(Role.member)),
    session: AsyncSession = Depends(get_session),
) -> RunSummary:
    """Start a new run reusing a previous run's configuration and its already
    uploaded certificates, without re-selecting files. The original run and its
    results are kept intact — this creates a separate new run."""
    settings = get_settings()
    prior = await _get_run_or_404(session, run_id, ctx)

    prior_config = dict(prior.config)
    prior_files = dict(prior_config.get("files", {}) or {})

    # Reconstruct a clean RunConfig from the stored config (drop run-only keys).
    raw = {k: v for k, v in prior_config.items() if k in RunConfig.model_fields}
    # The certificates are copied as concrete files below, so this run no longer
    # depends on the CA library entries the original may have referenced.
    raw["saved_certs"] = {}
    try:
        run_config = RunConfig.model_validate(raw)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422, detail=f"Stored run configuration is invalid: {exc.errors()}"
        ) from exc

    # The prior workspace holds the uploaded certs; they must still exist (they
    # are removed by retention cleanup after the configured window).
    prior_ws = RunWorkspace(settings, run_id)
    if not (prior_ws.uploads / UPLOAD_SLOTS["issuer_cert"]).is_file():
        raise HTTPException(
            status_code=409,
            detail=(
                "The original run's certificates are no longer available "
                "(they were likely removed by retention cleanup). Start a new run instead."
            ),
        )

    policy = _workspace_policy(ctx)
    try:
        validate_url(run_config.ocsp_url, policy)
        for crl_url in run_config.crl_urls:
            validate_url(crl_url, policy)
    except BlockedTargetError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    selection = run_config.test_selection
    resolved_tests: Optional[dict] = None
    if selection.mode == "custom":
        error = validate_selection(selection.tests)
        if error:
            raise HTTPException(status_code=400, detail=error)
        resolved_tests = selection.tests
    elif selection.mode == "global":
        resolved_tests = await load_global_selection(session)

    manager = get_job_manager()
    ws_limit = min(ctx.workspace.max_concurrent_runs, settings.max_concurrent_runs)
    if await _active_run_count(session, ctx.workspace.id) >= ws_limit:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum of {ws_limit} concurrent runs reached for this workspace; try again later",
        )

    new_run_id = str(uuid.uuid4())
    workspace = RunWorkspace(settings, new_run_id).create()
    stored_files: dict[str, str] = {}
    file_names: dict[str, str] = {}
    try:
        for slot, display in prior_files.items():
            if slot not in UPLOAD_SLOTS:
                continue
            src = prior_ws.uploads / UPLOAD_SLOTS[slot]
            if not src.is_file():
                continue
            dest = workspace.save_upload(slot, src.read_bytes(), sensitive=(slot == "client_key"))
            stored_files[slot] = str(dest)
            file_names[slot] = display
        if "issuer_cert" not in stored_files:
            raise HTTPException(
                status_code=409,
                detail="The original run's issuer certificate is no longer available. Start a new run instead.",
            )
    except HTTPException:
        workspace.delete()
        raise

    stored_config = run_config.model_dump()
    stored_config["files"] = file_names
    stored_config["resolved_test_selection"] = resolved_tests
    stored_config["rerun_of"] = run_id

    run = Run(
        id=new_run_id,
        workspace_id=ctx.workspace.id,
        created_by_user_id=ctx.principal.user.id or None,
        name=run_config.name,
        ocsp_url=run_config.ocsp_url,
        status="queued",
        config_json=json.dumps(stored_config),
    )
    session.add(run)
    await session.commit()

    manifest_config = run_config.model_dump()
    manifest_config["resolved_test_selection"] = resolved_tests
    workspace.write_job_manifest(
        {
            "run_id": new_run_id,
            "config": manifest_config,
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

    await manager.start_run(new_run_id)
    await session.refresh(run)
    logger.info("reran run %s as %s -> %s", str(run_id).replace("\r", "\\r").replace("\n", "\\n"), new_run_id, str(run_config.ocsp_url).replace("\r", "\\r").replace("\n", "\\n"))
    return run_to_summary(run)


@router.get("/test-runs", response_model=RunList)
async def list_runs(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = None,
    ctx: WorkspaceContext = Depends(active_workspace(Role.viewer)),
    session: AsyncSession = Depends(get_session),
) -> RunList:
    stmt = _visibility_filter(select(Run).where(Run.workspace_id == ctx.workspace.id), ctx)
    count_stmt = _visibility_filter(
        select(func.count(Run.id)).where(Run.workspace_id == ctx.workspace.id), ctx
    )
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
async def get_run(
    run_id: RunID,
    ctx: WorkspaceContext = Depends(active_workspace(Role.viewer)),
    session: AsyncSession = Depends(get_session),
) -> RunDetail:
    run = await _get_run_or_404(session, run_id, ctx)
    return run_to_detail(run)


@router.get("/test-runs/{run_id}/results", response_model=ResultList)
async def get_results(
    run_id: RunID,
    category: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
    ctx: WorkspaceContext = Depends(active_workspace(Role.viewer)),
    session: AsyncSession = Depends(get_session),
) -> ResultList:
    await _get_run_or_404(session, run_id, ctx)
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
    run_id: RunID,
    after_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=1000, ge=1, le=10000),
    ctx: WorkspaceContext = Depends(active_workspace(Role.viewer)),
    session: AsyncSession = Depends(get_session),
) -> LogList:
    run = await _get_run_or_404(session, run_id, ctx)
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
async def export_json(
    run_id: RunID,
    ctx: WorkspaceContext = Depends(active_workspace(Role.viewer)),
    session: AsyncSession = Depends(get_session),
) -> JSONResponse:
    run = await _get_run_or_404(session, run_id, ctx)
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
async def export_csv(
    run_id: RunID,
    ctx: WorkspaceContext = Depends(active_workspace(Role.viewer)),
    session: AsyncSession = Depends(get_session),
) -> PlainTextResponse:
    await _get_run_or_404(session, run_id, ctx)
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


@router.post("/test-runs/{run_id}/profile", response_model=ProfileOut, status_code=201)
async def save_run_as_profile(
    run_id: RunID,
    payload: RunProfileIn,
    ctx: WorkspaceContext = Depends(active_workspace(Role.member)),
    session: AsyncSession = Depends(get_session),
) -> ProfileOut:
    """Save an existing run's configuration as a reusable profile."""
    from .profiles import _check_name_free, _to_out

    run = await _get_run_or_404(session, run_id, ctx)
    # The stored run config carries run-only bookkeeping ("files",
    # "resolved_test_selection"); keep only real RunConfig fields.
    raw = {k: v for k, v in run.config.items() if k in RunConfig.model_fields}
    try:
        config = RunConfig.model_validate(raw)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422, detail=f"Run configuration cannot be saved as a profile: {exc.errors()}"
        ) from exc

    await _check_name_free(session, ctx.workspace.id, payload.name)
    profile = Profile(
        workspace_id=ctx.workspace.id,
        created_by_user_id=ctx.principal.user.id or None,
        name=payload.name,
        description=payload.description,
        config_json=json.dumps(config.model_dump(exclude={"profile_id"})),
    )
    session.add(profile)
    await session.commit()
    await session.refresh(profile)
    logger.info("saved run %s as profile %r", str(run_id).replace("\r", "\\r").replace("\n", "\\n"), str(payload.name).replace("\r", "\\r").replace("\n", "\\n"))
    return _to_out(profile)


@router.post("/test-runs/{run_id}/cancel", response_model=RunSummary)
async def cancel_run(
    run_id: RunID,
    ctx: WorkspaceContext = Depends(active_workspace(Role.member)),
    session: AsyncSession = Depends(get_session),
) -> RunSummary:
    run = await _get_run_or_404(session, run_id, ctx)
    if run.status in TERMINAL_STATUSES:
        raise HTTPException(status_code=409, detail=f"Run already finished with status {run.status}")
    await get_job_manager().cancel_run(run_id)
    await session.refresh(run)
    return run_to_summary(run)


@router.delete("/test-runs/{run_id}", status_code=204)
async def delete_run(
    run_id: RunID,
    ctx: WorkspaceContext = Depends(active_workspace(Role.member)),
    session: AsyncSession = Depends(get_session),
) -> Response:
    run = await _get_run_or_404(session, run_id, ctx)
    if run.status not in TERMINAL_STATUSES:
        await get_job_manager().cancel_run(run_id)
    await session.delete(run)
    await session.commit()
    RunWorkspace(get_settings(), run_id).delete()
    return Response(status_code=204)
