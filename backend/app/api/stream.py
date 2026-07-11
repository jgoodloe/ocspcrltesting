"""Live run streaming over WebSocket with an SSE fallback.

Events are read from the persisted ``run_events`` table (so reconnects can
resume from any sequence number and streams work across multiple server
workers) and the in-process notifier is used only as a low-latency wakeup.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncIterator, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from starlette.websockets import WebSocket, WebSocketDisconnect

from ..authz import Principal, authorize_run_view, current_principal, principal_from_websocket
from ..db import get_session, session_factory
from ..jobs import TERMINAL_STATUSES, get_job_manager
from ..orm import Run, RunEvent

from ..logging_config import log_safe

logger = logging.getLogger("ocspweb.api.stream")

router = APIRouter(tags=["stream"])

POLL_INTERVAL_SECONDS = 1.0


async def _fetch_events(run_id: str, after_seq: int, limit: int = 500) -> List[RunEvent]:
    async with session_factory()() as session:
        stmt = (
            select(RunEvent)
            .where(RunEvent.run_id == run_id, RunEvent.seq > after_seq)
            .order_by(RunEvent.seq)
            .limit(limit)
        )
        return list((await session.execute(stmt)).scalars().all())


async def _run_status(run_id: str) -> Optional[str]:
    async with session_factory()() as session:
        run = await session.get(Run, run_id)
        return run.status if run else None


async def _load_run(run_id: str) -> Optional[Run]:
    async with session_factory()() as session:
        return await session.get(Run, run_id)


def _wire_event(run_id: str, event: RunEvent) -> dict:
    return {"seq": event.seq, "type": event.type, "run_id": run_id, "data": event.payload}


async def _event_stream(run_id: str, after_seq: int) -> AsyncIterator[dict]:
    """Yield wire events until the run is terminal and fully flushed."""
    manager = get_job_manager()
    last_seq = after_seq
    while True:
        events = await _fetch_events(run_id, last_seq)
        for event in events:
            last_seq = event.seq
            yield _wire_event(run_id, event)
        if not events:
            status = await _run_status(run_id)
            if status is None:
                return
            if status in TERMINAL_STATUSES:
                # Final flush guards against events committed after the check.
                for event in await _fetch_events(run_id, last_seq):
                    last_seq = event.seq
                    yield _wire_event(run_id, event)
                return
            await manager.notifier.wait(run_id, timeout=POLL_INTERVAL_SECONDS)


@router.websocket("/test-runs/{run_id}/stream")
async def stream_ws(websocket: WebSocket, run_id: str, after_seq: int = Query(default=0, ge=0)) -> None:
    async with session_factory()() as session:
        principal = await principal_from_websocket(websocket, session)
        if principal is None:
            await websocket.close(code=1008, reason="Authentication required")
            return
        run = await session.get(Run, run_id)
        if run is None:
            await websocket.close(code=4404, reason="Test run not found")
            return
        if not await authorize_run_view(session, principal, run):
            await websocket.close(code=4404, reason="Test run not found")
            return
    await websocket.accept()
    try:
        async for event in _event_stream(run_id, after_seq):
            await websocket.send_text(json.dumps(event, default=str))
        await websocket.close(code=1000)
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("websocket stream for run %s failed", log_safe(run_id))
        try:
            await websocket.close(code=1011)
        except RuntimeError:
            pass


@router.get("/test-runs/{run_id}/stream/sse")
async def stream_sse(
    request: Request,
    run_id: str,
    after_seq: int = Query(default=0, ge=0),
    principal: Principal = Depends(current_principal),
    session=Depends(get_session),
) -> StreamingResponse:
    run = await session.get(Run, run_id)
    if run is None or not await authorize_run_view(session, principal, run):
        raise HTTPException(status_code=404, detail="Test run not found")

    last_event_id = request.headers.get("Last-Event-ID")
    if last_event_id and last_event_id.isdigit():
        after_seq = max(after_seq, int(last_event_id))

    async def generate() -> AsyncIterator[str]:
        try:
            async for event in _event_stream(run_id, after_seq):
                if await request.is_disconnected():
                    return
                yield f"id: {event['seq']}\ndata: {json.dumps(event, default=str)}\n\n"
            yield "event: end\ndata: {}\n\n"
        except asyncio.CancelledError:
            return

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering for SSE
            "Connection": "keep-alive",
        },
    )
