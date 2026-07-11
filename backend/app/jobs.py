"""Run supervision: worker subprocess lifecycle, event persistence, wakeups.

Each test run executes in its own subprocess (``python -m backend.app.worker``)
so a hung OCSP responder or a crashing OpenSSL call can never block or take
down the API server, and cancellation/timeout are a process-group kill rather
than a cooperative hope. The supervisor consumes the worker's JSONL event
stream, persists every event (source of truth for stream replay), and wakes
in-process stream subscribers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set

from sqlalchemy import func, select, update

from .db import session_factory
from .orm import Result, Run, RunEvent, utcnow
from .settings import Settings, get_settings
from .storage import RunWorkspace

logger = logging.getLogger("ocspweb.jobs")

TERMINAL_STATUSES = {"completed", "failed", "cancelled", "timed_out"}
CANCEL_GRACE_SECONDS = 5.0


class RunNotifier:
    """Per-run wakeup for stream subscribers in this process."""

    def __init__(self) -> None:
        self._events: Dict[str, asyncio.Event] = {}

    def signal(self, run_id: str) -> None:
        event = self._events.get(run_id)
        if event:
            event.set()

    async def wait(self, run_id: str, timeout: float) -> None:
        event = self._events.setdefault(run_id, asyncio.Event())
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return
        finally:
            event.clear()

    def discard(self, run_id: str) -> None:
        self._events.pop(run_id, None)


class JobManager:
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.notifier = RunNotifier()
        self._processes: Dict[str, asyncio.subprocess.Process] = {}
        self._tasks: Set[asyncio.Task] = set()
        self._cancel_requested: Set[str] = set()

    def _track(self, task: asyncio.Task) -> asyncio.Task:
        """Register a task so shutdown can drain it. Every task the manager
        spawns (supervisors, stderr drainers, cancel-escalators) is tracked;
        leaving any pending when the event loop closes hangs anyio's test
        portal on Python <= 3.11."""
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    # ---- lifecycle -----------------------------------------------------

    async def active_run_count(self) -> int:
        async with session_factory()() as session:
            stmt = select(func.count(Run.id)).where(Run.status.in_(("queued", "running")))
            return int((await session.execute(stmt)).scalar_one())

    async def start_run(self, run_id: str) -> None:
        workspace = RunWorkspace(self.settings, run_id)
        python = self.settings.worker_python or sys.executable
        repo_root = Path(__file__).resolve().parents[2]

        env = dict(os.environ)
        env.setdefault("PYTHONUNBUFFERED", "1")

        process = await asyncio.create_subprocess_exec(
            python,
            "-m",
            "backend.app.worker",
            str(workspace.root),
            cwd=str(repo_root),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # own process group: kill() reaches openssl children
            env=env,
        )
        self._processes[run_id] = process
        await self._update_run(run_id, status="running", started_at=utcnow())
        await self._append_event(run_id, "run_status", await self._run_snapshot(run_id))

        self._track(asyncio.create_task(self._supervise(run_id, process)))
        logger.info("run %s: worker pid %s started", run_id, process.pid)

    async def cancel_run(self, run_id: str) -> bool:
        """Request cooperative cancel, escalate to SIGKILL after a grace period."""
        workspace = RunWorkspace(self.settings, run_id)
        workspace.request_cancel()
        self._cancel_requested.add(run_id)
        process = self._processes.get(run_id)
        if process is None:
            # No live process in this worker (e.g. other gunicorn worker or stale
            # row): mark cancelled directly if the run is not terminal.
            return await self._finalize_if_not_terminal(run_id, "cancelled", "cancelled by user")

        async def _escalate() -> None:
            await asyncio.sleep(CANCEL_GRACE_SECONDS)
            if process.returncode is None:
                self._kill_group(process)

        self._track(asyncio.create_task(_escalate()))
        return True

    def _kill_group(self, process: asyncio.subprocess.Process) -> None:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                process.kill()
            except ProcessLookupError:
                pass

    async def shutdown(self) -> None:
        """Drain every worker and task while the loop still runs normally.

        Killing subprocesses without reaping them, or cancelling tasks
        without awaiting them, leaves the reaper/reader machinery pending
        when the event loop is torn down. On Python <= 3.11 (notably under
        the anyio blocking portal that Starlette's TestClient uses) that
        makes loop-close ``_cancel_all_tasks`` hang forever. So we kill, reap
        with a timeout, then cancel and gather all tracked tasks here."""
        processes = list(self._processes.items())
        for run_id, process in processes:
            logger.warning("shutdown: killing worker for run %s", run_id)
            self._kill_group(process)
        for run_id, process in processes:
            try:
                await asyncio.wait_for(process.wait(), timeout=CANCEL_GRACE_SECONDS)
            except (asyncio.TimeoutError, ProcessLookupError):
                pass
            except Exception:  # never let reaping abort shutdown
                logger.exception("shutdown: error reaping worker for run %s", run_id)
        self._processes.clear()

        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True), timeout=10.0
                )
            except asyncio.TimeoutError:
                logger.warning("shutdown: %d task(s) did not drain within 10s", len(tasks))

    async def mark_orphans_failed(self) -> None:
        """At boot, no workers exist: any queued/running rows are stale."""
        async with session_factory()() as session:
            await session.execute(
                update(Run)
                .where(Run.status.in_(("queued", "running")))
                .values(status="failed", error="Server restarted while the run was in progress", finished_at=utcnow())
            )
            await session.commit()

    # ---- supervision ----------------------------------------------------

    async def _supervise(self, run_id: str, process: asyncio.subprocess.Process) -> None:
        run_timeout = await self._run_timeout(run_id)
        stderr_task = self._track(asyncio.create_task(self._drain_stderr(run_id, process)))
        terminal_from_worker: Optional[str] = None
        worker_error: Optional[str] = None
        latency: Optional[Dict[str, Any]] = None
        async def _consume() -> None:
            nonlocal terminal_from_worker, worker_error, latency
            assert process.stdout is not None
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                event = self._parse_event(line)
                if event is None:
                    continue
                etype = event.pop("type", "log")
                event.pop("ts", None)
                if etype == "done":
                    terminal_from_worker = event.get("status", "completed")
                    worker_error = event.get("error")
                    latency = event.get("latency")
                elif etype == "fatal":
                    terminal_from_worker = "failed"
                    worker_error = event.get("error", "worker failed")
                    await self._append_event(
                        run_id, "log", {"level": "ERROR", "message": f"Run failed: {worker_error}"}
                    )
                else:
                    await self._handle_event(run_id, etype, event)
            await process.wait()

        try:
            try:
                await asyncio.wait_for(_consume(), timeout=run_timeout)
            except asyncio.TimeoutError:
                logger.warning("run %s exceeded timeout of %ss; killing worker", run_id, run_timeout)
                self._kill_group(process)
                await process.wait()
                terminal_from_worker = "timed_out"
                worker_error = f"Run exceeded the configured timeout of {run_timeout} seconds"
                await self._append_event(run_id, "log", {"level": "ERROR", "message": worker_error})
        except Exception:
            logger.exception("run %s: supervisor crashed", run_id)
            terminal_from_worker = "failed"
            worker_error = "internal supervisor error"
        finally:
            stderr_task.cancel()
            self._processes.pop(run_id, None)

        if terminal_from_worker is None:
            # Worker died without a done/fatal event.
            if run_id in self._cancel_requested:
                terminal_from_worker = "cancelled"
                worker_error = "cancelled by user"
            else:
                terminal_from_worker = "failed"
                worker_error = f"Worker exited unexpectedly (code {process.returncode})"
                await self._append_event(run_id, "log", {"level": "ERROR", "message": worker_error})
        elif run_id in self._cancel_requested and terminal_from_worker == "completed":
            terminal_from_worker = "cancelled"

        self._cancel_requested.discard(run_id)
        await self._finalize(run_id, terminal_from_worker, worker_error, latency)

    async def _drain_stderr(self, run_id: str, process: asyncio.subprocess.Process) -> None:
        assert process.stderr is not None
        try:
            while True:
                line = await process.stderr.readline()
                if not line:
                    return
                text = line.decode("utf-8", "replace").rstrip()
                if text:
                    await self._append_event(
                        run_id, "log", {"level": "DEBUG", "message": f"[worker] {text}"}
                    )
        except asyncio.CancelledError:
            return

    def _parse_event(self, line: bytes) -> Optional[Dict[str, Any]]:
        text = line.decode("utf-8", "replace").strip()
        if not text:
            return None
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
        return {"type": "log", "level": "INFO", "message": text}

    # ---- persistence -----------------------------------------------------

    async def _handle_event(self, run_id: str, etype: str, data: Dict[str, Any]) -> None:
        if etype == "result":
            result = data.get("result", {})
            # A single malformed/duplicate result must never abort the run and
            # drop every later category. Persistence is best-effort and isolated.
            try:
                await self._persist_result(run_id, result)
            except Exception:
                logger.exception("run %s: failed to persist result %r", run_id, str(result.get("id")).replace("\r", "\\r").replace("\n", "\\n"))
            await self._append_event(run_id, "result", result)
        elif etype == "progress":
            await self._update_run(run_id, current_activity=data.get("current_activity"))
            await self._append_event(run_id, "progress", data)
        else:  # log and anything unknown
            await self._append_event(run_id, "log", data)

    async def _append_event(self, run_id: str, etype: str, payload: Dict[str, Any]) -> None:
        async with session_factory()() as session:
            run = await session.get(Run, run_id)
            if run is None:
                return
            run.last_seq += 1
            session.add(
                RunEvent(
                    run_id=run_id,
                    seq=run.last_seq,
                    type=etype,
                    payload_json=json.dumps(payload, default=str),
                )
            )
            await session.commit()
        self.notifier.signal(run_id)

    async def _persist_result(self, run_id: str, result: Dict[str, Any]) -> None:
        async with session_factory()() as session:
            run = await session.get(Run, run_id)
            if run is None:
                return
            # Result.id is a global primary key. Guarantee it is unique even if
            # an engine emits a non-unique id (path validation used deterministic
            # ids that collided with prior runs and aborted the whole run). The
            # result dict is mutated so the streamed event uses the same id.
            result_id = str(result.get("id") or uuid.uuid4())
            if await session.get(Result, result_id) is not None:
                result_id = str(uuid.uuid4())
            result["id"] = result_id
            session.add(
                Result(
                    id=result_id,
                    run_id=run_id,
                    category=result.get("category", ""),
                    name=result.get("name", ""),
                    status=result.get("status", "ERROR"),
                    message=result.get("message", ""),
                    details_json=json.dumps(result.get("details", {}), default=str),
                    started_at=_parse_dt(result.get("started_at")),
                    ended_at=_parse_dt(result.get("ended_at")),
                    duration_ms=result.get("duration_ms"),
                )
            )
            totals = run.totals
            totals["total"] = totals.get("total", 0) + 1
            key = result.get("status", "ERROR").lower()
            totals[key] = totals.get(key, 0) + 1
            run.totals_json = json.dumps(totals)
            await session.commit()

    async def _update_run(self, run_id: str, **fields: Any) -> None:
        async with session_factory()() as session:
            await session.execute(update(Run).where(Run.id == run_id).values(**fields))
            await session.commit()

    async def _finalize_if_not_terminal(self, run_id: str, status: str, error: Optional[str]) -> bool:
        async with session_factory()() as session:
            run = await session.get(Run, run_id)
            if run is None or run.status in TERMINAL_STATUSES:
                return False
        await self._finalize(run_id, status, error, None)
        return True

    async def _finalize(
        self, run_id: str, status: str, error: Optional[str], latency: Optional[Dict[str, Any]]
    ) -> None:
        fields: Dict[str, Any] = {
            "status": status,
            "finished_at": utcnow(),
            "current_activity": None,
        }
        if error:
            fields["error"] = error
        if latency is not None:
            fields["latency_json"] = json.dumps(latency)
        await self._update_run(run_id, **fields)
        await self._append_event(run_id, "run_status", await self._run_snapshot(run_id))
        self.notifier.signal(run_id)
        logger.info("run %s finished with status %s", run_id, str(status).replace("\r", "\\r").replace("\n", "\\n"))

    async def _run_snapshot(self, run_id: str) -> Dict[str, Any]:
        from .api.serializers import run_to_summary  # local import to avoid a cycle

        async with session_factory()() as session:
            run = await session.get(Run, run_id)
            if run is None:
                return {}
            return json.loads(run_to_summary(run).model_dump_json())

    async def _run_timeout(self, run_id: str) -> int:
        async with session_factory()() as session:
            run = await session.get(Run, run_id)
            if run is None:
                return self.settings.default_run_timeout_seconds
            configured = int(run.config.get("run_timeout_seconds", self.settings.default_run_timeout_seconds))
            return min(configured, self.settings.max_run_timeout_seconds)


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


_manager: Optional[JobManager] = None


def get_job_manager() -> JobManager:
    global _manager
    if _manager is None:
        _manager = JobManager()
    return _manager


def reset_job_manager() -> None:
    global _manager
    _manager = None
