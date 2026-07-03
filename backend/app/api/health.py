from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .. import APP_NAME, __version__
from ..db import get_session
from ..schemas import HealthOut, VersionOut

router = APIRouter(tags=["meta"])


async def _openssl_version() -> str | None:
    try:
        proc = await asyncio.create_subprocess_exec(
            "openssl", "version", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        return stdout.decode().strip() or None
    except Exception:
        return None


@router.get("/health", response_model=HealthOut)
async def health(session: AsyncSession = Depends(get_session)) -> HealthOut:
    db_status = "ok"
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"
    return HealthOut(
        status="ok" if db_status == "ok" else "degraded",
        database=db_status,
        openssl=await _openssl_version(),
        time=datetime.now(timezone.utc),
    )


@router.get("/version", response_model=VersionOut)
async def version() -> VersionOut:
    return VersionOut(name=APP_NAME, version=__version__)
