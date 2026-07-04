"""FastAPI application factory.

Reverse-proxy behaviour: the app runs happily at ``/`` or under a subpath
(e.g. ``/ocsp``). nginx strips the prefix and forwards
``X-Forwarded-Prefix``; ``OCSPWEB_BASE_PATH`` provides the same information
statically. The SPA's ``<base href>`` tag is rewritten at serve time so all
frontend assets, API calls and WebSocket URLs resolve correctly with no
hardcoded origins anywhere in browser code.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import APP_NAME, __version__
from .api import build_api_router
from .db import dispose_db, init_db
from .jobs import get_job_manager
from .logging_config import configure_logging
from .settings import get_settings
from .storage import sweep_expired_workspaces

logger = logging.getLogger("ocspweb.main")


async def _retention_loop() -> None:
    settings = get_settings()
    interval = max(1, settings.retention_sweep_minutes) * 60
    while True:
        try:
            removed = await asyncio.to_thread(sweep_expired_workspaces, settings)
            if removed:
                logger.info("retention sweep removed %d run workspaces", removed)
        except Exception:
            logger.exception("retention sweep failed")
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.runs_dir.mkdir(parents=True, exist_ok=True)
    await init_db()
    manager = get_job_manager()
    await manager.mark_orphans_failed()
    retention_task = asyncio.create_task(_retention_loop())
    logger.info(
        "%s %s started (base_path=%r, auth=%s, private targets %s)",
        APP_NAME,
        __version__,
        settings.base_path or "/",
        "on" if settings.auth_enabled else "off",
        "allowed" if settings.allow_private_targets else "blocked",
    )
    try:
        yield
    finally:
        retention_task.cancel()
        # Await the cancelled task so no coroutine is left pending when the
        # event loop closes (that hangs anyio's TestClient portal on
        # Python <= 3.11).
        try:
            await retention_task
        except asyncio.CancelledError:
            pass
        await manager.shutdown()
        await dispose_db()


def _load_spa_index(settings) -> Optional[str]:
    index_path = settings.frontend_dist / "index.html"
    if not index_path.is_file():
        return None
    html = index_path.read_text(encoding="utf-8")
    base_href = (settings.base_path or "") + "/"
    return html.replace('<base href="/">', f'<base href="{base_href}">', 1)


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)

    app = FastAPI(
        title="OCSP Testing Web",
        version=__version__,
        root_path=settings.base_path,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        redoc_url=None,
        lifespan=lifespan,
    )

    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    app.include_router(build_api_router())

    # --- SPA (built frontend) -------------------------------------------
    dist = settings.frontend_dist
    assets_dir = dist / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    spa_index = _load_spa_index(settings)

    if spa_index is not None:

        @app.get("/favicon.svg", include_in_schema=False)
        async def favicon() -> FileResponse:
            path = dist / "favicon.svg"
            if path.is_file():
                return FileResponse(path)
            raise HTTPException(status_code=404)

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa(full_path: str) -> HTMLResponse:
            # API 404s must stay JSON; everything else falls through to the SPA
            # router so deep links like /runs/<id> work under any base path.
            if full_path.startswith("api/") or full_path == "api":
                raise HTTPException(status_code=404, detail="Not found")
            return HTMLResponse(spa_index)

    else:

        @app.get("/", include_in_schema=False)
        async def no_frontend() -> JSONResponse:
            return JSONResponse(
                {
                    "detail": "Frontend build not found. Run `npm install && npm run build` in frontend/ "
                    "or use the Docker image. The API is available under /api."
                }
            )

    return app


app = create_app()
