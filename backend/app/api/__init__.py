from fastapi import APIRouter, Depends

from ..auth import require_auth
from . import certs, health, profiles, runs, stream


def build_api_router() -> APIRouter:
    router = APIRouter(prefix="/api")
    # HTTP routers share the basic-auth dependency; the stream router manages
    # auth itself because WebSocket routes cannot use Request-based dependencies.
    for http_router in (health.router, certs.router, runs.router, profiles.router):
        router.include_router(http_router, dependencies=[Depends(require_auth)])
    router.include_router(stream.router)
    return router
