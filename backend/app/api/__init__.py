from fastapi import APIRouter, Depends

from ..authz import current_principal
from . import (
    admin,
    auth,
    ca_certs,
    catalog,
    certs,
    health,
    profiles,
    runs,
    stream,
    tokens,
    workspaces,
)


def build_api_router() -> APIRouter:
    router = APIRouter(prefix="/api")
    # Authentication and authorization are enforced per-route: workspace-scoped
    # routers depend on ``active_workspace``/``require_workspace`` and the
    # admin/token routers on ``current_principal``. The auth router itself must
    # stay open (it is the login path), and health is intentionally public.
    for http_router in (
        health.router,
        auth.router,
        runs.router,
        profiles.router,
        ca_certs.router,
        workspaces.router,
        tokens.router,
        admin.router,
    ):
        router.include_router(http_router)
    # Stateless helpers (cert inspection, catalog) are not workspace-scoped but
    # still require an authenticated principal when auth is active.
    for guarded in (certs.router, catalog.router):
        router.include_router(guarded, dependencies=[Depends(current_principal)])
    router.include_router(stream.router)
    return router
