"""Optional shared-password HTTP Basic authentication."""

from __future__ import annotations

import base64
import secrets
from typing import Optional

from fastapi import HTTPException, Request, status
from starlette.websockets import WebSocket

from .settings import get_settings


def _check_basic_header(header: Optional[str]) -> bool:
    settings = get_settings()
    if not header or not header.lower().startswith("basic "):
        return False
    try:
        decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
        username, _, password = decoded.partition(":")
    except Exception:
        return False
    return secrets.compare_digest(username, settings.auth_username) and secrets.compare_digest(
        password, settings.auth_password
    )


async def require_auth(request: Request) -> None:
    """FastAPI dependency enforcing basic auth when a password is configured."""
    settings = get_settings()
    if not settings.auth_enabled:
        return
    if _check_basic_header(request.headers.get("Authorization")):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": 'Basic realm="OCSP Testing"'},
    )


async def websocket_authorized(websocket: WebSocket) -> bool:
    settings = get_settings()
    if not settings.auth_enabled:
        return True
    return _check_basic_header(websocket.headers.get("Authorization"))
