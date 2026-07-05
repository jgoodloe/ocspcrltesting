"""Append-only audit logging helper."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from .orm import AuditLog, User

logger = logging.getLogger("ocspweb.audit")


async def record(
    session: AsyncSession,
    event: str,
    *,
    user: Optional[User] = None,
    actor: Optional[str] = None,
    workspace_id: Optional[int] = None,
    target: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
    commit: bool = True,
) -> None:
    """Write an audit row. Never raises into the caller — auditing must not
    break the operation it records."""
    try:
        row = AuditLog(
            event=event,
            user_id=(user.id if user and user.id else None),
            actor=actor or (user.email or user.display_name or user.subject if user else None),
            workspace_id=workspace_id,
            target=target,
            detail_json=json.dumps(detail or {}, default=str),
        )
        session.add(row)
        if commit:
            await session.commit()
    except Exception:
        logger.exception("failed to write audit event %s", event)
