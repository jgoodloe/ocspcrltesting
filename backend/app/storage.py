"""Run workspace management: uploaded files, job manifests, retention cleanup."""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .settings import Settings

logger = logging.getLogger("ocspweb.storage")

# Canonical upload slots -> stored file name. Everything except the client key
# is normalized to PEM at ingest time.
UPLOAD_SLOTS = {
    "issuer_cert": "issuer.pem",
    "good_cert": "good.pem",
    "revoked_cert": "revoked.pem",
    "unknown_ca_cert": "unknown_ca.pem",
    "trust_anchor": "trust_anchor.pem",
    "client_cert": "client_cert.pem",
    "client_key": "client_key.pem",
}


class RunWorkspace:
    def __init__(self, settings: Settings, run_id: str):
        self.run_id = run_id
        self.root = settings.runs_dir / run_id
        self.uploads = self.root / "uploads"

    def create(self) -> "RunWorkspace":
        self.uploads.mkdir(parents=True, exist_ok=True)
        return self

    def save_upload(self, slot: str, data: bytes, sensitive: bool = False) -> Path:
        path = self.uploads / UPLOAD_SLOTS[slot]
        path.write_bytes(data)
        if sensitive:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600 for key material
        return path

    def write_job_manifest(self, manifest: Dict[str, Any]) -> Path:
        path = self.root / "job.json"
        path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
        return path

    @property
    def cancel_flag(self) -> Path:
        return self.root / "cancel"

    def request_cancel(self) -> None:
        try:
            self.cancel_flag.touch()
        except OSError:
            pass

    def delete(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def sweep_expired_workspaces(settings: Settings, now: Optional[datetime] = None) -> int:
    """Delete run workspaces older than the retention window. Returns count."""
    if settings.retention_days <= 0:
        return 0
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=settings.retention_days)
    removed = 0
    runs_dir = settings.runs_dir
    if not runs_dir.exists():
        return 0
    for entry in runs_dir.iterdir():
        if not entry.is_dir():
            continue
        try:
            mtime = datetime.fromtimestamp(entry.stat().st_mtime, tz=timezone.utc)
        except OSError:
            continue
        if mtime < cutoff:
            shutil.rmtree(entry, ignore_errors=True)
            removed += 1
            logger.info("retention sweep removed workspace %s", entry.name)
    return removed
