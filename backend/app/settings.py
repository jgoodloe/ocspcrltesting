"""Application settings.

Every security-sensitive knob is an environment variable with the ``OCSPWEB_``
prefix so deployments can be configured without touching code. See
``.env.example`` at the repository root for documentation of each variable.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OCSPWEB_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- deployment ---
    base_path: str = Field(default="", description="Public base path when served under a subpath, e.g. /ocsp")
    public_base_url: str = Field(default="", description="Optional absolute public URL, e.g. https://ocsp.example.com")
    data_dir: Path = Field(default=REPO_ROOT / "data")
    frontend_dist: Path = Field(default=REPO_ROOT / "frontend" / "dist")
    database_url: str = Field(default="", description="SQLAlchemy async URL; defaults to sqlite in data_dir")

    # --- auth / CORS ---
    auth_username: str = "admin"
    auth_password: str = Field(default="", description="Enable HTTP Basic auth when non-empty")
    cors_origins: str = Field(default="", description="Comma-separated allowed origins; empty disables CORS headers")

    # --- uploads / retention ---
    max_upload_bytes: int = 5 * 1024 * 1024
    retention_days: int = Field(default=30, description="Run workspaces and records older than this are purged")
    retention_sweep_minutes: int = 60

    # --- execution ---
    max_concurrent_runs: int = 2
    default_run_timeout_seconds: int = 900
    max_run_timeout_seconds: int = 7200
    worker_python: str = Field(default="", description="Python interpreter for run workers; defaults to sys.executable")

    # --- outbound request policy (SSRF protection) ---
    allow_private_targets: bool = Field(
        default=False,
        description="Allow OCSP/CRL targets on loopback/private/link-local networks (internal lab use)",
    )
    allow_redirects: bool = False
    max_response_bytes: int = 10 * 1024 * 1024
    max_request_timeout_seconds: int = 60
    extra_blocked_hosts: str = Field(default="", description="Comma-separated additional hostnames/IPs to block")

    log_level: str = "INFO"
    log_json: bool = False

    @field_validator("base_path")
    @classmethod
    def _normalize_base_path(cls, v: str) -> str:
        v = v.strip()
        if not v or v == "/":
            return ""
        if not v.startswith("/"):
            v = "/" + v
        return v.rstrip("/")

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite+aiosqlite:///{self.data_dir / 'ocspweb.sqlite3'}"

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def extra_blocked_host_list(self) -> List[str]:
        return [h.strip().lower() for h in self.extra_blocked_hosts.split(",") if h.strip()]

    @property
    def auth_enabled(self) -> bool:
        return bool(self.auth_password)


@lru_cache
def get_settings() -> Settings:
    return Settings()
