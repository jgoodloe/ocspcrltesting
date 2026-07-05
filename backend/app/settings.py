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
    # Legacy shared-password Basic auth (deprecated by the multi-user model;
    # retained only so an in-place upgrade keeps working during migration).
    auth_username: str = "admin"
    auth_password: str = Field(default="", description="DEPRECATED shared-password Basic auth")
    cors_origins: str = Field(default="", description="Comma-separated allowed origins; empty disables CORS headers")

    # --- multi-user auth / sessions ---
    # When false, the app runs open (no login) — only intended for isolated
    # single-user/dev use. Any auth configuration below turns it on.
    session_secret: str = Field(
        default="", description="Secret key that signs session cookies; set a stable value in production"
    )
    session_ttl_seconds: int = Field(default=8 * 3600, ge=300)
    session_cookie_name: str = "ocspweb_session"
    session_cookie_secure: bool = Field(default=True, description="Set Secure flag on the session cookie (HTTPS)")

    # Break-glass local admin, created at first boot when no users exist yet.
    bootstrap_admin_username: str = Field(default="admin")
    bootstrap_admin_password: str = Field(
        default="", description="If set, ensures a local global-admin account exists at startup"
    )

    # Local password login (in addition to OIDC). Disable to force OIDC-only
    # (the bootstrap admin still works as break-glass).
    local_login_enabled: bool = True

    # OIDC (authentik). All four must be set to enable the OIDC login button.
    oidc_issuer: str = Field(default="", description="OIDC issuer URL, e.g. https://authentik.example.com/application/o/ocsp/")
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = Field(default="openid email profile", description="Space-separated OIDC scopes")
    oidc_group_claim: str = Field(default="groups", description="Claim carrying group names for optional group sync")

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

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id and self.oidc_client_secret)

    @property
    def oidc_scope_list(self) -> List[str]:
        return [s for s in self.oidc_scopes.split() if s]

    @property
    def session_signing_key(self) -> str:
        """Key used to sign session cookies. A stable value must be set in
        production (multi-worker / restarts); otherwise a random per-process
        key is used and sessions do not survive a restart."""
        if self.session_secret:
            return self.session_secret
        import secrets as _secrets

        # Cache a per-process ephemeral key so it is stable within the process.
        key = getattr(self, "_ephemeral_session_key", None)
        if key is None:
            key = _secrets.token_urlsafe(48)
            object.__setattr__(self, "_ephemeral_session_key", key)
        return key


@lru_cache
def get_settings() -> Settings:
    return Settings()
