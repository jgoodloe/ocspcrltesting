"""Pydantic request/response schemas (the shapes documented in docs/API.md)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

RunStatus = Literal["queued", "running", "completed", "failed", "cancelled", "timed_out"]
ResultStatus = Literal["PASS", "FAIL", "WARN", "SKIP", "ERROR"]

CATEGORY_KEYS = (
    "protocol",
    "status",
    "crl",
    "path_validation",
    "ikev2",
    "federal",
    "performance",
    "security",
)


class Categories(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: bool = True
    status: bool = True
    crl: bool = True
    path_validation: bool = True
    ikev2: bool = False
    federal: bool = False
    performance: bool = False
    security: bool = True

    def enabled(self) -> List[str]:
        return [k for k in CATEGORY_KEYS if getattr(self, k)]


class TestSelection(BaseModel):
    """Fine-grained choice of which individual tests run.

    ``mode``:
      - ``all``    — every test in each enabled category (default).
      - ``global`` — apply the server-wide selection stored in settings.
      - ``custom`` — apply ``tests`` from this config only.

    ``tests`` maps a category key to the list of selected test names; a
    category absent from the map runs all of its tests.
    """

    model_config = ConfigDict(extra="forbid")

    mode: Literal["all", "global", "custom"] = "all"
    tests: Dict[str, List[str]] = Field(default_factory=dict)


class RunConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, max_length=200)
    ocsp_url: str = Field(min_length=1, max_length=2000)
    crl_urls: List[str] = Field(default_factory=list, max_length=10)
    request_method: Literal["auto", "get", "post"] = "auto"
    nonce_enabled: bool = True
    nonce_length: int = Field(default=32, ge=1, le=128)
    latency_samples: int = Field(default=5, ge=1, le=100)
    enable_load_test: bool = False
    load_concurrency: int = Field(default=5, ge=1, le=64)
    load_requests: int = Field(default=50, ge=1, le=2000)
    timeout_seconds: int = Field(default=10, ge=1, le=120)
    run_timeout_seconds: int = Field(default=900, ge=30, le=7200)
    max_age_hours: int = Field(default=24, ge=1, le=8760)
    trust_anchor_type: Literal["root", "intermediate"] = "root"
    require_explicit_policy: bool = False
    inhibit_policy_mapping: bool = False
    categories: Categories = Field(default_factory=Categories)
    test_selection: TestSelection = Field(default_factory=TestSelection)
    # Saved CA library references: {upload slot -> CACertificate id}. The
    # referenced certificate is materialized into the run workspace exactly
    # like an uploaded file. Client TLS material can never come from the
    # library.
    saved_certs: Dict[str, int] = Field(default_factory=dict)
    profile_id: Optional[int] = None

    @field_validator("saved_certs")
    @classmethod
    def _saved_cert_slots(cls, v: Dict[str, int]) -> Dict[str, int]:
        allowed = {"issuer_cert", "good_cert", "revoked_cert", "unknown_ca_cert", "trust_anchor"}
        for slot in v:
            if slot not in allowed:
                raise ValueError(f"saved_certs slot must be one of {sorted(allowed)}, got {slot!r}")
        return v

    @field_validator("ocsp_url", "crl_urls")
    @classmethod
    def _must_be_http(cls, v: Any) -> Any:
        urls = v if isinstance(v, list) else [v]
        for url in urls:
            if not url.lower().startswith(("http://", "https://")):
                raise ValueError(f"URL must be http(s): {url}")
        return v


class Totals(BaseModel):
    total: int = 0
    pass_: int = Field(default=0, alias="pass")
    fail: int = 0
    warn: int = 0
    skip: int = 0
    error: int = 0

    model_config = ConfigDict(populate_by_name=True)


class LatencySummary(BaseModel):
    median_ms: Optional[int] = None
    min_ms: Optional[int] = None
    max_ms: Optional[int] = None
    samples: int = 0


class RunSummary(BaseModel):
    id: str
    name: Optional[str] = None
    ocsp_url: str
    status: RunStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    totals: Dict[str, int] = Field(default_factory=dict)
    latency: Optional[LatencySummary] = None
    categories: List[str] = Field(default_factory=list)
    current_activity: Optional[str] = None
    error: Optional[str] = None


class RunDetail(RunSummary):
    config: Dict[str, Any] = Field(default_factory=dict)


class RunList(BaseModel):
    items: List[RunSummary]
    total: int


class TestResultOut(BaseModel):
    id: str
    category: str
    name: str
    status: ResultStatus
    message: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    duration_ms: Optional[int] = None


class ResultList(BaseModel):
    items: List[TestResultOut]
    total: int


class LogLine(BaseModel):
    seq: int
    ts: datetime
    level: str = "INFO"
    message: str


class LogList(BaseModel):
    items: List[LogLine]
    last_seq: int


class CertMetadata(BaseModel):
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    key_algorithm: str
    signature_algorithm: str
    signature_algorithm_oid: str
    ski: Optional[str] = None
    aki: Optional[str] = None
    aia_ocsp_urls: List[str] = Field(default_factory=list)
    aia_ca_issuers: List[str] = Field(default_factory=list)
    crl_distribution_points: List[str] = Field(default_factory=list)
    is_ca: bool = False
    expired: bool = False
    self_signed: bool = False


class ProfileIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    config: RunConfig


class ProfileOut(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ProfileList(BaseModel):
    items: List[ProfileOut]


class CatalogTestOut(BaseModel):
    name: str
    description: str = ""
    dynamic: bool = False
    # What the test exercises: "ocsp" | "crl" | "crl+ocsp" | "path" | "ikev2"
    scope: str = "ocsp"


class CatalogCategoryOut(BaseModel):
    key: str
    label: str
    tests: List[CatalogTestOut]


class TestCatalogOut(BaseModel):
    categories: List[CatalogCategoryOut]


class GlobalTestSelection(BaseModel):
    """Server-wide default test selection, applied to runs whose config uses
    ``test_selection.mode == "global"``. ``tests = null`` means run all."""

    model_config = ConfigDict(extra="forbid")

    tests: Optional[Dict[str, List[str]]] = None
    updated_at: Optional[datetime] = None


class CACertOut(BaseModel):
    id: int
    name: str
    subject: str
    issuer: str
    serial_number: str
    fingerprint_sha256: str
    not_before: datetime
    not_after: datetime
    is_ca: bool
    expired: bool
    self_signed: bool
    source: str
    source_url: Optional[str] = None
    created_at: datetime


class CertExtensions(BaseModel):
    """Commonly-inspected X.509 v3 extensions, parsed for display."""

    subject_alt_names: List[str] = Field(default_factory=list)
    key_usage: List[str] = Field(default_factory=list)
    extended_key_usage: List[str] = Field(default_factory=list)
    certificate_policies: List[str] = Field(default_factory=list)
    aia_ocsp_urls: List[str] = Field(default_factory=list)
    aia_ca_issuers: List[str] = Field(default_factory=list)
    crl_distribution_points: List[str] = Field(default_factory=list)
    subject_key_identifier: Optional[str] = None
    authority_key_identifier: Optional[str] = None


class CACertDetail(CACertOut):
    """Full saved-certificate record, including the stored PEM for inspection
    and download, plus parsed v3 extensions."""

    pem: str
    extensions: CertExtensions = Field(default_factory=CertExtensions)


class CACertList(BaseModel):
    items: List[CACertOut]


class ShareIn(BaseModel):
    """Copy a profile or saved certificate into another workspace."""

    model_config = ConfigDict(extra="forbid")

    target_workspace_id: int


class CACertUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)


class CACertImportResult(BaseModel):
    created: List[CACertOut]
    skipped_duplicates: int = 0


class CACertFetchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=2000)
    name: Optional[str] = Field(default=None, max_length=200)

    @field_validator("url")
    @classmethod
    def _must_be_http(cls, v: str) -> str:
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("URL must be http(s)")
        return v


class WellKnownCA(BaseModel):
    key: str
    name: str
    url: str
    description: str = ""


class WellKnownCAList(BaseModel):
    items: List[WellKnownCA]


class RunProfileIn(BaseModel):
    """Payload for saving a finished run's configuration as a profile."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)


Role = Literal["viewer", "member", "admin"]
RunVisibility = Literal["all", "own"]


class UserOut(BaseModel):
    id: int
    provider: str
    subject: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    is_global_admin: bool = False
    is_active: bool = True
    created_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024)


class AuthConfigOut(BaseModel):
    """What the login page needs to render (no secrets)."""

    auth_required: bool
    local_login_enabled: bool
    oidc_enabled: bool
    oidc_login_url: Optional[str] = None


class WorkspaceOut(BaseModel):
    id: int
    name: str
    kind: str
    run_visibility: RunVisibility
    allow_private_targets: bool
    max_concurrent_runs: int
    oidc_group_admin: Optional[str] = None
    oidc_group: Optional[str] = None  # member tier
    oidc_group_viewer: Optional[str] = None
    role: Optional[Role] = None  # the requesting user's role in this workspace
    created_at: Optional[datetime] = None


class MeOut(BaseModel):
    user: UserOut
    workspaces: List[WorkspaceOut] = Field(default_factory=list)


class WorkspaceCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)


class WorkspaceUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    run_visibility: Optional[RunVisibility] = None
    allow_private_targets: Optional[bool] = None
    max_concurrent_runs: Optional[int] = Field(default=None, ge=1, le=64)
    oidc_group_admin: Optional[str] = Field(default=None, max_length=200)
    oidc_group: Optional[str] = Field(default=None, max_length=200)
    oidc_group_viewer: Optional[str] = Field(default=None, max_length=200)


class MemberOut(BaseModel):
    user_id: int
    role: Role
    email: Optional[str] = None
    display_name: Optional[str] = None
    provider: Optional[str] = None
    source: Optional[str] = None  # "manual" | "oidc" (how the membership was granted)


class MemberList(BaseModel):
    items: List[MemberOut]


class MemberAddIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Add by existing user id, or by email (must already exist as a user).
    user_id: Optional[int] = None
    email: Optional[str] = Field(default=None, max_length=320)
    role: Role = "member"


class MemberRoleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role


class TokenOut(BaseModel):
    id: int
    name: str
    workspace_id: Optional[int] = None
    role_ceiling: Role
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


class TokenList(BaseModel):
    items: List[TokenOut]


class TokenCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    workspace_id: Optional[int] = None
    role_ceiling: Role = "viewer"


class TokenCreatedOut(TokenOut):
    token: str  # shown exactly once


class LocalUserCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=8, max_length=1024)
    display_name: Optional[str] = Field(default=None, max_length=200)
    is_global_admin: bool = False


class AuditEntryOut(BaseModel):
    id: int
    ts: datetime
    actor: Optional[str] = None
    event: str
    workspace_id: Optional[int] = None
    target: Optional[str] = None
    detail: Dict[str, Any] = Field(default_factory=dict)


class AuditList(BaseModel):
    items: List[AuditEntryOut]
    total: int


class HealthOut(BaseModel):
    status: str
    database: str
    openssl: Optional[str] = None
    time: datetime


class VersionOut(BaseModel):
    name: str
    version: str
    engine: str = "ocsp_tester"
