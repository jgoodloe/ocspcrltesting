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


class CACertList(BaseModel):
    items: List[CACertOut]


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


class HealthOut(BaseModel):
    status: str
    database: str
    openssl: Optional[str] = None
    time: datetime


class VersionOut(BaseModel):
    name: str
    version: str
    engine: str = "ocsp_tester"
