"""SQLAlchemy ORM models.

Types are deliberately portable (Text/Integer/DateTime + JSON-as-text) so the
schema can move from SQLite to PostgreSQL without changes.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    ocsp_url: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    current_activity: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    totals_json: Mapped[str] = mapped_column(Text, default="{}")
    latency_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_seq: Mapped[int] = mapped_column(Integer, default=0)

    results: Mapped[list["Result"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    events: Mapped[list["RunEvent"]] = relationship(back_populates="run", cascade="all, delete-orphan")

    @property
    def config(self) -> Dict[str, Any]:
        return json.loads(self.config_json or "{}")

    @property
    def totals(self) -> Dict[str, int]:
        return json.loads(self.totals_json or "{}")


class RunEvent(Base):
    """Append-only event log per run; the source of truth for stream replay."""

    __tablename__ = "run_events"
    __table_args__ = (Index("ix_run_events_run_seq", "run_id", "seq", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    type: Mapped[str] = mapped_column(String(20))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    payload_json: Mapped[str] = mapped_column(Text, default="{}")

    run: Mapped[Run] = relationship(back_populates="events")

    @property
    def payload(self) -> Dict[str, Any]:
        return json.loads(self.payload_json or "{}")


class Result(Base):
    __tablename__ = "results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    category: Mapped[str] = mapped_column(String(60), index=True)
    name: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(10), index=True)
    message: Mapped[str] = mapped_column(Text, default="")
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    run: Mapped[Run] = relationship(back_populates="results")

    @property
    def details(self) -> Dict[str, Any]:
        return json.loads(self.details_json or "{}")


class AppSetting(Base):
    """Simple key/value store for server-wide settings (JSON payloads)."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(60), primary_key=True)
    value_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    @property
    def value(self) -> Dict[str, Any]:
        return json.loads(self.value_json or "{}")


class CACertificate(Base):
    """Saved CA certificate library: commonly used roots and issuing CAs the
    user can reference in a run instead of re-uploading files."""

    __tablename__ = "ca_certificates"
    __table_args__ = (UniqueConstraint("fingerprint_sha256", name="uq_ca_certificates_fingerprint"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200))
    pem: Mapped[str] = mapped_column(Text)
    subject: Mapped[str] = mapped_column(Text)
    issuer: Mapped[str] = mapped_column(Text)
    serial_number: Mapped[str] = mapped_column(Text)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_ca: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(20), default="upload")  # upload | url | well-known
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Profile(Base):
    __tablename__ = "profiles"
    __table_args__ = (UniqueConstraint("name", name="uq_profiles_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    @property
    def config(self) -> Dict[str, Any]:
        return json.loads(self.config_json or "{}")
