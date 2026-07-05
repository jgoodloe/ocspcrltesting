"""Saved CA certificate library.

Commonly used roots and issuing CAs (e.g. Federal Common Policy CA G2) are
stored once — by file upload, by server-side fetch from a URL, or from a
curated well-known list — and referenced in run configurations instead of
being re-uploaded for every run.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime, timezone
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException, Response, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import Role, WorkspaceContext, active_workspace
from ..certs import CertificateError, load_certificates_any
from ..db import get_session
from ..orm import CACertificate
from ..schemas import (
    CACertFetchIn,
    CACertImportResult,
    CACertList,
    CACertOut,
    CACertUpdate,
    WellKnownCA,
    WellKnownCAList,
)
from ..settings import get_settings
from ..ssrf import BlockedTargetError, NetworkPolicy, validate_url
from .certs import read_limited_upload

logger = logging.getLogger("ocspweb.api.ca_certs")

router = APIRouter(tags=["ca-certificates"])

MAX_FETCH_BYTES = 2 * 1024 * 1024  # generous: FPKI P7C bundles run to ~100 KB
FETCH_TIMEOUT_SECONDS = 20

# Curated well-known CAs. These are official publication URLs; the server
# fetches them on demand (nothing is bundled that could go stale).
WELL_KNOWN_CAS: List[WellKnownCA] = [
    WellKnownCA(
        key="fcpca-g2",
        name="Federal Common Policy CA G2",
        url="http://repo.fpki.gov/fcpca/fcpcag2.crt",
        description="U.S. Federal PKI trust anchor (FCPCAG2)",
    ),
    WellKnownCA(
        key="fbca-g4",
        name="Federal Bridge CA G4",
        url="http://repo.fpki.gov/bridge/fbcag4.crt",
        description="U.S. Federal Bridge CA (cross-certification hub)",
    ),
    WellKnownCA(
        key="fbca-g4-issued",
        name="CAs issued by Federal Bridge CA G4 (bundle)",
        url="http://repo.fpki.gov/bridge/caCertsIssuedByfbcag4.p7c",
        description="PKCS#7 bundle of every CA certified by FBCA G4 — imports many entries",
    ),
]


def _to_out(row: CACertificate) -> CACertOut:
    return CACertOut(
        id=row.id,
        name=row.name,
        subject=row.subject,
        issuer=row.issuer,
        serial_number=row.serial_number,
        fingerprint_sha256=row.fingerprint_sha256,
        not_before=row.not_before,
        not_after=row.not_after,
        is_ca=bool(row.is_ca),
        expired=row.not_after.replace(tzinfo=row.not_after.tzinfo or timezone.utc)
        < datetime.now(timezone.utc),
        self_signed=row.subject == row.issuer,
        source=row.source,
        source_url=row.source_url,
        created_at=row.created_at,
    )


def _display_name(cert: x509.Certificate) -> str:
    from cryptography.x509.oid import NameOID

    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cns:
        return str(cns[0].value)[:200]
    return cert.subject.rfc4514_string()[:200]


async def _import_certificates(
    session: AsyncSession,
    ctx: "WorkspaceContext",
    certs: List[x509.Certificate],
    name: Optional[str],
    source: str,
    source_url: Optional[str] = None,
) -> CACertImportResult:
    created: List[CACertOut] = []
    skipped = 0
    for cert in certs:
        fingerprint = hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        existing = (
            await session.execute(
                select(CACertificate).where(
                    CACertificate.workspace_id == ctx.workspace.id,
                    CACertificate.fingerprint_sha256 == fingerprint,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            skipped += 1
            continue
        # A user-provided name applies when importing a single certificate;
        # bundle entries are named from their subject CN.
        entry_name = name if (name and len(certs) == 1) else _display_name(cert)
        row = CACertificate(
            workspace_id=ctx.workspace.id,
            created_by_user_id=ctx.principal.user.id or None,
            name=entry_name,
            pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=hex(cert.serial_number),
            fingerprint_sha256=fingerprint,
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            is_ca=1 if _is_ca(cert) else 0,
            source=source,
            source_url=source_url,
        )
        session.add(row)
        await session.flush()
        created.append(_to_out(row))
    await session.commit()
    return CACertImportResult(created=created, skipped_duplicates=skipped)


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(
            cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        )
    except x509.ExtensionNotFound:
        return False


@router.get("/ca-certs", response_model=CACertList)
async def list_ca_certs(
    ctx: WorkspaceContext = Depends(active_workspace(Role.viewer)),
    session: AsyncSession = Depends(get_session),
) -> CACertList:
    rows = (
        await session.execute(
            select(CACertificate)
            .where(CACertificate.workspace_id == ctx.workspace.id)
            .order_by(CACertificate.name)
        )
    ).scalars().all()
    return CACertList(items=[_to_out(r) for r in rows])


@router.get("/ca-certs/well-known", response_model=WellKnownCAList)
async def list_well_known_cas() -> WellKnownCAList:
    return WellKnownCAList(items=WELL_KNOWN_CAS)


@router.post("/ca-certs", response_model=CACertImportResult, status_code=201)
async def upload_ca_cert(
    file: UploadFile,
    name: Optional[str] = None,
    ctx: WorkspaceContext = Depends(active_workspace(Role.member)),
    session: AsyncSession = Depends(get_session),
) -> CACertImportResult:
    data = await read_limited_upload(file)
    try:
        certs = load_certificates_any(data)
    except CertificateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = await _import_certificates(session, ctx, certs, name, source="upload")
    logger.info(
        "CA library upload: %d created, %d duplicates skipped",
        len(result.created),
        result.skipped_duplicates,
    )
    return result


@router.post("/ca-certs/fetch", response_model=CACertImportResult, status_code=201)
async def fetch_ca_cert(
    payload: CACertFetchIn,
    ctx: WorkspaceContext = Depends(active_workspace(Role.member)),
    session: AsyncSession = Depends(get_session),
) -> CACertImportResult:
    settings = get_settings()
    policy = NetworkPolicy.from_settings(settings)
    try:
        validate_url(payload.url, policy)
    except BlockedTargetError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    def _download() -> bytes:
        import requests

        response = requests.get(payload.url, timeout=FETCH_TIMEOUT_SECONDS, stream=True)
        response.raise_for_status()
        chunks: List[bytes] = []
        read = 0
        for chunk in response.iter_content(chunk_size=65536):
            chunks.append(chunk)
            read += len(chunk)
            if read > MAX_FETCH_BYTES:
                raise ValueError(f"response exceeded {MAX_FETCH_BYTES} byte limit")
        return b"".join(chunks)

    try:
        data = await asyncio.to_thread(_download)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not fetch {payload.url}: {exc}") from exc

    try:
        certs = load_certificates_any(data)
    except CertificateError as exc:
        raise HTTPException(status_code=400, detail=f"{payload.url}: {exc}") from exc

    well_known = any(w.url == payload.url for w in WELL_KNOWN_CAS)
    result = await _import_certificates(
        session, ctx, certs, payload.name, source="well-known" if well_known else "url",
        source_url=payload.url,
    )
    logger.info(
        "CA library fetch %s: %d created, %d duplicates skipped",
        payload.url,
        len(result.created),
        result.skipped_duplicates,
    )
    return result


async def _get_in_ws_or_404(session: AsyncSession, cert_id: int, workspace_id: int) -> CACertificate:
    row = await session.get(CACertificate, cert_id)
    if row is None or row.workspace_id != workspace_id:
        raise HTTPException(status_code=404, detail="Saved certificate not found")
    return row


@router.patch("/ca-certs/{cert_id}", response_model=CACertOut)
async def rename_ca_cert(
    cert_id: int,
    payload: CACertUpdate,
    ctx: WorkspaceContext = Depends(active_workspace(Role.member)),
    session: AsyncSession = Depends(get_session),
) -> CACertOut:
    row = await _get_in_ws_or_404(session, cert_id, ctx.workspace.id)
    row.name = payload.name
    await session.commit()
    await session.refresh(row)
    return _to_out(row)


@router.delete("/ca-certs/{cert_id}", status_code=204)
async def delete_ca_cert(
    cert_id: int,
    ctx: WorkspaceContext = Depends(active_workspace(Role.member)),
    session: AsyncSession = Depends(get_session),
) -> Response:
    row = await _get_in_ws_or_404(session, cert_id, ctx.workspace.id)
    await session.delete(row)
    await session.commit()
    return Response(status_code=204)
