from __future__ import annotations

from fastapi import APIRouter, HTTPException, UploadFile

from ..certs import CertificateError, extract_metadata, load_certificate
from ..schemas import CertMetadata
from ..settings import get_settings

router = APIRouter(tags=["certificates"])


async def read_limited_upload(file: UploadFile) -> bytes:
    """Read an upload while enforcing the configured size limit."""
    settings = get_settings()
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Upload exceeds the maximum allowed size of {settings.max_upload_bytes} bytes",
        )
    return data


@router.post("/certificates/inspect", response_model=CertMetadata)
async def inspect_certificate(file: UploadFile) -> CertMetadata:
    data = await read_limited_upload(file)
    try:
        cert = load_certificate(data)
    except CertificateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return extract_metadata(cert)
