"""Test catalog and server-wide test selection settings."""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..authz import Principal, current_principal
from ..db import get_session
from ..orm import AppSetting, utcnow
from ..schemas import (
    CATEGORY_KEYS,
    CatalogCategoryOut,
    CatalogTestOut,
    GlobalTestSelection,
    TestCatalogOut,
)
from ..test_catalog import TEST_CATALOG, validate_selection

router = APIRouter(tags=["test-catalog"])

GLOBAL_SELECTION_KEY = "global_test_selection"

# Human labels mirroring the worker's CATEGORY_LABELS.
CATEGORY_LABELS = {
    "protocol": "OCSP protocol tests",
    "status": "Certificate status tests",
    "crl": "CRL tests",
    "path_validation": "Certificate path validation tests",
    "ikev2": "IKEv2 tests",
    "federal": "Federal PKI / Federal Bridge tests",
    "performance": "Performance tests (OCSP)",
    "security": "Security & error handling tests (OCSP)",
}


@router.get("/test-catalog", response_model=TestCatalogOut)
async def get_test_catalog() -> TestCatalogOut:
    categories = [
        CatalogCategoryOut(
            key=key,
            label=CATEGORY_LABELS.get(key, key),
            tests=[CatalogTestOut(**t) for t in TEST_CATALOG.get(key, [])],
        )
        for key in CATEGORY_KEYS
    ]
    return TestCatalogOut(categories=categories)


async def load_global_selection(session: AsyncSession) -> Optional[Dict[str, List[str]]]:
    """The stored global selection map, or None when unset / run-all."""
    setting = await session.get(AppSetting, GLOBAL_SELECTION_KEY)
    if setting is None:
        return None
    tests = setting.value.get("tests")
    return tests if isinstance(tests, dict) else None


@router.get("/settings/test-selection", response_model=GlobalTestSelection)
async def get_global_test_selection(
    session: AsyncSession = Depends(get_session),
) -> GlobalTestSelection:
    setting = await session.get(AppSetting, GLOBAL_SELECTION_KEY)
    if setting is None:
        return GlobalTestSelection(tests=None, updated_at=None)
    tests = setting.value.get("tests")
    return GlobalTestSelection(
        tests=tests if isinstance(tests, dict) else None,
        updated_at=setting.updated_at,
    )


@router.put("/settings/test-selection", response_model=GlobalTestSelection)
async def put_global_test_selection(
    payload: GlobalTestSelection,
    principal: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> GlobalTestSelection:
    # The global default selection is a deployment-wide setting: admin-only.
    if not principal.is_global_admin:
        raise HTTPException(status_code=403, detail="Global admin required")
    if payload.tests is not None:
        error = validate_selection(payload.tests)
        if error:
            raise HTTPException(status_code=400, detail=error)
    setting = await session.get(AppSetting, GLOBAL_SELECTION_KEY)
    value_json = json.dumps({"tests": payload.tests})
    if setting is None:
        setting = AppSetting(key=GLOBAL_SELECTION_KEY, value_json=value_json)
        session.add(setting)
    else:
        setting.value_json = value_json
        setting.updated_at = utcnow()
    await session.commit()
    await session.refresh(setting)
    return GlobalTestSelection(tests=payload.tests, updated_at=setting.updated_at)
