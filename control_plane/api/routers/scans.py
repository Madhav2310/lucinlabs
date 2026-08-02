"""Scans router (50_ §2.3): SARIF ingestion + scan listing.

Ingestion (machine auth) and read (human auth) are separated because they
authenticate + scale differently (50_ §2.3). The SARIF body is the exact output
of `lucin scan --format sarif` (sarif.py).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status

from control_plane.api.deps import require_auth, require_role
from control_plane.api.schemas import (
    Page,
    Principal,
    SarifIngestRequest,
    ScanAccepted,
    ScanList,
    ScanSummary,
)
from control_plane.enums import Role, ScanStatus

router = APIRouter(prefix="/v1", tags=["scans"])


@router.post(
    "/ingest/sarif",
    response_model=ScanAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_sarif(
    req: SarifIngestRequest,
    principal: Principal = Depends(require_auth),
) -> ScanAccepted:
    """Accept a SARIF 2.1.0 document for {repo, commit, ref}; enqueue parsing.

    TODO(stage-1):
      1. Validate `req.sarif` against the SARIF 2.1.0 JSON Schema -> 422 on fail
         (50_ §2.3, never silently drop).
      2. Upload the raw SARIF blob to the object store (tenant-prefixed key).
      3. Create a `scans` row (status=queued) scoped to principal.tenant_id.
      4. Enqueue a scan-ingest job (pg queue, SELECT ... FOR UPDATE SKIP LOCKED):
         the worker parses results -> findings rows, diffs fingerprints vs the
         previous scan -> open/fixed/reappeared, extracts the embedded
         AIFG.to_dict() -> aifg_object_key.
    Returns 202 + scan_id immediately (async by design).
    """
    raise NotImplementedError("SARIF ingest not implemented (scaffold) — 50_ §2.3/§2.5")


@router.get("/repos/{repo_id}/scans", response_model=ScanList)
async def list_scans(
    repo_id: uuid.UUID,
    limit: int = 50,
    offset: int = 0,
    principal: Principal = Depends(require_role(Role.VIEWER)),
) -> ScanList:
    """List scans for a repo (paginated, always tenant-filtered by RLS).

    TODO(stage-2): query `scans` WHERE repo_id=... (RLS adds tenant_id); return
    ScanSummary rows. Returns an empty page as a fixture until wired.
    """
    # Fixture (empty) response so the contract is demonstrable pre-DB.
    return ScanList(items=[], page=Page(total=0, limit=limit, offset=offset))


@router.get("/scans/{scan_id}", response_model=ScanSummary)
async def get_scan(
    scan_id: uuid.UUID,
    principal: Principal = Depends(require_role(Role.VIEWER)),
) -> ScanSummary:
    """TODO(stage-2): fetch one scan (RLS-scoped). 404 if not in tenant."""
    raise NotImplementedError("get_scan not implemented (scaffold)")


@router.get("/scans/{scan_id}/aifg")
async def get_scan_aifg(
    scan_id: uuid.UUID,
    principal: Principal = Depends(require_role(Role.VIEWER)),
) -> dict:
    """Return the canonical `AIFG.to_dict()` for the React-Flow renderer (50_ §2.3, §5).

    TODO(stage-2): read the `aifg_object_key` blob from the object store; it is
    already `AIFG.to_dict()` shape (the SAME schema for static + runtime graphs).
    """
    raise NotImplementedError("get_scan_aifg not implemented (scaffold) — 50_ §5")
