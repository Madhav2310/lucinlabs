"""Findings router (50_ §2.3): list / detail / triage (suppress, reopen).

Suppression writes to `suppressions` (keyed by fingerprint, survives rescan) AND
`audit_log`. A suppression that doesn't survive a rescan is a Stage-1 regression
(50_ §2.2, §7) — the fingerprint keying here is what prevents that.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends

from control_plane.api.deps import require_role
from control_plane.api.schemas import (
    FindingList,
    FindingOut,
    Page,
    Principal,
    SuppressRequest,
    TriageResult,
)
from control_plane.enums import FindingState, Role

router = APIRouter(prefix="/v1", tags=["findings"])


@router.get("/scans/{scan_id}/findings", response_model=FindingList)
async def list_findings(
    scan_id: uuid.UUID,
    severity: str | None = None,
    state: FindingState | None = None,
    rule: str | None = None,
    limit: int = 50,
    offset: int = 0,
    principal: Principal = Depends(require_role(Role.VIEWER)),
) -> FindingList:
    """List findings for a scan with optional severity/state/rule filters.

    TODO(stage-1/2): query `findings` WHERE scan_id=... + filters (RLS adds
    tenant_id); apply active suppressions (by fingerprint) so triaged findings
    don't resurface. Returns an empty page fixture until wired.
    """
    return FindingList(items=[], page=Page(total=0, limit=limit, offset=offset))


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(
    finding_id: uuid.UUID,
    principal: Principal = Depends(require_role(Role.VIEWER)),
) -> FindingOut:
    """Full finding detail incl. `witness` (the AIFG proof-path, 50_ §2.3).

    TODO(stage-2): fetch one finding (RLS-scoped); 404 if not in tenant.
    """
    raise NotImplementedError("get_finding not implemented (scaffold)")


@router.post("/findings/{finding_id}/suppress", response_model=TriageResult)
async def suppress_finding(
    finding_id: uuid.UUID,
    req: SuppressRequest,
    principal: Principal = Depends(require_role(Role.MEMBER)),
) -> TriageResult:
    """Suppress a finding by its FINGERPRINT (survives rescan — 50_ §2.2).

    TODO(stage-2): look up the finding's fingerprint; INSERT a `suppressions` row
    (scope/reason/expires_at, created_by=principal.user_id); write an
    `audit_log` "finding.suppress" row; set the finding state accordingly.
    """
    raise NotImplementedError("suppress_finding not implemented (scaffold) — 50_ §2.2")


@router.post("/findings/{finding_id}/reopen", response_model=TriageResult)
async def reopen_finding(
    finding_id: uuid.UUID,
    principal: Principal = Depends(require_role(Role.MEMBER)),
) -> TriageResult:
    """Reverse a suppression (delete/expire it) + audit-log the reopen.

    TODO(stage-2): expire the matching suppression; audit-log "finding.reopen".
    """
    raise NotImplementedError("reopen_finding not implemented (scaffold)")
