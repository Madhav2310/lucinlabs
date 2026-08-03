"""Orgs / teams / users / policies router (50_ §2.2, §2.3).

Org + membership management (RBAC) and policy CRUD. Policy CRUD is here because a
policy is org-scoped config that governs BOTH scan gating and GUARD IFC
enforcement (one policy, both layers — 50_ §5).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends

from control_plane.api.deps import require_auth, require_role
from control_plane.api.schemas import MembershipOut, OrgOut, Principal, UserOut
from control_plane.enums import Role

router = APIRouter(prefix="/v1", tags=["orgs"])


@router.get("/org", response_model=OrgOut)
async def get_org(principal: Principal = Depends(require_role(Role.VIEWER))) -> OrgOut:
    """Return the caller's org (tenant). TODO(stage-1): fetch by principal.tenant_id."""
    raise NotImplementedError("get_org not implemented (scaffold)")


@router.get("/org/members", response_model=list[MembershipOut])
async def list_members(
    principal: Principal = Depends(require_role(Role.MEMBER)),
) -> list[MembershipOut]:
    """List memberships in the caller's org (RLS-scoped).

    TODO(stage-1): query `memberships` (RLS adds tenant_id). Empty fixture for now.
    """
    return []


@router.post("/org/members", response_model=MembershipOut)
async def invite_member(
    principal: Principal = Depends(require_role(Role.ADMIN)),
) -> MembershipOut:
    """Invite/add a member (admin+). TODO(stage-1): create user + membership,
    audit-log "member.invite"."""
    raise NotImplementedError("invite_member not implemented (scaffold)")


@router.get("/users/me", response_model=UserOut)
async def me(principal: Principal = Depends(require_auth)) -> UserOut:
    """Return the authenticated user. TODO(stage-1): fetch by principal.user_id."""
    raise NotImplementedError("me not implemented (scaffold)")


@router.get("/policies/{policy_id}")
async def get_policy(
    policy_id: uuid.UUID,
    principal: Principal = Depends(require_role(Role.VIEWER)),
) -> dict:
    """Get a policy spec (fail-on severity, required detectors, GUARD IFC allow-list).

    TODO(stage-2): fetch `policies.spec` (RLS-scoped).
    """
    raise NotImplementedError("get_policy not implemented (scaffold) — 50_ §5")


@router.put("/policies/{policy_id}")
async def put_policy(
    policy_id: uuid.UUID,
    spec: dict,
    principal: Principal = Depends(require_role(Role.ADMIN)),
) -> dict:
    """Upsert a policy spec (admin+). TODO(stage-2): validate spec maps to a valid
    IFCPolicy + scan gate; write `policies`; audit-log "policy.update"."""
    raise NotImplementedError("put_policy not implemented (scaffold) — 50_ §5")
