"""Policy + Suppression tables (50_ §2.2).

`policies.spec` (JSONB) is the serialized form of the engine's `IFCPolicy` plus
scan gates — the SAME policy object governs both SCAN (fail-on severity, required
detectors) and GUARD (the IFC allow-list at the tool boundary). One policy, both
layers — that is the "one coherent model" property expressed in configuration
(50_ §5).

`suppressions` key off `finding_fingerprint` (NOT a finding row id) so a
suppression survives a rescan (50_ §2.2). This is the mechanism that keeps
triaged findings from resurfacing — the brand-critical 0%-FP promise depends on it.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from control_plane.models.base import Base, TenantMixin, TimestampMixin, pk_column, short_str
from control_plane.models.enums import SuppressionScope


class Policy(Base, TenantMixin, TimestampMixin):
    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = pk_column()
    # tenant_id (FK orgs.id) supplied by TenantMixin.
    name: Mapped[str] = short_str(nullable=False)
    # spec example:
    #   {"fail_on": "high",
    #    "required_detectors": ["AG-TRIFECTA", "AG-007"],
    #    "guard_ifc_allowlist": [{"tool": "send_email", "reason": "newsletter"}]}
    # The guard_ifc_allowlist maps directly onto lucin.guard.ifc_runtime.IFCPolicy.
    spec: Mapped[dict] = mapped_column(JSONB, default=dict)


class Suppression(Base, TenantMixin, TimestampMixin):
    __tablename__ = "suppressions"

    id: Mapped[uuid.UUID] = pk_column()
    # tenant_id (FK orgs.id) supplied by TenantMixin.
    repo_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("repos.id"), nullable=False
    )
    # The fingerprint (or rule/path/repo per scope) this suppression matches.
    finding_fingerprint: Mapped[str] = short_str(nullable=False, index=True)
    scope: Mapped[SuppressionScope] = mapped_column(
        SAEnum(SuppressionScope, name="suppression_scope"),
        default=SuppressionScope.FINDING,
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
