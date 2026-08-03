"""Immutable audit log (50_ §2.2, §4.1).

Append-only. Every triage/suppress/policy-change/login writes a row here. Per
50_ §4.1 this should also ship to a WORM/SIEM sink so tampering to hide an
intrusion is detectable. There is intentionally no `updated_at` and no ORM path
that UPDATEs or DELETEs a row.

TODO(stage-1): a Postgres trigger that raises on UPDATE/DELETE, enforcing
append-only at the DB layer (not just by convention).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from control_plane.models.base import Base, TenantMixin, pk_column, short_str


class AuditLog(Base, TenantMixin):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = pk_column()
    # tenant_id (FK orgs.id) supplied by TenantMixin.
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    actor: Mapped[str] = short_str(default="")   # user id / api-key id / "system"
    action: Mapped[str] = short_str(default="")  # e.g. "finding.suppress"
    target: Mapped[str] = short_str(default="")  # e.g. "finding:<uuid>"
    meta: Mapped[dict] = mapped_column(JSONB, default=dict)
