"""Platform ORM models (SQLAlchemy 2.0) — the findings + telemetry data model.

Schema per `plan/50_technical_architecture.md` §2.2 (findings) and §3 (GUARD).
Every tenant-scoped table carries `tenant_id` (NOT NULL) and is protected by a
Postgres RLS policy — see `base.py` for the RLS contract and fail-closed rule.

Import order note: `base.Base` must be imported before the concrete models so
they register on the same declarative metadata.
"""

from control_plane.models.base import Base, TenantMixin, TimestampMixin
from control_plane.models.enums import (
    DataRegion,
    FindingState,
    GuardDecision,
    Plan,
    Role,
    ScanStatus,
    ScanTrigger,
    Severity,
    SuppressionScope,
)
from control_plane.models.tenant import Membership, Org, Team, User
from control_plane.models.repo import Repo
from control_plane.models.scan import Finding, Scan
from control_plane.models.policy import Policy, Suppression
from control_plane.models.telemetry import Baseline, TelemetryEvent
from control_plane.models.audit import AuditLog

__all__ = [
    "Base",
    "TenantMixin",
    "TimestampMixin",
    # enums
    "DataRegion",
    "FindingState",
    "GuardDecision",
    "Plan",
    "Role",
    "ScanStatus",
    "ScanTrigger",
    "Severity",
    "SuppressionScope",
    # tables
    "Org",
    "Team",
    "User",
    "Membership",
    "Repo",
    "Scan",
    "Finding",
    "Policy",
    "Suppression",
    "TelemetryEvent",
    "Baseline",
    "AuditLog",
]
