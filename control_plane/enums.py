"""Enums for the platform data model (50_ §2.2, §2.4).

These are plain `str, Enum` so they serialize cleanly in both SQLAlchemy columns
and Pydantic schemas, and so the RBAC/severity vocabularies match the engine's.
"""

from enum import Enum


class Role(str, Enum):
    """RBAC role on a `memberships` row (50_ §2.2, §2.4).

    Enforced in the FastAPI auth dependency (api/deps.py) alongside the RLS
    tenant setting — the role check and the RLS setting are the SAME dependency
    so a handler is unreachable without both (fail-closed by construction).
    """

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class Plan(str, Enum):
    """Org billing plan (drives retention + feature gates, 50_ §4.2)."""

    FREE = "free"
    TEAM = "team"
    ENTERPRISE = "enterprise"  # SSO + self-host + dedicated-DB isolation


class DataRegion(str, Enum):
    """Single-region at MVP; enum exists so residency is a column from day one."""

    US = "us"
    EU = "eu"


class ScanTrigger(str, Enum):
    GITHUB_PUSH = "github_push"
    GITHUB_PR = "github_pr"
    CI_UPLOAD = "ci_upload"  # customer runs `lucin scan`, POSTs SARIF (mode-b)
    MANUAL = "manual"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class FindingState(str, Enum):
    """Derived by diffing fingerprints across consecutive scans (50_ §2.2)."""

    OPEN = "open"
    FIXED = "fixed"
    REAPPEARED = "reappeared"


class SuppressionScope(str, Enum):
    """A suppression's blast radius (50_ §2.2)."""

    FINDING = "finding"  # this one fingerprint only
    RULE = "rule"        # all findings of this rule_id
    PATH = "path"        # all findings under a path prefix
    REPO = "repo"        # everything in the repo


class Severity(str, Enum):
    """Mirrors `lucin.models.Severity` (kept in sync; the engine is truth)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class GuardDecision(str, Enum):
    """GUARD tool-boundary decision, mirrors the runtime engine (50_ §3.2)."""

    ALLOW = "allow"
    BLOCK = "block"
