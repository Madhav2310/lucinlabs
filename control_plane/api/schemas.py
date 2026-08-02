"""Typed request/response DTOs (Pydantic v2) for the /v1 API (50_ §2.3).

These are the OpenAPI contract the dashboard + SDK clients are generated from
(50_ §2.3 "the SDK and dashboard are both generated clients"). They are distinct
from the ORM models (control_plane/models) on purpose: the wire contract is
versioned (/v1) and must not leak DB internals.

Pydantic v2 is present in the scaffold venv, so this module imports cleanly today.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from control_plane.enums import (
    FindingState,
    GuardDecision,
    Role,
    ScanStatus,
    ScanTrigger,
    Severity,
    SuppressionScope,
)


# --- common ---------------------------------------------------------------

class Health(BaseModel):
    status: str = "ok"
    service: str = "lucin-platform"
    version: str


class Page(BaseModel):
    """Cursor-lite pagination envelope (always tenant-filtered server-side)."""

    total: int = 0
    limit: int = 50
    offset: int = 0


# --- auth (50_ §2.4) ------------------------------------------------------

class LoginRequest(BaseModel):
    email: str
    # Password only for local/dev accounts; production is OIDC/SAML SSO (50_ §2.4).
    password: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600  # short-lived JWT (50_ §2.4)


class Principal(BaseModel):
    """The authenticated caller, resolved by the auth dependency."""

    user_id: uuid.UUID
    tenant_id: uuid.UUID
    role: Role


# --- scans / SARIF ingestion (50_ §2.3) -----------------------------------

class SarifIngestRequest(BaseModel):
    """Body of POST /v1/ingest/sarif — the exact output of
    `lucin scan --format sarif` (sarif.py:to_sarif), plus locators.
    """

    repo_external_id: str
    commit_sha: str
    ref: str = ""
    trigger: ScanTrigger = ScanTrigger.CI_UPLOAD
    engine_version: str = ""
    sarif: dict = Field(..., description="A SARIF 2.1.0 document (validated on ingest)")


class ScanAccepted(BaseModel):
    """202 response: parsing/finding-diff happens in a worker."""

    scan_id: uuid.UUID
    status: ScanStatus = ScanStatus.QUEUED


class ScanSummary(BaseModel):
    id: uuid.UUID
    repo_id: uuid.UUID
    commit_sha: str
    ref: str
    trigger: ScanTrigger
    status: ScanStatus
    engine_version: str
    summary_counts: dict = Field(default_factory=dict)
    created_at: datetime | None = None


class ScanList(BaseModel):
    items: list[ScanSummary] = Field(default_factory=list)
    page: Page = Field(default_factory=Page)


# --- findings (50_ §2.3) --------------------------------------------------

class FindingOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    repo_id: uuid.UUID
    rule_id: str
    severity: Severity
    title: str = ""
    message: str = ""
    file_path: str = ""
    start_line: int = 0
    end_line: int = 0
    witness: list[str] = Field(default_factory=list)  # the AIFG proof-path
    owasp_refs: list[str] = Field(default_factory=list)
    fingerprint: str
    state: FindingState = FindingState.OPEN


class FindingList(BaseModel):
    items: list[FindingOut] = Field(default_factory=list)
    page: Page = Field(default_factory=Page)


class SuppressRequest(BaseModel):
    scope: SuppressionScope = SuppressionScope.FINDING
    reason: str = ""
    expires_at: datetime | None = None


class TriageResult(BaseModel):
    finding_id: uuid.UUID
    state: FindingState
    suppression_id: uuid.UUID | None = None


# --- GUARD telemetry (50_ §3.2) -------------------------------------------

class IFCLabelWire(BaseModel):
    """The IFC lattice label as it appears on the wire (lowercase strings).

    Decoded server-side via the engine's `ifc_label_from_strings` — the SINGLE
    canonical string<->enum mapping shared by static + runtime (aifg.py).
    """

    integrity: str = "untrusted"       # untrusted | trusted
    confidentiality: str = "public"    # public | internal | secret


class TelemetryEventIn(BaseModel):
    """One redacted guarded-call event (50_ §3.2 schema).

    Mirrors the OTel GenAI `gen_ai.execute_tool` span + `lucin.*` extension
    attributes. Only labels/hashes/stats — NEVER raw args/returns/secrets.
    """

    trace_id: str = ""
    span_id: str = ""
    start_ns: int = 0
    end_ns: int = 0

    agent_id: str                      # gen_ai.agent.id
    session_id: str                    # lucin.session_id
    role: str = ""                     # lucin.role

    tool_name: str                     # gen_ai.tool.name
    tool_category: str = ""            # lucin.tool_category
    destination: str = ""             # inferred: external | internal
    decision: GuardDecision = GuardDecision.ALLOW
    reason: str = ""

    witness: list[str] = Field(default_factory=list)          # tool-name paths only
    ifc_args: IFCLabelWire = Field(default_factory=IFCLabelWire)
    ifc_result: IFCLabelWire = Field(default_factory=IFCLabelWire)
    taint_sources: list[str] = Field(default_factory=list)    # HASHED ids
    features: dict = Field(default_factory=dict)              # numeric stats only


class TelemetryBatch(BaseModel):
    """POST /v1/ingest/telemetry — OTLP-style batch of redacted events."""

    events: list[TelemetryEventIn] = Field(default_factory=list)


class TelemetryAccepted(BaseModel):
    accepted: int = 0
    rejected: int = 0
    rejected_reasons: list[str] = Field(default_factory=list)


# --- orgs / teams / users (50_ §2.2) --------------------------------------

class OrgOut(BaseModel):
    id: uuid.UUID
    name: str
    plan: str


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    name: str = ""


class MembershipOut(BaseModel):
    user_id: uuid.UUID
    team_id: uuid.UUID
    role: Role
