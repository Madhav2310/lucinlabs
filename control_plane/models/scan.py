"""Scan + Finding tables (50_ §2.2) — the heart of the findings data model.

The `findings` row is populated by the ingest worker from the SARIF document the
OSS engine emits — it is NOT a field-for-field copy of `lucin.models.Finding`.
The real path is engine `Finding` → `sarif.to_sarif` → the SARIF `result` objects
→ these ORM rows. The mapping the worker applies (see the class docstring below)
drops engine-only prose fields and adds cross-scan lifecycle fields that the
detector never authors. The full SARIF and the AIFG graph live in the object
store (referenced by `sarif_object_key` / `aifg_object_key`), NOT in Postgres
(blobs don't belong in the DB — 50_ §2.1).

The two identity decisions a staff engineer checks (50_ §2.2):
  * `fingerprint` (not the row id) is the finding's identity ACROSS scans, so a
    suppression made in scan #1 still applies in scan #100 (reuses SARIF
    `partialFingerprints`). Without this, rescans resurface triaged findings —
    the #1 reason teams uninstall a scanner.
  * `state` (open/fixed/reappeared) is DERIVED by diffing fingerprints between
    consecutive scans in the ingestion worker — not authored by the detector.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Enum as SAEnum
from sqlalchemy import ForeignKey, Index, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from control_plane.models.base import Base, TenantMixin, TimestampMixin, pk_column, short_str
from control_plane.models.enums import FindingState, ScanStatus, ScanTrigger, Severity


class Scan(Base, TenantMixin, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = pk_column()
    # tenant_id (FK orgs.id) supplied by TenantMixin.
    repo_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("repos.id"), nullable=False
    )
    commit_sha: Mapped[str] = short_str(default="")
    ref: Mapped[str] = short_str(default="")  # e.g. "refs/heads/main"
    trigger: Mapped[ScanTrigger] = mapped_column(
        SAEnum(ScanTrigger, name="scan_trigger"),
        default=ScanTrigger.CI_UPLOAD,
        nullable=False,
    )
    engine_version: Mapped[str] = short_str(default="")  # ScanMetadata.scanner_version
    status: Mapped[ScanStatus] = mapped_column(
        SAEnum(ScanStatus, name="scan_status"), default=ScanStatus.QUEUED, nullable=False
    )
    # Blobs in the object store (presigned, tenant-prefixed keys — 50_ §2.1, §4.2).
    sarif_object_key: Mapped[str | None] = short_str(nullable=True)
    aifg_object_key: Mapped[str | None] = short_str(nullable=True)  # AIFG.to_dict() JSON
    # {"critical": n, "high": n, ...} — cheap dashboard rollup without scanning findings.
    summary_counts: Mapped[dict] = mapped_column(JSONB, default=dict)

    repo: Mapped["Repo"] = relationship(back_populates="scans")  # noqa: F821
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")


class Finding(Base, TenantMixin, TimestampMixin):
    """One security finding, materialized by the ingest worker from a SARIF result.

    The worker maps each SARIF `result` (produced by `sarif.to_sarif` from an
    engine `lucin.models.Finding`) onto these columns:

        SARIF result.ruleId                        -> rule_id
        result.level (via _SEVERITY_TO_SARIF_LEVEL) -> severity
        result.message.text                         -> message   (engine .description)
        result.properties / rule name               -> title
        result.locations[0].physicalLocation
            .artifactLocation.uri                   -> file_path  (engine .source_file)
            .region.startLine                       -> start_line (engine .source_line)
        result.properties.witness                   -> witness    (AIFG proof-path)
        Finding.owasp_asi (OWASP-ASI mapping)       -> owasp_refs

    NOT copied: engine-only prose fields (attack_scenario, blast_radius,
    fix_suggestion, agent_name). ADDED here (the detector never authors these):
    the tenant/scan/repo FKs, a stable `fingerprint` computed by the worker, the
    first/last-seen scan pointers, and the derived cross-scan `state`.
    """

    __tablename__ = "findings"
    __table_args__ = (
        # Fingerprint lookups (dedup + suppression matching) are the hot path.
        Index("ix_findings_tenant_fingerprint", "tenant_id", "fingerprint"),
    )

    id: Mapped[uuid.UUID] = pk_column()
    # tenant_id (FK orgs.id) supplied by TenantMixin.
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False
    )
    repo_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("repos.id"), nullable=False
    )

    # --- fields derived from the SARIF result (see class docstring) ---
    rule_id: Mapped[str] = short_str(nullable=False)  # detector id, e.g. "AG-TRIFECTA"
    severity: Mapped[Severity] = mapped_column(
        SAEnum(Severity, name="severity"), nullable=False
    )
    title: Mapped[str] = short_str(default="")
    message: Mapped[str] = mapped_column(Text, default="")
    file_path: Mapped[str] = short_str(default="")
    start_line: Mapped[int] = mapped_column(Integer, default=0)
    end_line: Mapped[int] = mapped_column(Integer, default=0)
    # The AIFG proof-path (TrifectaFinding.witness_summary) — the "awe" artifact
    # rendered by the dashboard graph. JSONB so the list-of-strings survives as-is.
    witness: Mapped[list] = mapped_column(JSONB, default=list)
    owasp_refs: Mapped[list] = mapped_column(JSONB, default=list)  # Finding.owasp_asi

    # --- cross-scan lifecycle (50_ §2.2) ---
    fingerprint: Mapped[str] = short_str(nullable=False)  # stable identity across scans
    first_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), nullable=True
    )
    last_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), nullable=True
    )
    state: Mapped[FindingState] = mapped_column(
        SAEnum(FindingState, name="finding_state"),
        default=FindingState.OPEN,
        nullable=False,
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")
