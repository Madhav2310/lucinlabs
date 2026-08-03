"""GUARD runtime telemetry + per-role baselines (50_ §3.2, §3.4).

`telemetry_events` is the append-only, high-volume time-series of guarded
tool calls (§3.2). Per 50_ §2.1 this is a **TimescaleDB hypertable**, not a plain
Postgres table:

    SELECT create_hypertable('telemetry_events', 'occurred_at');
    -- 90-day retention (tenant-configurable, 50_ §4.2):
    SELECT add_retention_policy('telemetry_events', INTERVAL '90 days');
    -- native compression for the older chunks:
    ALTER TABLE telemetry_events SET (timescaledb.compress);
    SELECT add_compression_policy('telemetry_events', INTERVAL '7 days');

TODO(stage-3): the above run as a migration. RLS still applies (tenant_id column
+ policy) exactly as for the relational tables — one DB technology, one RLS story.

REDACTION IS THE CONTRACT (50_ §3.2, §4.1): a row here holds ONLY the decision,
the witness (tool-name paths), the IFC labels, HASHED taint-source ids, and
numeric feature stats. Raw tool args, raw returns, and secret VALUES are never
here. The ingest endpoint rejects any event carrying an oversized free-text field
(belt-and-suspenders against a customer misconfiguring client-side redaction).

`baselines` holds the ONLINE sufficient statistics (`AgentBaseline` in
`lucin.behavioral.scoring`), NOT a trained model — the DB row IS the JSON
that `behavioral/persistence.py` already serializes, so the local-file -> hosted
migration is a serializer swap (50_ §3.4). Small + structured => Postgres, not
the time-series store.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Index, UniqueConstraint
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from control_plane.models.base import Base, TenantMixin, TimestampMixin, pk_column, short_str
from control_plane.models.enums import GuardDecision


class TelemetryEvent(Base, TenantMixin):
    """One guarded tool call, AFTER client-side redaction (50_ §3.2).

    Modeled on OTel GenAI `gen_ai.execute_tool` spans + the `lucin.*`
    extension namespace. High-volume append-only => TimescaleDB hypertable
    (see module docstring). No TimestampMixin (updated_at is meaningless for an
    immutable event; `occurred_at` is the hypertable time dimension).
    """

    __tablename__ = "telemetry_events"
    __table_args__ = (
        Index("ix_telemetry_tenant_agent_session", "tenant_id", "agent_id", "session_id"),
    )

    id: Mapped[uuid.UUID] = pk_column()
    # tenant_id (FK orgs.id) supplied by TenantMixin.
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # --- identity (OTel GenAI convention) ---
    trace_id: Mapped[str] = short_str(default="")
    span_id: Mapped[str] = short_str(default="")
    agent_id: Mapped[str] = short_str(default="", index=True)   # gen_ai.agent.id
    session_id: Mapped[str] = short_str(default="", index=True) # lucin.session_id
    role: Mapped[str] = short_str(default="")                   # lucin.role

    # --- tool + decision ---
    tool_name: Mapped[str] = short_str(default="")              # gen_ai.tool.name
    tool_category: Mapped[str] = short_str(default="")          # lucin.tool_category
    destination: Mapped[str] = short_str(default="")           # inferred: external|internal
    decision: Mapped[GuardDecision] = mapped_column(
        SAEnum(GuardDecision, name="guard_decision"),
        default=GuardDecision.ALLOW,
        nullable=False,
    )
    reason: Mapped[str] = short_str(default="")

    # --- structural witness + IFC labels (the AIFG lattice, NOT the data) ---
    witness: Mapped[list] = mapped_column(JSONB, default=list)         # tool-name paths only
    ifc_args: Mapped[dict] = mapped_column(JSONB, default=dict)        # {integrity, confidentiality}
    ifc_result: Mapped[dict] = mapped_column(JSONB, default=dict)
    taint_sources: Mapped[list] = mapped_column(JSONB, default=list)   # HASHED ids, never secrets

    # --- derived numeric behavioral features (NOT raw params — 50_ §3.2) ---
    features: Mapped[dict] = mapped_column(JSONB, default=dict)

    # timing (nanoseconds from the span)
    start_ns: Mapped[int] = mapped_column(BigInteger, default=0)
    end_ns: Mapped[int] = mapped_column(BigInteger, default=0)


class Baseline(Base, TenantMixin, TimestampMixin):
    """Per-(tenant, role, tool) online sufficient statistics (50_ §3.4).

    Keyed by (tenant_id, agent_role, tool_name). `stats` is the serialized
    `AgentBaseline` (observation_count, running mean/var of param length/entropy,
    tool_frequencies, hour distribution, Wilson counts, per-role conformal
    calibration set). Updated in-place by the ingestion worker via the existing
    `AgentBaseline.update` — no batch retrain.
    """

    __tablename__ = "baselines"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "agent_role", "tool_name", name="uq_baseline_role_tool"
        ),
    )

    id: Mapped[uuid.UUID] = pk_column()
    # tenant_id (FK orgs.id) supplied by TenantMixin.
    agent_role: Mapped[str] = short_str(nullable=False)
    tool_name: Mapped[str] = short_str(nullable=False)
    observation_count: Mapped[int] = mapped_column(BigInteger, default=0)
    # The serialized AgentBaseline JSON (behavioral/persistence.py format).
    stats: Mapped[dict] = mapped_column(JSONB, default=dict)
