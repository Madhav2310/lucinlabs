"""GUARD telemetry ingestion router (50_ §2.3, §3).

Accepts a batch of REDACTED tool-call events (OTel GenAI shape), rejects any that
carry oversized free-text (belt-and-suspenders against a customer misconfiguring
client-side redaction — 50_ §3.2), then (in the real worker) reconstructs the
session AIFG and updates per-role baselines.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status

from control_plane.api.deps import require_auth
from control_plane.api.reconstruction import query_runtime_trifecta, reconstruct_session_aifg
from control_plane.api.redaction import redaction_violation
from control_plane.api.schemas import (
    Principal,
    TelemetryAccepted,
    TelemetryBatch,
    TelemetryEventIn,
)  # noqa: F401  (TelemetryEventIn used as a type hint)

router = APIRouter(prefix="/v1", tags=["telemetry"])


@router.post(
    "/ingest/telemetry",
    response_model=TelemetryAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_telemetry(
    batch: TelemetryBatch,
    principal: Principal = Depends(require_auth),
) -> TelemetryAccepted:
    """Ingest a batch of redacted GUARD events (machine auth: SDK API key).

    REAL (runs today): the redaction backstop + AIFG reconstruction call below
    are live code against the engine — see reconstruction.py.
    STUBBED (TODO stage-3): persisting `telemetry_events` rows, the per-role
    baseline online-update (`AgentBaseline.update` + self-poisoning guard),
    session-close scoring, and storing the reconstructed `AIFG.to_dict()` to the
    object store keyed by (tenant, agent, session).
    """
    accepted, rejected, reasons = 0, 0, []
    ok_events: list[TelemetryEventIn] = []
    for ev in batch.events:
        why = redaction_violation(ev)
        if why:
            rejected += 1
            reasons.append(why)
            continue
        ok_events.append(ev)
        accepted += 1

    # Demonstrate the coherence stitch: reconstruct one runtime AIFG per agent
    # using the SHARED engine types, and run the UNCHANGED trifecta query.
    # TODO(stage-3): group by session, persist, update baselines, score at close.
    by_agent: dict[str, list[TelemetryEventIn]] = {}
    for ev in ok_events:
        by_agent.setdefault(ev.agent_id, []).append(ev)
    for agent_id, evs in by_agent.items():
        g = reconstruct_session_aifg(agent_id, evs)
        _ = query_runtime_trifecta(g)  # findings; persistence TODO(stage-3)

    return TelemetryAccepted(accepted=accepted, rejected=rejected, rejected_reasons=reasons)


@router.get("/agents/{agent_id}/baseline")
async def get_agent_baseline(
    agent_id: str,
    principal: Principal = Depends(require_auth),
) -> dict:
    """Return the per-role baseline sufficient statistics (50_ §3.4).

    TODO(stage-3): read `baselines` rows for (tenant, role, tool); return the
    serialized AgentBaseline JSON (the same shape behavioral/persistence.py uses).
    """
    raise NotImplementedError("get_agent_baseline not implemented (scaffold) — 50_ §3.4")


@router.get("/sessions/{session_id}")
async def get_session(
    session_id: uuid.UUID,
    principal: Principal = Depends(require_auth),
) -> dict:
    """Return a session's reconstructed runtime AIFG + score (50_ §2.3, §3.3).

    TODO(stage-3): read the session's `aifg_object_key` blob + session score.
    """
    raise NotImplementedError("get_session not implemented (scaffold) — 50_ §3.3")
