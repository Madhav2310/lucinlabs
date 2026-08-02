"""Server-side redaction backstop for GUARD telemetry (50_ §3.2, §4.1).

A correctly-redacted event carries ONLY bounded identifiers, the fixed IFC-label
vocabulary, hashed taint ids, and NUMERIC feature stats. This module is the
belt-and-suspenders check against a customer misconfiguring client-side redaction:
it validates EVERY field of the event and rejects anything that could be a raw-
content leak.

It is deliberately FastAPI-free (imports only the Pydantic wire schema) so it is
executable and unit-tested without the API server installed — the backstop is real
logic, not a comment (see tests/test_control_plane.py).
"""

from __future__ import annotations

from control_plane.api.schemas import TelemetryEventIn

# Free-text reason/witness bound.
MAX_FREETEXT = 512
# Identifier-shaped fields (tool/role/agent/session/trace/span) are short tokens,
# NOT free text — a raw arg dumped into one would blow past this bound.
MAX_IDENT = 256
# taint_sources are SHA256 prefixes ("h:" + 16 hex here); never a raw value.
MAX_TAINT = 128
# features is a bag of numeric stats; cap its cardinality so it can't smuggle content.
MAX_FEATURE_KEYS = 64

# The IFC lattice vocabulary (aifg.py) — anything else in an ifc_* field is either a
# bug or an attempt to smuggle raw content through a "label" field.
INTEGRITY_VALUES = {"trusted", "untrusted"}
CONFIDENTIALITY_VALUES = {"public", "internal", "secret"}
DESTINATION_VALUES = {"", "external", "internal"}


def redaction_violation(ev: TelemetryEventIn) -> str | None:
    """Return a reason string if the event looks unredacted, else None.

    Validates EVERY field of the event (50_ §3.2), not just the obvious free-text
    ones: any string where a label/hash/number belongs, any oversized identifier,
    or any non-numeric feature value is treated as a possible raw-content leak and
    rejected.
    """
    # --- bounded identifier fields (short tokens, not free text) ---
    for name, value in (
        ("tool_name", ev.tool_name),
        ("tool_category", ev.tool_category),
        ("role", ev.role),
        ("agent_id", ev.agent_id),
        ("session_id", ev.session_id),
        ("trace_id", ev.trace_id),
        ("span_id", ev.span_id),
    ):
        if len(value) > MAX_IDENT:
            return f"{name} exceeds identifier limit (raw arg leak?)"

    # --- free-text reason (bounded) ---
    if len(ev.reason) > MAX_FREETEXT:
        return "reason field exceeds redaction limit"

    # --- witness: tool-name paths only, each a bounded token-ish string ---
    for w in ev.witness:
        if len(w) > MAX_FREETEXT:
            return "witness entry exceeds redaction limit (raw arg leak?)"

    # --- destination is an inferred enum, never free text ---
    if ev.destination not in DESTINATION_VALUES:
        return "destination is not an inferred label (raw arg leak?)"

    # --- ifc_args / ifc_result must be lattice labels, not smuggled content ---
    for name, lab in (("ifc_args", ev.ifc_args), ("ifc_result", ev.ifc_result)):
        if lab.integrity not in INTEGRITY_VALUES:
            return f"{name}.integrity is not a lattice label (raw arg leak?)"
        if lab.confidentiality not in CONFIDENTIALITY_VALUES:
            return f"{name}.confidentiality is not a lattice label (raw arg leak?)"

    # --- taint_sources must be hashes, not raw values ---
    for t in ev.taint_sources:
        if len(t) > MAX_TAINT:
            return "taint_source is not a hash (raw secret leak?)"

    # --- features: NUMERIC stats only — a string/list/dict value would be content ---
    if len(ev.features) > MAX_FEATURE_KEYS:
        return "features carries too many keys (raw content leak?)"
    for key, val in ev.features.items():
        if len(str(key)) > MAX_IDENT:
            return "feature key exceeds identifier limit (raw content leak?)"
        # bool is a subclass of int; allow it. Reject anything non-numeric.
        if not isinstance(val, (int, float)):
            return f"feature '{key}' is not a numeric stat (raw arg leak?)"

    return None
