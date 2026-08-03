"""Runtime IFC enforcement — the deterministic trifecta gate.

Blueprint §6.1, Codex §5.

Implements the CaMeL/Fides pattern [VERIFIED: arXiv:2503.18813, arXiv:2505.23643]:
  - Every runtime value carries IFC labels (integrity × confidentiality).
  - Labels propagate via join through operations and tool calls.
  - At every egress call: if payload carries INTERNAL+ data AND the call was
    triggered by UNTRUSTED control, BLOCK it — deterministically, by code,
    not by the model.
  - An explicit, auditable declassification allowlist overrides the block.

This is sound-by-construction for the trifecta on all labeled values. [VERIFIED]

Honest limit: strict non-interference forbids all useful output. Real deployments
need explicit declassification allowlists (Willison's "route egress through an
allowlist"). The allowlist is made mandatory and auditable here by design.

Pure Python. The runtime interceptor (Phase 3) will wrap real tool calls
with these guards; this module is the gate logic, not the interceptor itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from lucin.aifg import Confidentiality, IFCLabel, Integrity, is_egress_by_name

# Reuse the SINGLE runtime name->capability inference that the provenance
# reconstruction (ProvenanceGraph.to_aifg) already uses, so the enforcement
# gate and the AIFG reconstruction classify egress the SAME way, and both
# agree with SCAN's static classifier (all three route through
# aifg.is_egress_by_name). provenance.py imports only stdlib + a lazy aifg
# import, so this does not create an import cycle.
from lucin.guard.provenance import _infer_caps_from_name

# ---------------------------------------------------------------------------
# Re-export the label constants from aifg for convenience
# ---------------------------------------------------------------------------
TRUSTED_PUBLIC   = IFCLabel(Integrity.TRUSTED,   Confidentiality.PUBLIC)
TRUSTED_SECRET   = IFCLabel(Integrity.TRUSTED,   Confidentiality.SECRET)
UNTRUSTED_PUBLIC = IFCLabel(Integrity.UNTRUSTED, Confidentiality.PUBLIC)
UNTRUSTED_SECRET = IFCLabel(Integrity.UNTRUSTED, Confidentiality.SECRET)


# ---------------------------------------------------------------------------
# 1. Tainted value wrapper
# ---------------------------------------------------------------------------

@dataclass
class Tainted:
    """A runtime value tagged with IFC labels and provenance.

    Every value that flows through the agent is wrapped in a Tainted
    at its entry point (tool return, user message, file read, etc.).
    Operations on Tainted values propagate labels via join.

    control_causes: the set of node IDs whose values caused this value
    to exist (i.e. the control-flow path). Used to detect whether an
    attacker-controlled value *triggered* a given operation.

    CaMeL paper: "each value is annotated with a label that tracks
    whether it originated from a privileged or quarantined source." [VERIFIED]
    """
    value:          Any
    label:          IFCLabel = field(default_factory=lambda: UNTRUSTED_PUBLIC)
    provenance_ids: frozenset[str] = field(default_factory=frozenset)  # where value came from
    control_causes: frozenset[str] = field(default_factory=frozenset)  # what gated this

    def combine(self, other: "Tainted", inherit_control: bool = True) -> "Tainted":
        """Merge two Tainted values (join of labels, union of provenance)."""
        return Tainted(
            value=None,  # combined value is caller's responsibility
            label=self.label.join(other.label),
            provenance_ids=self.provenance_ids | other.provenance_ids,
            control_causes=(self.control_causes | other.control_causes)
                           if inherit_control else self.control_causes,
        )

    @classmethod
    def wrap(cls, value: Any, *, integrity: Integrity = Integrity.UNTRUSTED,
             confidentiality: Confidentiality = Confidentiality.PUBLIC,
             source_id: str = "") -> "Tainted":
        """Convenience constructor for labeling a raw value at ingress."""
        return cls(
            value=value,
            label=IFCLabel(integrity, confidentiality),
            provenance_ids=frozenset({source_id}) if source_id else frozenset(),
        )

    @classmethod
    def system_prompt(cls, value: Any, source_id: str = "system_prompt") -> "Tainted":
        """The system prompt is TRUSTED and can be SECRET."""
        return cls.wrap(value,
                        integrity=Integrity.TRUSTED,
                        confidentiality=Confidentiality.INTERNAL,
                        source_id=source_id)

    @classmethod
    def tool_return(cls, value: Any, tool_name: str,
                    contains_sensitive: bool = False) -> "Tainted":
        """Tool returns are UNTRUSTED (SEP impossibility). [VERIFIED]
        Confidentiality depends on whether they accessed sensitive data."""
        conf = Confidentiality.INTERNAL if contains_sensitive else Confidentiality.PUBLIC
        return cls.wrap(value,
                        integrity=Integrity.UNTRUSTED,
                        confidentiality=conf,
                        source_id=f"tool:{tool_name}")

    @classmethod
    def user_input(cls, value: Any) -> "Tainted":
        """Direct user input: integrity depends on trust model; UNTRUSTED by default."""
        return cls.wrap(value,
                        integrity=Integrity.UNTRUSTED,
                        confidentiality=Confidentiality.PUBLIC,
                        source_id="user_input")


# ---------------------------------------------------------------------------
# 2. Policy and declassification allowlist
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AllowlistEntry:
    """One explicit declassification: allow (tool, destination) to carry secret data."""
    tool_name:   str
    destination: str   # URL prefix or exact match; "" means any destination
    reason:      str   # human-readable audit note (required — no silent exceptions)


class IFCPolicy:
    """Runtime IFC policy: allowlist-based declassification + capability gates.

    Honest design note: the allowlist IS the product from the security
    engineer's perspective. Every entry must have a `reason` — silent
    exceptions are the failure mode we're preventing.
    """

    def __init__(self, agent_id: str = ""):
        self.agent_id = agent_id
        self._allowlist: list[AllowlistEntry] = []

    def allow(self, tool_name: str, destination: str = "", *,
              reason: str) -> "IFCPolicy":
        """Declare an explicit declassification. Reason is mandatory."""
        if not reason:
            raise ValueError("IFCPolicy.allow() requires a non-empty reason= argument")
        self._allowlist.append(AllowlistEntry(tool_name, destination, reason))
        return self

    def declassifier_allows(self, call: "ToolCall") -> AllowlistEntry | None:
        """Return the matching allowlist entry, or None if the call is blocked."""
        for entry in self._allowlist:
            if entry.tool_name != call.tool_name:
                continue
            if entry.destination == "" or call.destination.startswith(entry.destination):
                return entry
        return None


# ---------------------------------------------------------------------------
# 3. ToolCall — the unit of runtime enforcement
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
    """A tool call about to be executed — the enforcement point."""
    tool_name:   str
    destination: str                  # URL / path / identifier
    args:        list[Tainted] = field(default_factory=list)
    context_id:  str = ""             # provenance node of the triggering context


# ---------------------------------------------------------------------------
# 4. Decision
# ---------------------------------------------------------------------------

@dataclass
class Decision:
    allow:     bool
    reason:    str
    witness:   list[str] = field(default_factory=list)  # causal chain for the alert
    allowlist_entry: AllowlistEntry | None = None

    @staticmethod
    def BLOCK(reason: str, witness: list[str] | None = None) -> "Decision":
        return Decision(allow=False, reason=reason, witness=witness or [])

    @staticmethod
    def ALLOW(reason: str = "ok",
              entry: AllowlistEntry | None = None) -> "Decision":
        return Decision(allow=True, reason=reason, allowlist_entry=entry)


# Control-cause markers that denote the call was steered by UNTRUSTED input.
# These are the provenance tags placed on a value's `control_causes` when it
# originates from (or was relayed through) an attacker-influenceable path.
# The gate consults this set so `control_causes` is load-bearing evidence for
# the (T) predicate — not merely decorative metadata.
UNTRUSTED_CONTROL_CAUSES = frozenset({
    "llm_output",       # value produced by the LLM (SEP: model output is untrusted)
    "llm_relayed",      # sensitive content relayed verbatim through the LLM
    "untrusted_input",  # value ingested from an external/untrusted source
})


# ---------------------------------------------------------------------------
# 5. The gate — guard_tool_call
# ---------------------------------------------------------------------------

# LEGACY egress name list — no longer the egress decision. Kept only as the
# baseline for the divergence audit in benchmarks/guard_completeness.py. The
# gate now routes every classification through aifg.is_egress_by_name (the
# shared vocabulary) so GUARD, the AIFG reconstruction, and SCAN all agree on
# what "egress" means. See _call_is_egress below.
EXTERNAL_EGRESS_TOOLS = frozenset({
    "send_email", "http_post", "http_put", "http_patch",
    "webhook", "post_message", "write_public_file",
    "upload_file", "send_slack", "send_teams", "notify_team",
    "dns_lookup", "smtp_send", "external_api_call",
})


def _call_is_egress(tool_name: str, destination: str) -> bool:
    """Decide egress for a runtime call via the SHARED capability rule.

    Runtime telemetry gives us a tool NAME (and sometimes a destination) but no
    declared capability set, so we infer (has_network, has_write) from the name
    with the SAME helper the provenance reconstruction uses, then defer to
    aifg.is_egress_by_name. A URL destination is direct evidence of network
    egress, so it forces has_network=True — but the fetch-only suppression
    inside is_egress_by_name still applies, so a read-only fetch tool (web_search,
    scrape, http_get) called against a URL is correctly a SOURCE, not a sink.
    """
    has_network, has_write = _infer_caps_from_name(tool_name)
    if destination.startswith(("http://", "https://")):
        has_network = True
    return is_egress_by_name(
        tool_name, has_network=has_network, has_write=has_write,
    )


def guard_tool_call(call: ToolCall, policy: IFCPolicy) -> Decision:
    """Deterministic IFC enforcement gate.

    Implements the lethal-trifecta predicate at runtime (Blueprint §3.3):
      (T) any arg's control_causes contains an UNTRUSTED source
      (S) any arg carries INTERNAL or SECRET data
      (E) the tool is an egress sink
      (¬D) no allowlist entry permits it

    Sound-by-construction for the trifecta on all labeled values. [VERIFIED]
    Honest limit: only values that have been wrapped with Tainted are protected;
    unwrapped raw values pass through unchecked (the interceptor's job).
    """
    if not call.args:
        return Decision.ALLOW("no args")

    # Merge all argument labels (join — most-untrusted/most-secret wins)
    merged = call.args[0]
    for a in call.args[1:]:
        merged = merged.combine(a)

    is_egress = _call_is_egress(call.tool_name, call.destination)

    if not is_egress:
        return Decision.ALLOW("non-egress tool")

    # (T) control: was this call steered by untrusted input? Consult BOTH the
    # integrity label AND the explicit control-cause provenance (the control-
    # flow path that led here). control_causes is now load-bearing: a value
    # tagged with an untrusted origin trips (T) even if its integrity label was
    # not itself downgraded (e.g. a trusted-labelled arg whose control path
    # passed through the LLM / untrusted input).
    untrusted_causes = merged.control_causes & UNTRUSTED_CONTROL_CAUSES
    untrusted_ctrl = (merged.label.integrity == Integrity.UNTRUSTED
                      or bool(untrusted_causes))

    # (S) data: does the payload carry internal/secret data?
    carries_sensitive = merged.label.confidentiality >= Confidentiality.INTERNAL

    if untrusted_ctrl and carries_sensitive:
        # Check allowlist before blocking
        entry = policy.declassifier_allows(call)
        if entry:
            return Decision.ALLOW(
                f"declassified: {entry.reason}",
                entry=entry,
            )
        # Trifecta — block with causal trace. Name the specific untrusted
        # control causes that fired (T), so the witness reflects the actual
        # evidence the gate consulted.
        ctrl_evidence = (sorted(untrusted_causes) if untrusted_causes
                         else f"integrity={merged.label.integrity.name}")
        witness = [
            f"untrusted control: causes={ctrl_evidence} "
            f"(all sources={sorted(merged.control_causes)})",
            f"sensitive data: confidentiality={merged.label.confidentiality.name}",
            f"egress tool: '{call.tool_name}' → '{call.destination}'",
        ]
        return Decision.BLOCK(
            "lethal trifecta: untrusted-controlled egress of sensitive data",
            witness=witness,
        )

    return Decision.ALLOW()
