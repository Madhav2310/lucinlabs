"""GUARD runtime interceptor — the tool-boundary enforcement layer.

Blueprint §6.1, §9.1: "in-runtime SDK/interceptor at the tool-call boundary."

This module wires the ifc_runtime.py gate into actual Python code:
  - @guard_tool decorator: wraps any function with IFC enforcement
  - GuardSession: per-agent session state (provenance + policy + event log)
  - LangChain integration: GuardedTool wrapper for BaseTool
  - Framework-agnostic: plain callable wrapping works with any agent framework

The three-line integration:
    session = GuardSession(policy=IFCPolicy().allow("send_email",
                                                     reason="newsletter sends are ok"))
    @guard_tool(session, label=UNTRUSTED_SECRET)
    def read_database(query: str) -> str: ...

Sound-by-construction for the trifecta on labeled values. [VERIFIED]
"""

from __future__ import annotations

import functools
import time
from dataclasses import dataclass
from typing import Any, Callable

from lucin.aifg import Confidentiality, IFCLabel
from lucin.guard.ifc_runtime import (
    UNTRUSTED_PUBLIC,
    Decision,
    IFCPolicy,
    Tainted,
    ToolCall,
    _call_is_egress,
    guard_tool_call,
)
from lucin.guard.provenance import ProvenanceGraph
from lucin.guard.taint_registry import TaintRegistry


class GuardBlockError(RuntimeError):
    """Raised when the IFC gate blocks a tool call (trifecta detected)."""
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(
            f"IFC BLOCKED: {decision.reason}\n"
            f"Witness:\n" + "\n".join(f"  {w}" for w in decision.witness)
        )


@dataclass
class GuardedCallRecord:
    """Immutable record of one tool call intercepted by GUARD."""
    tool_name:    str
    decision:     Decision
    timestamp:    float
    args_preview: str      # first 120 chars of args repr — no secrets logged in full
    result_label: str      # label assigned to the return value


class GuardSession:
    """Per-agent-session enforcement context.

    Holds the policy, provenance graph, and call log for one agent session.
    Create one per agent execution; discard after the session ends.

    Usage:
        policy = (IFCPolicy("my-agent")
                  .allow("notify_team", reason="approved alert channel"))
        session = GuardSession(policy=policy)
        # Then use @guard_tool(session) on each tool function.
    """

    def __init__(self, policy: IFCPolicy | None = None, agent_id: str = "agent",
                 content_taint: bool = True):
        self.policy     = policy or IFCPolicy(agent_id)
        self.provenance = ProvenanceGraph(agent_id=agent_id)
        self.call_log:  list[GuardedCallRecord] = []
        self.agent_id   = agent_id
        self._blocked_count = 0
        self._allowed_count = 0
        # Content-based taint propagation across the LLM boundary (see
        # guard/taint_registry.py). Closes the "taint lost when the LLM
        # re-emits a secret as a plain string" gap. On by default.
        self.content_taint = content_taint
        self.taint_registry = TaintRegistry() if content_taint else None

        # Out-of-band taint tracking: maps a content-taint source_id (e.g.
        # "tool:read_db") to the provenance ENTITY node id that tool produced.
        # A later egress call that carries the same content (detected verbatim
        # by the taint registry across the LLM boundary) is linked back to the
        # producing entity, so ProvenanceGraph.to_aifg() builds a REAL observed
        # producer->consumer lineage edge. Also tracks the per-value label so a
        # guarded tool can return the RAW value (needed for a real runtime to
        # serialize/use it) while its taint is still tracked here, not in-band.
        self._entity_by_source: dict[str, str] = {}
        self.result_labels: dict[str, IFCLabel] = {}   # source_id -> label

        # Session is initialized — provenance graph already has human_sponsor node

    def record_call(self, tool_name: str, decision: Decision,
                    args_preview: str, result_label: str) -> None:
        self.call_log.append(GuardedCallRecord(
            tool_name=tool_name,
            decision=decision,
            timestamp=time.time(),
            args_preview=args_preview,
            result_label=result_label,
        ))
        if decision.allow:
            self._allowed_count += 1
        else:
            self._blocked_count += 1

    def summary(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "total_calls": self._allowed_count + self._blocked_count,
            "allowed": self._allowed_count,
            "blocked": self._blocked_count,
            "blocked_calls": [
                {"tool": r.tool_name, "reason": r.decision.reason,
                 "witness": r.decision.witness}
                for r in self.call_log if not r.decision.allow
            ],
        }


def _classify_args(args: tuple, kwargs: dict,
                   declared_label: IFCLabel | None) -> list[Tainted]:
    """Convert raw function arguments to Tainted values for IFC checking.

    If the caller provided an explicit label (e.g. UNTRUSTED_SECRET for a
    database-read tool), use that. Otherwise default to UNTRUSTED_PUBLIC.
    (Tool returns are untrusted per SEP impossibility.) [VERIFIED]
    """
    all_args = list(args) + list(kwargs.values())
    if not all_args:
        return []

    base_label: IFCLabel = declared_label if declared_label is not None else UNTRUSTED_PUBLIC

    result = []
    for arg in all_args:
        if isinstance(arg, Tainted):
            result.append(arg)
        else:
            result.append(Tainted(
                value=arg,
                label=base_label,
                control_causes=frozenset({"llm_output"}),
                provenance_ids=frozenset({f"arg:{type(arg).__name__}"}),
            ))
    return result


def _tool_destination(tool_name: str, kwargs: dict) -> str:
    """Infer the call destination from tool name and keyword arguments."""
    for key in ("url", "endpoint", "host", "destination", "to", "address"):
        val = kwargs.get(key, "")
        if isinstance(val, str) and val:
            return val
    # No explicit destination arg: mark egress sinks as "external" so the gate
    # and allowlist see a non-empty destination. Uses the SHARED classifier
    # (same rule as the gate), not the legacy name list.
    if _call_is_egress(tool_name, ""):
        return "external"
    return ""


def guard_tool(session: GuardSession,
               label: IFCLabel | None = None,
               tool_name: str | None = None) -> Callable:
    """Decorator: wrap a tool function with IFC enforcement.

    Args:
        session:   The GuardSession for this agent execution.
        label:     IFC label to assign to all arguments of this tool.
                   Use UNTRUSTED_SECRET for tools that read sensitive data.
                   Use UNTRUSTED_PUBLIC (default) for tools with plain I/O.
        tool_name: Override the function name for policy matching.

    The decorator:
      1. Classifies all arguments as Tainted values.
      2. Checks the trifecta predicate via guard_tool_call().
      3. Raises GuardBlockError if blocked (trifecta detected).
      4. Calls the underlying function.
      5. Wraps the return value as Tainted and logs to provenance.

    Example:
        @guard_tool(session, label=UNTRUSTED_SECRET)
        def query_customer_db(customer_id: str) -> dict:
            return db.query("SELECT * FROM customers WHERE id = ?", customer_id)
    """
    def decorator(func: Callable) -> Callable:
        tname = tool_name or func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            tainted_args = _classify_args(args, kwargs, label)
            destination  = _tool_destination(tname, kwargs)

            # Content-based taint propagation: if any argument CONTAINS bytes
            # that a prior tool returned as sensitive (even though the LLM
            # re-emitted them as a plain string), re-apply that taint here.
            # This closes the "taint lost at the LLM boundary" gap for verbatim
            # data flows — the common exfil case.
            taint_sources: list[str] = []
            if session.taint_registry is not None:
                raw_values = list(args) + list(kwargs.values())
                for i, raw in enumerate(raw_values):
                    if isinstance(raw, Tainted):
                        continue
                    detected, srcs = session.taint_registry.scan(raw)
                    if detected is not None and i < len(tainted_args):
                        ta = tainted_args[i]
                        # Elevate: join the detected (secret) label; mark the
                        # control cause as untrusted (it arrived via the LLM).
                        tainted_args[i] = Tainted(
                            value=ta.value,
                            label=ta.label.join(detected),
                            provenance_ids=ta.provenance_ids | frozenset(srcs),
                            control_causes=ta.control_causes | frozenset({"llm_relayed"}),
                        )
                        taint_sources.extend(srcs)

            call = ToolCall(
                tool_name=tname,
                destination=destination,
                args=tainted_args,
            )

            decision = guard_tool_call(call, session.policy)

            # Observed lineage: which producer ENTITIES did this call consume?
            # We know from the content-taint scan which prior tool outputs are
            # carried in these args (taint_sources). Map those to the producer
            # entity node ids so record_activity can declare real data lineage.
            used_entity_ids = [
                session._entity_by_source[s]
                for s in taint_sources
                if s in session._entity_by_source
            ]

            # Log to provenance (activity node); returns the activity id.
            act_id = session.provenance.record_activity(
                tool_name=tname,
                inputs={"destination": destination, "decision": "ALLOW" if decision.allow else "BLOCK"},
                triggered_by="llm",
                used_entities=used_entity_ids or None,
            )

            args_preview = repr((args, kwargs))[:120]
            if not decision.allow:
                session.record_call(tname, decision, args_preview, "BLOCKED")
                raise GuardBlockError(decision)

            # Execute the real function
            result = func(*args, **kwargs)

            # Compute the return value's IFC label OUT-OF-BAND (we no longer wrap
            # the value in a Tainted — a real runtime must receive the raw value
            # so it can serialize/forward it). Taint is tracked in the registry
            # (content) and provenance graph (lineage), not on the value itself.
            effective_label = label if label is not None else UNTRUSTED_PUBLIC
            return_label = Tainted.tool_return(
                result,
                tool_name=tname,
                contains_sensitive=(effective_label.confidentiality
                                    >= Confidentiality.INTERNAL),
            ).label
            source_id = f"tool:{tname}"
            session.result_labels[source_id] = return_label

            # Record the return value as a provenance ENTITY produced by this
            # activity, and remember its id keyed by the taint source, so a later
            # consumer that carries this content links back to it (real lineage).
            entity_id = session.provenance.record_entity(
                name=f"{tname}_return",
                produced_by=act_id,
                integrity="untrusted",
                confidentiality=("internal"
                                 if return_label.confidentiality >= Confidentiality.INTERNAL
                                 else "public"),
                content_preview=repr(result)[:120],
            )
            session._entity_by_source[source_id] = entity_id

            # Register sensitive return content so a later egress call carrying
            # these bytes (verbatim, via the LLM) gets re-tainted and blocked.
            if session.taint_registry is not None:
                session.taint_registry.register(
                    result, return_label, source_id=source_id
                )

            session.record_call(tname, decision, args_preview,
                                f"{return_label.confidentiality.name}")
            # Return the REAL underlying value (not a Tainted wrapper).
            return result

        wrapper._guard_session = session   # type: ignore[attr-defined]
        wrapper._guard_label   = label     # type: ignore[attr-defined]
        wrapper._is_guarded    = True      # type: ignore[attr-defined]
        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# LangChain integration
# ---------------------------------------------------------------------------

def make_guarded_langchain_tool(tool_func: Callable,
                                session: GuardSession,
                                label: IFCLabel | None = None) -> Callable:
    """Wrap a LangChain @tool function with GUARD enforcement.

    Usage:
        from langchain.agents import tool

        @tool
        def send_report(recipient: str, content: str) -> str:
            "Send a report to a recipient."
            smtp_client.send(recipient, content)
            return "sent"

        guarded_send = make_guarded_langchain_tool(send_report, session,
                                                    label=UNTRUSTED_SECRET)
        # Use guarded_send in your agent instead of send_report.
    """
    guarded = guard_tool(session, label=label, tool_name=tool_func.__name__)(tool_func)
    # Preserve LangChain tool metadata if present
    if hasattr(tool_func, "name"):
        guarded.name = tool_func.name
    if hasattr(tool_func, "description"):
        guarded.description = tool_func.description
    return guarded


# ---------------------------------------------------------------------------
# Framework-agnostic: GuardedAgent wrapper
# ---------------------------------------------------------------------------

class GuardedAgent:
    """Wraps an arbitrary agent's tool-call dispatch with GUARD enforcement.

    Framework-agnostic: works with any agent that dispatches tool calls
    through a single callable or a dict of callables.

    Usage (framework-agnostic):
        tools = {
            "read_db": read_db_func,
            "send_email": send_email_func,
        }
        labels = {
            "read_db": UNTRUSTED_SECRET,
            "send_email": UNTRUSTED_PUBLIC,
        }
        agent = GuardedAgent(tools, session, labels)
        result = agent.call("read_db", customer_id="123")
    """

    def __init__(self,
                 tools: dict[str, Callable],
                 session: GuardSession,
                 labels: dict[str, IFCLabel] | None = None):
        self.session = session
        labels = labels or {}
        self._tools: dict[str, Callable] = {}
        for name, func in tools.items():
            lbl = labels.get(name)
            self._tools[name] = guard_tool(session, label=lbl, tool_name=name)(func)

    def call(self, tool_name: str, *args, **kwargs) -> Any:
        """Call a guarded tool by name. Raises GuardBlockError if blocked."""
        if tool_name not in self._tools:
            raise KeyError(f"Unknown tool: {tool_name!r}")
        return self._tools[tool_name](*args, **kwargs)

    def summary(self) -> dict:
        return self.session.summary()
