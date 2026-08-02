"""GUARD client SDK — wrap a tool call, redact, emit telemetry (50_ §3.1, §3.2).

Design contract (the single most important privacy decision in the platform,
50_ §1, §4.1): the raw tool args and return value NEVER leave the customer
process. This module computes only:
  * the decision + reason + structural witness (tool NAMES),
  * the IFC labels (the lattice, not the data),
  * HASHED taint-source ids (never the secret),
  * numeric feature stats (entropy / length / counts).
and posts THAT to POST /v1/ingest/telemetry.

stdlib-only (uses urllib for the HTTP POST) so the SDK's dependency footprint
stays minimal — a supply-chain concern for code that runs in every customer
runtime (50_ §4.1). No `requests`, no heavy client.

This IS a GUARD SDK, not telemetry-only: the wrapper enforces the local decision
FAIL-CLOSED. When the local IFC decision is BLOCK, the wrapped tool is DENIED
(raises `GuardBlocked`) BEFORE it runs, and the block is recorded as telemetry.
Enforcement is LOCAL — it does not depend on the network being reachable (a
telemetry export failure never weakens a block; see `_emit` fail-open, 50_ §4.2).

SCAFFOLD STATUS:
  REAL: redaction (`redact_to_event`) — hashing, entropy/length/counts, no raw
        args in the payload; the wrapping decorator; the OTLP-shaped POST; the
        fail-closed BLOCK enforcement (raise-before-run on a BLOCK decision).
  STUBBED: the DECISION SOURCE is a caller-supplied hook (`decide`) that defaults
        to ALLOW — so out of the box the wrapper enforces nothing until a real gate
        is wired. The real integration plugs in
        `lucin.guard.interceptor.guard_tool` / `ifc_runtime.guard_tool_call`
        (50_ §3.1); once wired, its BLOCK verdicts are enforced here. Batching/
        retry/back-pressure are TODO. Fail-open on EXPORT error is implemented
        (50_ §4.2): a telemetry failure never breaks the wrapped tool — but it also
        never turns a BLOCK into an ALLOW.
"""

from __future__ import annotations

import functools
import hashlib
import json
import math
import time
import urllib.request
from collections import Counter
from typing import Any, Callable


class GuardBlocked(RuntimeError):
    """Raised when the local IFC decision DENIES a guarded tool call (fail-closed).

    The tool body never runs. Carries the tool name, reason, and structural witness
    so the caller can log/alert without touching raw args (50_ §3.2).
    """

    def __init__(self, tool_name: str, reason: str = "", witness: list[str] | None = None):
        self.tool_name = tool_name
        self.reason = reason
        self.witness = witness or []
        super().__init__(f"GUARD blocked tool '{tool_name}': {reason or 'policy denied'}")


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string — a redaction-safe stat (no content)."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _hash_source(value: str) -> str:
    """Stable, non-reversible source id — the ONLY representation of a taint
    source that crosses the wire (50_ §3.2 'HASHED source ids, never the secret').
    """
    return "h:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _stats_for(args: tuple, kwargs: dict) -> dict:
    """Derive numeric-only feature stats from call params — NO raw content leaves.

    Mirrors the spirit of `lucin.behavioral.features.extract_features`
    (param_entropy, param_total_length, ...). TODO(stage-3): call the engine's
    extractor directly so client + server features are identical (train-serve
    parity, 50_ §7 Stage-3 gate).
    """
    try:
        blob = json.dumps({"a": args, "k": kwargs}, default=str)
    except (TypeError, ValueError):
        blob = str(args) + str(kwargs)
    return {
        "param_entropy": round(_shannon_entropy(blob), 3),
        "param_total_length": len(blob),
        "arg_count": len(args) + len(kwargs),
    }


def redact_to_event(
    *,
    tool_name: str,
    agent_id: str,
    session_id: str,
    role: str,
    args: tuple,
    kwargs: dict,
    decision: str,
    reason: str,
    witness: list[str],
    ifc_args: dict,
    ifc_result: dict,
    taint_sources: list[str],
    tool_category: str = "",
    destination: str = "",
    start_ns: int = 0,
    end_ns: int = 0,
) -> dict:
    """Build the redacted telemetry event dict (matches schemas.TelemetryEventIn).

    `taint_sources` are HASHED here — callers pass raw source identifiers and this
    function hashes them, so a raw value cannot leave even by mistake.
    """
    return {
        "trace_id": session_id,
        "span_id": f"{tool_name}:{start_ns}",
        "start_ns": start_ns,
        "end_ns": end_ns,
        "agent_id": agent_id,
        "session_id": session_id,
        "role": role,
        "tool_name": tool_name,
        "tool_category": tool_category,
        "destination": destination,
        "decision": decision,
        "reason": reason[:512],                 # bounded — server rejects oversized
        "witness": witness,                     # tool-name paths only
        "ifc_args": ifc_args,
        "ifc_result": ifc_result,
        "taint_sources": [_hash_source(s) for s in taint_sources],
        "features": _stats_for(args, kwargs),   # numeric stats only — never raw args
    }


class GuardClient:
    """Wraps tool calls and ships redacted telemetry to the platform."""

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        *,
        agent_id: str = "unknown",
        role: str = "",
        session_id: str = "default",
        decide: Callable[..., dict] | None = None,
        timeout: float = 2.0,
    ):
        """
        endpoint: base URL of the platform (e.g. https://api.lucin.dev)
        api_key:  scoped GUARD SDK key (machine auth, sent as Bearer — 50_ §2.4)
        decide:   optional hook returning a local IFC decision dict with keys
                  {decision, reason, witness, ifc_args, ifc_result, taint_sources,
                   tool_category, destination}. Defaults to ALLOW. The real
                  integration wires lucin.guard.ifc_runtime here (50_ §3.1).
        """
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id
        self.role = role
        self.session_id = session_id
        self._decide = decide or self._default_decide
        self.timeout = timeout

    @staticmethod
    def _default_decide(tool_name, args, kwargs) -> dict:
        """Placeholder local decision (ALLOW). TODO(stage-3): replace with the
        engine's in-process IFC gate (lucin.guard.interceptor.guard_tool)."""
        return {
            "decision": "allow",
            "reason": "",
            "witness": [],
            "ifc_args": {"integrity": "untrusted", "confidentiality": "public"},
            "ifc_result": {"integrity": "untrusted", "confidentiality": "public"},
            "taint_sources": [],
            "tool_category": "",
            "destination": "",
        }

    def guard(self, tool_name: str, *, tool_category: str = ""):
        """Decorator: wrap a tool fn so each call is gated + emits a redacted event.

        Fail-closed enforcement: the local IFC decision (from `decide`) is consulted
        BEFORE the tool runs. On a BLOCK verdict the tool body is NEVER executed —
        the block is recorded as telemetry and `GuardBlocked` is raised. Enforcement
        is local and does not depend on the network. On ALLOW, the tool runs and the
        wrapped tool completes regardless of telemetry success (fail-open EXPORT,
        50_ §4.2 — a telemetry failure never turns a block into an allow).
        """

        def _wrap(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def _inner(*args, **kwargs) -> Any:
                start = time.time_ns()
                decision = self._decide(tool_name, args, kwargs)
                blocked = str(decision.get("decision", "")).lower() == "block"

                def _build_event() -> dict:
                    return redact_to_event(
                        tool_name=tool_name,
                        agent_id=self.agent_id,
                        session_id=self.session_id,
                        role=self.role,
                        args=args,
                        kwargs=kwargs,
                        start_ns=start,
                        end_ns=time.time_ns(),
                        tool_category=tool_category or decision.get("tool_category", ""),
                        **{k: decision[k] for k in (
                            "decision", "reason", "witness",
                            "ifc_args", "ifc_result", "taint_sources", "destination",
                        )},
                    )

                if blocked:
                    # Fail-closed: record the block, then DENY without running the tool.
                    self._emit([_build_event()])
                    raise GuardBlocked(
                        tool_name,
                        reason=decision.get("reason", ""),
                        witness=list(decision.get("witness", [])),
                    )

                result = fn(*args, **kwargs)
                self._emit([_build_event()])
                return result

            return _inner

        return _wrap

    def _emit(self, events: list[dict]) -> None:
        """POST redacted events to /v1/ingest/telemetry. Fail-open (50_ §4.2)."""
        payload = json.dumps({"events": events}).encode("utf-8")
        req = urllib.request.Request(
            f"{self.endpoint}/v1/ingest/telemetry",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=self.timeout)  # noqa: S310 (https URL)
        except Exception:
            # Fail-open: never break the customer's agent because our backend is
            # unreachable (50_ §4.2). TODO(stage-3): buffer + retry with backoff.
            pass
