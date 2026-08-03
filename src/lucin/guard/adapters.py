"""GUARD framework adapters — wrap third-party agent tools with the IFC gate.

MATURITY: L2 (scaffolded + unit-tested on author input; NOT validated against a
live LLM/framework).

Blueprint §6.1, §9.1: "in-runtime SDK/interceptor at the tool-call boundary."
interceptor.py already ships the LangChain adapter (make_guarded_langchain_tool)
and the framework-agnostic GuardedAgent. This module adds CrewAI and
OpenAI-Agents adapters plus a generic dict wrapper, mirroring that pattern.

CRITICAL DESIGN CONSTRAINT: crewai and openai-agents are NOT installed, and this
module MUST import cleanly without them. Therefore:
  - No top-level import of any framework package.
  - Framework objects are handled by DUCK-TYPING, not isinstance checks.
  - The underlying callable is extracted by trying, in order: `.func`,
    `.__wrapped__`, `.on_invoke_tool`, then the object itself if callable.

Every wrapped callable goes through guard_tool() from interceptor.py, so the
same deterministic IFC enforcement applies regardless of framework.

Honest limits (hostile-reader test):
  - These adapters are validated only against plain Python callables and small
    stand-in objects in the tests — NOT against a running CrewAI or
    OpenAI-Agents runtime. Real tool objects may expose their callable
    differently; the extraction order is a best-effort, documented heuristic.
"""

from __future__ import annotations

from typing import Any, Callable

from lucin.aifg import IFCLabel
from lucin.guard.interceptor import GuardSession, guard_tool

# ---------------------------------------------------------------------------
# Callable extraction — duck-typed, framework-independent
# ---------------------------------------------------------------------------

# Attributes that framework tool-wrappers commonly use to hold the real callable.
_CALLABLE_ATTRS = ("func", "__wrapped__", "on_invoke_tool", "_run", "run", "coroutine")


def _extract_callable(tool_obj: Any) -> Callable:
    """Return the underlying callable from a framework tool object.

    Tries a documented sequence of attributes, then falls back to the object
    itself if it is directly callable. Raises TypeError if nothing usable is
    found — we never silently wrap a non-callable.
    """
    for attr in _CALLABLE_ATTRS:
        candidate = getattr(tool_obj, attr, None)
        if callable(candidate):
            return candidate
    if callable(tool_obj):
        return tool_obj
    raise TypeError(
        f"cannot extract a callable from {tool_obj!r}: "
        f"tried attrs {_CALLABLE_ATTRS} and direct call"
    )


def _tool_name_of(tool_obj: Any, fallback: str) -> str:
    for attr in ("name", "__name__"):
        val = getattr(tool_obj, attr, None)
        if isinstance(val, str) and val:
            return val
    return fallback


def _preserve_metadata(source: Any, target: Callable) -> None:
    """Copy `name`/`description` onto the wrapper if the source exposes them,
    so the guarded tool still looks like a valid framework tool downstream."""
    for attr in ("name", "description"):
        val = getattr(source, attr, None)
        if val is not None:
            try:
                setattr(target, attr, val)
            except (AttributeError, TypeError):
                pass


# ---------------------------------------------------------------------------
# CrewAI adapter
# ---------------------------------------------------------------------------

def guard_crewai_tool(tool_obj: Any,
                      session: GuardSession,
                      label: IFCLabel | None = None,
                      tool_name: str | None = None,
                      inplace: bool = False) -> Callable:
    """Wrap a CrewAI tool (or @tool-decorated function) with GUARD enforcement.

    CrewAI tools are typically BaseTool subclasses exposing `.func` (for the
    `@tool` decorator) or `._run`. We extract whichever is callable and wrap it
    via guard_tool. No crewai import is performed — pure duck-typing.

    inplace=False (default): returns a detached guarded callable. The caller must
    invoke it directly; CrewAI's own `.run()` dispatch is NOT enforced.

    inplace=True: reattaches the guarded callable onto the tool object's own
    dispatch slot (`.func` for @tool Tools, `._run` for BaseTool subclasses) and
    returns the tool object itself. CrewAI's native `tool.run(...)` then flows
    through the IFC gate — real tool-boundary enforcement (the L3 win). The
    original callable is captured before replacement, so re-entrancy is safe.
    """
    name = tool_name or _tool_name_of(tool_obj, "crewai_tool")
    inner = _extract_callable(tool_obj)
    guarded = guard_tool(session, label=label, tool_name=name)(inner)
    _preserve_metadata(tool_obj, guarded)
    if not inplace:
        return guarded
    # Reattach onto the dispatch slot CrewAI actually calls, so `.run()` enforces.
    for attr in ("func", "_run"):
        if callable(getattr(tool_obj, attr, None)):
            try:
                setattr(tool_obj, attr, guarded)
                return tool_obj
            except (AttributeError, TypeError):
                continue
    raise TypeError(
        f"cannot reattach guarded callable onto {tool_obj!r}: "
        f"no writable `.func` or `._run` dispatch slot"
    )


def guard_crewai_agent(agent_obj: Any,
                       session: GuardSession,
                       labels: dict[str, IFCLabel] | None = None) -> Any:
    """Guard every tool on a CrewAI Agent in place, returning the same agent.

    Duck-typed: looks for an iterable `.tools` attribute, replaces each tool's
    callable with a guarded version. If the agent exposes no `.tools`, raises
    TypeError rather than silently doing nothing. No crewai import performed.
    """
    labels = labels or {}
    tools = getattr(agent_obj, "tools", None)
    if tools is None:
        raise TypeError(
            "object has no `.tools` attribute — is this a CrewAI Agent?"
        )

    for tool_obj in tools:
        name = _tool_name_of(tool_obj, "crewai_tool")
        label = labels.get(name)
        inner = _extract_callable(tool_obj)
        guarded = guard_tool(session, label=label, tool_name=name)(inner)
        # Re-attach the guarded callable to the tool object where it was found.
        for attr in ("func", "_run"):
            if callable(getattr(tool_obj, attr, None)):
                try:
                    setattr(tool_obj, attr, guarded)
                except (AttributeError, TypeError):
                    pass
                break
    return agent_obj


# ---------------------------------------------------------------------------
# OpenAI Agents SDK adapter
# ---------------------------------------------------------------------------

def guard_openai_agents_tool(tool_obj: Any,
                             session: GuardSession,
                             label: IFCLabel | None = None,
                             tool_name: str | None = None) -> Callable:
    """Wrap an OpenAI-Agents FunctionTool (or plain function) with GUARD.

    OpenAI-Agents FunctionTool objects hold their callable on
    `.on_invoke_tool`; a `@function_tool`-decorated function keeps the original
    on `.__wrapped__`. Both are covered by _extract_callable's order. No
    openai/openai-agents import is performed.
    """
    name = tool_name or _tool_name_of(tool_obj, "openai_tool")
    inner = _extract_callable(tool_obj)
    guarded = guard_tool(session, label=label, tool_name=name)(inner)
    _preserve_metadata(tool_obj, guarded)
    return guarded


# ---------------------------------------------------------------------------
# Generic adapter
# ---------------------------------------------------------------------------

def guard_any(tools_dict: dict[str, Any],
              session: GuardSession,
              labels: dict[str, IFCLabel] | None = None) -> dict[str, Callable]:
    """Framework-agnostic: guard a name->tool mapping of any tool objects.

    Accepts plain callables OR framework tool objects (extracted via
    _extract_callable). Returns a new dict of name->guarded-callable. Mirrors
    GuardedAgent but returns the mapping so the caller can plug it back into
    whatever dispatch mechanism their framework uses.
    """
    labels = labels or {}
    guarded: dict[str, Callable] = {}
    for name, tool_obj in tools_dict.items():
        inner = _extract_callable(tool_obj)
        label = labels.get(name)
        wrapped = guard_tool(session, label=label, tool_name=name)(inner)
        _preserve_metadata(tool_obj, wrapped)
        guarded[name] = wrapped
    return guarded
