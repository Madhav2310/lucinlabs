"""Shared intraprocedural taint helpers for the dataflow detectors.

These are small, dependency-free utilities factored out of the SQL-injection
detector so the SSRF / insecure-deserialization / path-traversal detectors can
all use the SAME sound taint model:

    seed  = every user-visible function parameter is tainted
    prop  = `x = f(..., tainted, ...)`  →  x becomes tainted (monotone fixpoint)
    check = a sink whose argument references a tainted name is a candidate

In an agent tool, the tool's parameters ARE the LLM/attacker-controlled surface
(the model fills them from tool-call arguments, which an attacker can influence
via prompt injection). So parameter-seeded taint is the right source model here.

Precision is preserved by the SINK definitions + per-detector gating (allowlist /
containment / SafeLoader checks), NOT by narrowing the source — every detector
that uses this must gate its sinks conservatively.
"""

from __future__ import annotations

import ast

from lucin.parsers.body_inspector import _resolve_call_name
from lucin.analysis.cross_function_taint import (
    annotate_functions as _annotate_functions,
    augment_taint as _augment_taint,
    is_tainted as _is_tainted_tokens,
)

# Parameters that are never attacker-controlled tool inputs (framework plumbing).
SKIP_PARAMS = {
    "self", "cls", "ctx", "context", "run_manager", "config", "runtime",
    "callbacks", "cb", "tool_context",
}


def resolve_sig(node: ast.Call, aliases: dict[str, str] | None) -> str | None:
    """Resolve a call node to its canonical dotted signature, applying import aliases."""
    sig = _resolve_call_name(node)
    if not sig:
        return sig
    aliases = aliases or {}
    if sig in aliases:
        return aliases[sig]
    parts = sig.split(".", 1)
    if parts[0] in aliases:
        return aliases[parts[0]] + ("." + parts[1] if len(parts) > 1 else "")
    return sig


def param_names(func_node) -> set[str]:
    """All user-visible parameter names of a function (minus framework plumbing)."""
    args = func_node.args
    collected = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
    if args.vararg:
        collected.append(args.vararg)
    if args.kwarg:
        collected.append(args.kwarg)
    return {a.arg for a in collected} - SKIP_PARAMS


def names_in(node: ast.AST) -> set[str]:
    """All Name ids referenced anywhere in an expression subtree."""
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def compute_taint(func_node) -> tuple[set[str], set[str]]:
    """Return (tainted_tokens, effective_params) for a function.

    Base model: every user-visible parameter is tainted, propagated through a
    monotone assignment fixpoint. This now delegates to the cross-function taint
    engine (analysis.cross_function_taint), which ALSO:
      - propagates through ``with <tainted> as x`` bindings, and
      - seeds instance-field taint (``self.F`` set from a param/tainted source in
        one method of the enclosing class, read in another) when ``func_node``
        was annotated by ``iter_functions``.

    ``effective_params`` is non-empty when the function reads a tainted instance
    field even if it has no bare parameters (so ``if not params: continue`` guards
    still let a real cross-method flow through). The tainted set uses ``self.F``
    tokens that ``is_tainted`` matches. For a plain module-level function with no
    enclosing class this is behaviourally the old single-function taint (plus the
    sound ``with``-binding step).
    """
    params = param_names(func_node)
    return _augment_taint(func_node, params)


def var_defs(func_node) -> dict[str, ast.expr]:
    """Map a simple variable name → its FIRST assigned RHS expression (best-effort)."""
    defs: dict[str, ast.expr] = {}
    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            defs.setdefault(node.targets[0].id, node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                and node.value is not None:
            defs.setdefault(node.target.id, node.value)
    return defs


def is_tainted(expr: ast.AST, tainted: set[str]) -> bool:
    # Token-based match: bare Name ids AND depth-1 attribute paths (``self.field``).
    # Backward compatible — attribute-path tokens only match instance-field taint
    # that compute_taint explicitly seeded; bare names match exactly as before.
    return _is_tainted_tokens(expr, tainted)


def iter_functions(tree: ast.AST):
    """Yield every (async) function definition in a module tree.

    Annotates each function with its enclosing class first, so ``compute_taint``
    can resolve instance-field (cross-method) taint within the file.
    """
    _annotate_functions(tree)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def source_files_for(agent) -> set[str]:
    """Collect the set of source files associated with an agent and its tools."""
    sources: set[str] = set()
    if agent.source_file:
        sources.add(agent.source_file)
    for tool in agent.tools:
        if tool.source_file:
            sources.add(tool.source_file)
    return sources
