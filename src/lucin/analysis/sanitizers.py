"""Kind-scoped sanitizer / barrier model — the single biggest precision lever.

WHY THIS EXISTS
---------------
Lucin had no shared notion of "this value was made safe". Each detector carried an
ad-hoc allow-list, and AG-001 ignored the question entirely, so all four of these
were reported as CRITICAL "Unrestricted Shell/Exec Access" (measured 2026-07-30):

    subprocess.run(cmd, shell=True)                      # genuinely dangerous
    subprocess.run(f"ls {shlex.quote(cmd)}", shell=True)  # SANITIZED — our own fix!
    subprocess.run(shlex.split(cmd), shell=False)         # safe argv form
    subprocess.run(["git", "status"], shell=False)        # NO user input at all

The third and fourth have no injection surface whatsoever, and the second is
literally the remediation `lucin fix` tells the user to apply — we flagged code for
not being fixed, then flagged it again after it was.

WHY KIND-SCOPED
---------------
Sanitization is sink-specific: `shlex.quote` makes a value safe for a SHELL sink and
does nothing for a SQL sink; `html.escape` protects HTML and not shell. Pysa models
this explicitly (`Sanitize[TaintSink[SQL]]`) and its own docs warn that unscoped
sanitizers "affect all flows indiscriminately". A global "is_sanitized" flag would
silence real bugs, so every entry here declares WHICH sink kinds it neutralises.

EVIDENCE FOR THE APPROACH
-------------------------
Artemis (OOPSLA 2025, arXiv:2502.21026) ablated its taint rules and found that
weaker propagation/sanitizer modelling produced **9.2x more false positives** — the
largest single effect in the SOTA survey we ran. Pysa (pyre-check.org/docs/pysa-basics)
and CodeQL (`isBarrier`/flow-state) both make sources/sinks/sanitizers the primary
extension points. This module is the same idea, sized for an AST-only analyzer.

SCOPE / HONEST LIMITS
---------------------
Intraprocedural and name-based: we resolve import aliases and same-function data
flow only. A sanitizer applied in another function is NOT seen (no whole-program
call graph — PyCG is blocked in this environment). Unrecognised calls are treated as
NOT sanitizing (fail-closed), so this can only ever *withdraw* a finding we can
prove is guarded — never introduce one.
"""

from __future__ import annotations

import ast
from enum import Enum


class SinkKind(str, Enum):
    """The sink families a sanitizer can neutralise."""
    COMMAND = "command"        # shell / subprocess / exec
    SQL = "sql"
    PATH = "path"              # filesystem path traversal
    HTML = "html"
    URL = "url"                # SSRF / request targets


# name -> the sink kinds it makes safe. Deliberately narrow; fail closed.
# `shlex.split` is NOT a sanitizer: it produces an argv LIST, which is only safe
# because it avoids a shell — handled by the argv-form check below, not here.
SANITIZERS: dict[str, frozenset[SinkKind]] = {
    # shell quoting/escaping
    "shlex.quote": frozenset({SinkKind.COMMAND}),
    "shlex.join": frozenset({SinkKind.COMMAND}),
    "oslex.quote": frozenset({SinkKind.COMMAND}),
    "oslex.join": frozenset({SinkKind.COMMAND}),
    "pipes.quote": frozenset({SinkKind.COMMAND}),
    # path confinement
    "os.path.basename": frozenset({SinkKind.PATH}),
    "werkzeug.utils.secure_filename": frozenset({SinkKind.PATH}),
    "secure_filename": frozenset({SinkKind.PATH}),
    # html / url
    "html.escape": frozenset({SinkKind.HTML}),
    "urllib.parse.quote": frozenset({SinkKind.URL}),
    "urllib.parse.quote_plus": frozenset({SinkKind.URL}),
    # regex metacharacter escaping (protects a regex-built command, not SQL)
    "re.escape": frozenset({SinkKind.COMMAND}),
}

# Calls whose RESULT is a shell-free argument vector. Passing a list to subprocess
# without shell=True means the OS execs argv directly — no shell metacharacter
# interpretation, so injection via `; rm -rf` is structurally impossible.
ARGV_BUILDERS = {"shlex.split"}


def _resolve(node: ast.Call, aliases: dict[str, str] | None) -> str:
    """Dotted call name with import aliases resolved (`sp.run` -> `subprocess.run`)."""
    func = node.func
    parts: list[str] = []
    if isinstance(func, ast.Name):
        parts = [func.id]
    else:
        cur = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
    if not parts:
        return ""
    if aliases and parts[0] in aliases:
        parts[0] = aliases[parts[0]]
    return ".".join(parts)


def sanitizer_kinds(node: ast.Call, aliases: dict[str, str] | None = None) -> frozenset[SinkKind]:
    """Sink kinds this call neutralises (empty set if it is not a sanitizer)."""
    return SANITIZERS.get(_resolve(node, aliases), frozenset())


def is_argv_builder(node: ast.Call, aliases: dict[str, str] | None = None) -> bool:
    """True if the call yields an argv list (shell-free execution)."""
    return _resolve(node, aliases) in ARGV_BUILDERS


def expr_is_sanitized_for(expr: ast.expr, kind: SinkKind,
                          aliases: dict[str, str] | None = None) -> bool:
    """Is every tainted-looking part of `expr` wrapped in a sanitizer for `kind`?

    Conservative and structural: we return True when a sanitizer call for this sink
    kind appears anywhere inside the expression, INCLUDING inside f-string
    interpolations — `f"ls {shlex.quote(p)}"` is the canonical safe shape. We do NOT
    attempt to prove that *all* interpolations are wrapped (that needs the taint
    engine); callers combine this with a taint check.
    """
    for n in ast.walk(expr):
        if isinstance(n, ast.Call) and kind in sanitizer_kinds(n, aliases):
            return True
    return False


def call_is_shell_free_argv(call: ast.Call, aliases: dict[str, str] | None = None) -> bool:
    """True if this subprocess-style call execs an argv list WITHOUT a shell.

    `shell=True` is decisive: with a shell, even a list is joined and interpreted.
    A list literal (or `shlex.split(...)`) plus no `shell=True` means the argument
    vector is passed straight to execve — the structurally safe form.
    """
    for kw in call.keywords:
        if kw.arg == "shell":
            if not (isinstance(kw.value, ast.Constant) and kw.value.value is False):
                return False        # shell=True, or non-literal we cannot prove
    if not call.args:
        return False
    first = call.args[0]
    if isinstance(first, ast.List):
        return True
    if isinstance(first, ast.Call) and is_argv_builder(first, aliases):
        return True
    return False


def exec_guard_status(func_node: ast.FunctionDef,
                      aliases: dict[str, str] | None = None) -> str:
    """Classify a tool body's command-execution posture.

    Returns one of:
      "unguarded" — a parameter reaches a shell/exec sink with no sanitizer and no
                    shell-free argv form. This is the real AG-001 finding.
      "guarded"   — every exec sink we can see is either shell-free argv, wrapped in
                    a COMMAND-kind sanitizer, or built entirely from literals.
      "none"      — no exec sink in this body at all.

    Fail-closed: anything we cannot prove guarded counts as "unguarded", so this can
    only downgrade findings we can positively justify.
    """
    from lucin.parsers.body_inspector import DANGEROUS_EXEC_CALLS

    params = {a.arg for a in func_node.args.args} - {
        "self", "cls", "ctx", "context", "run_manager", "config", "runtime"}
    # TRANSITIVE taint: a value DERIVED from a parameter is still attacker-reachable.
    # Checking only for a parameter name directly inside the call arguments made
    # `module = ast.parse(code); exec(module)` look literal, which SUPPRESSED 2
    # confirmed true positives (bisheng `execute_function`, RD-Agent `execute`) and
    # made precision worse, not better. Weak propagation is the dominant FP/FN
    # driver in the literature (Artemis ablation: 9.2x more FPs with weaker rules),
    # so propagate to a fixpoint and fail closed.
    tainted = set(params)
    changed = True
    while changed:
        changed = False
        for n in ast.walk(func_node):
            targets = []
            if isinstance(n, ast.Assign):
                targets, value = n.targets, n.value
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                targets, value = [n.target], n.value
            else:
                continue
            if not any(isinstance(x, ast.Name) and x.id in tainted
                       for x in ast.walk(value)):
                continue
            for t in targets:
                for x in ast.walk(t):
                    if isinstance(x, ast.Name) and x.id not in tainted:
                        tainted.add(x.id)
                        changed = True
    params = tainted

    saw_exec = False
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue
        name = _resolve(node, aliases)
        bare = name.split(".")[-1]
        is_exec_sink = (name in DANGEROUS_EXEC_CALLS
                        or name in ("eval", "exec")
                        or bare in ("system", "popen"))
        if not is_exec_sink:
            continue
        saw_exec = True
        # Guarded if: shell-free argv, OR command has no parameter in it, OR a
        # COMMAND-kind sanitizer is applied to the command expression.
        if call_is_shell_free_argv(node, aliases):
            continue
        if command_is_fully_literal(node, params):
            continue
        if node.args and expr_is_sanitized_for(node.args[0], SinkKind.COMMAND, aliases):
            continue
        return "unguarded"          # one unguarded sink is enough
    return "guarded" if saw_exec else "none"


def command_is_fully_literal(call: ast.Call, param_names: set[str]) -> bool:
    """True only if the command is built ENTIRELY from constant literals.

    `subprocess.run(["git", "status"])` has no attacker-reachable input at all, so
    there is nothing to inject. Anything else — a parameter, a `self.<attr>`, a
    global, a function call — is treated as NOT literal.

    Why so strict (measured 2026-07-30): the earlier version only looked for a
    *parameter* in the command, which suppressed a confirmed true positive in
    RD-Agent's `execute(self, data_type="Debug")`. Its only parameter is a mode
    string; the code it runs comes from `self.file_dict` — LLM-authored workspace
    state. For an AGENT that state is attacker-reachable under prompt injection, so
    "no parameter here" is not the same as "no attack surface". `param_names` is
    retained for API compatibility and as a fast reject.
    """
    if not call.args:
        return False
    target = call.args[0]
    for n in ast.walk(target):
        if isinstance(n, (ast.Name, ast.Attribute, ast.Subscript, ast.Call,
                          ast.Starred, ast.JoinedStr, ast.FormattedValue)):
            return False          # any non-constant source ⇒ not literal
    return True
