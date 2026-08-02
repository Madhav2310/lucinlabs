"""AG-PATH-TRAVERSAL: tool-controlled path reaching a file sink without containment.

An agent tool that opens / reads / writes / deletes a file at a path derived from
a tool parameter — with no normalization + containment check — is a path
traversal (CWE-22): '../../etc/passwd' escapes any intended base directory, and a
naive os.path.join('./base', param) does NOT prevent it.

Sinks:
  - open / io.open                (read or write, mode-aware for severity)
  - os.remove / os.unlink / os.rmdir / os.rename / os.replace
  - shutil.rmtree / shutil.move / shutil.copy / shutil.copyfile / shutil.copy2
  - flask send_file
  - pathlib: Path(...).read_text / write_text / read_bytes / write_bytes / unlink,
    or  p.read_text() where p is a tainted Path

PRECISION MODEL (path traversal is the most FP-prone class under static analysis,
so gating is deliberately conservative — we accept lower recall over any benign FP):
  1. The function must expose a PATH-LIKE parameter (name contains path/file/dir/
     template/document/report/…). Tools with no path-shaped input aren't flagged.
  2. A tainted value must reach a file sink.
  3. The function must contain NO containment/normalization signal — realpath/
     abspath/resolve/relative_to/commonpath/secure_filename/safe_join/_check_path,
     or an explicit '..' check. Any such signal → skip (assume validated).

Corpus evidence: agno PythonTools.read_file uses _check_path containment → we
(correctly) do NOT flag it. The constructed read/write/delete/join/template cases
have no containment → flagged.
"""

from __future__ import annotations

import ast
from pathlib import Path

from lucin.models import Agent, Finding, Severity
from lucin.detectors._taint import (
    compute_taint, is_tainted, iter_functions, resolve_sig, param_names,
    source_files_for,
)
from lucin.parsers.body_inspector import build_import_alias_map


# Function-style file sinks (path is a positional arg).
_READ_SINKS = {"open", "io.open"}
_DESTRUCTIVE_SINKS = {
    "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
    "os.rename", "os.replace",
    "shutil.rmtree", "shutil.move", "shutil.copy", "shutil.copyfile", "shutil.copy2",
}
_SEND_SINKS = {"send_file", "flask.send_file"}

# pathlib / object method sinks (path is the RECEIVER).
_READ_METHODS = {"read_text", "read_bytes"}
_WRITE_METHODS = {"write_text", "write_bytes", "unlink"}

# param name tokens that indicate a filesystem-path-shaped input.
_PATH_TOKENS = ("path", "file", "dir", "folder", "template", "document",
                "report", "fname", "fpath", "filename")

# Containment / normalization signals — presence anywhere in the function → skip.
_CONTAINMENT_SIGS = {
    "os.path.realpath", "os.path.abspath", "os.path.normpath",
    "os.path.commonpath", "os.path.commonprefix",
    "realpath", "abspath", "normpath", "commonpath", "commonprefix",
    "secure_filename", "werkzeug.utils.secure_filename",
    "safe_join", "werkzeug.utils.safe_join", "send_from_directory",
    "flask.send_from_directory",
}
_CONTAINMENT_METHODS = {"resolve", "relative_to", "is_relative_to", "commonpath"}
_CONTAINMENT_NAME_TOKENS = ("check_path", "is_safe_path", "safe_join",
                            "validate_path", "sanitize_path", "is_within",
                            "ensure_within", "secure_filename")


def _open_is_write(call_node: ast.Call) -> bool:
    mode = None
    if len(call_node.args) >= 2 and isinstance(call_node.args[1], ast.Constant):
        mode = call_node.args[1].value
    for kw in call_node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = kw.value.value
    if not isinstance(mode, str):
        return False
    return any(c in mode for c in ("w", "a", "x", "+"))


def _has_path_param(func_node) -> bool:
    for name in param_names(func_node):
        low = name.lower()
        if any(tok in low for tok in _PATH_TOKENS):
            return True
    return False


def _has_containment(func_node, aliases: dict[str, str]) -> bool:
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            sig = resolve_sig(node, aliases) or ""
            if sig in _CONTAINMENT_SIGS:
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr in _CONTAINMENT_METHODS:
                return True
            if isinstance(node.func, ast.Name) and any(
                    tok in node.func.id.lower() for tok in _CONTAINMENT_NAME_TOKENS):
                return True
            if isinstance(node.func, ast.Attribute) and any(
                    tok in node.func.attr.lower() for tok in _CONTAINMENT_NAME_TOKENS):
                return True
        # explicit '..' traversal check
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and node.value in ("..", "../", "..\\"):
            return True
    return False


def _receiver_is_tainted_path(receiver: ast.expr, tainted: set[str],
                              aliases: dict[str, str]) -> bool:
    """A Path-object receiver whose construction is tool-controlled."""
    if isinstance(receiver, ast.Name):
        return receiver.id in tainted
    if isinstance(receiver, ast.Call):
        sig = resolve_sig(receiver, aliases) or ""
        if sig in ("Path", "pathlib.Path", "PurePath", "pathlib.PurePath"):
            return any(is_tainted(a, tainted) for a in receiver.args)
    return False


def detect_path_traversal(agent: Agent) -> list[Finding]:
    findings: list[Finding] = []
    scanned: set[str] = set()

    for filepath in source_files_for(agent):
        if filepath in scanned:
            continue
        scanned.add(filepath)
        try:
            source = Path(filepath).read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            continue

        aliases = build_import_alias_map(tree)

        for func in iter_functions(tree):
            tainted, params = compute_taint(func)
            if not params or not _has_path_param(func):
                continue
            if _has_containment(func, aliases):
                continue

            for node in ast.walk(func):
                if not isinstance(node, ast.Call):
                    continue

                sink = None          # dotted signature or method label
                is_write = False
                path_arg = None

                sig = resolve_sig(node, aliases)
                if sig in _READ_SINKS:
                    if node.args:
                        path_arg = node.args[0]
                        sink, is_write = sig, _open_is_write(node)
                elif sig in _DESTRUCTIVE_SINKS:
                    if node.args:
                        # source and/or dest may be tainted
                        candidates = node.args[:2]
                        path_arg = next(
                            (a for a in candidates if is_tainted(a, tainted)),
                            node.args[0])
                        sink, is_write = sig, True
                elif sig in _SEND_SINKS:
                    if node.args:
                        path_arg = node.args[0]
                        sink, is_write = sig, False
                elif isinstance(node.func, ast.Attribute) and (
                        node.func.attr in _READ_METHODS or node.func.attr in _WRITE_METHODS):
                    receiver = node.func.value
                    if _receiver_is_tainted_path(receiver, tainted, aliases):
                        sink = f"Path.{node.func.attr}"
                        is_write = node.func.attr in _WRITE_METHODS
                        # taint already confirmed on the receiver
                        path_arg = receiver

                if sink is None or path_arg is None:
                    continue
                if not is_tainted(path_arg, tainted):
                    continue

                severity = Severity.CRITICAL if is_write else Severity.HIGH
                action = "write/delete" if is_write else "read"
                findings.append(Finding(
                    id="AG-PATH-TRAVERSAL",
                    title=f"Path Traversal ({action}) in '{func.name}'",
                    severity=severity,
                    description=(
                        f"Function '{func.name}' uses a tool-controlled path in a file "
                        f"{action} sink ('{sink}') with no normalization/containment check. "
                        f"A parameter like '../../etc/passwd' (read) or '../../.bashrc' "
                        f"(write) escapes any intended base directory — os.path.join with a "
                        f"'..' segment does NOT contain the path."
                    ),
                    agent_name=agent.name,
                    attack_scenario=(
                        "1. Attacker gets the agent to call this tool with a traversal path\n"
                        f"2. The tool performs a {action} at that path outside the sandbox\n"
                        "3. Reads secrets (/etc/passwd, .env, SSH keys) or overwrites/deletes "
                        "arbitrary host files"
                    ),
                    blast_radius=(
                        "Arbitrary file read (credential/secret disclosure) or arbitrary file "
                        "write/delete (config tampering, code overwrite → RCE) on the host."
                    ),
                    owasp_ref="A01 - Broken Access Control / ASI02 - Tool Misuse",
                    fix_suggestion=(
                        "Normalize AND contain the path before use:\n"
                        "  base = Path(BASE_DIR).resolve()\n"
                        "  target = (base / user_path).resolve()\n"
                        "  if not target.is_relative_to(base): raise ValueError\n"
                        "Or use werkzeug.utils.secure_filename / send_from_directory for "
                        "downloads. Never open a raw tool parameter directly."
                    ),
                    source_file=filepath,
                    source_line=node.lineno,
                    witness=[
                        f"tainted path → {sink}(...) [{action}] in '{func.name}' "
                        f"(line {node.lineno})"
                    ],
                ))

    seen: set[tuple] = set()
    unique = []
    for f in findings:
        key = (f.source_file, f.source_line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
