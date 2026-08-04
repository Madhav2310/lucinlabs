"""Function Body Inspector — analyzes tool implementation code for hidden capabilities.

This is the critical missing piece that separates a toy scanner from a real one.
Pattern matching on tool NAMES catches naive cases. Body inspection catches:
1. Shell execution hidden behind innocent names ("data_processor" → subprocess.run)
2. Network access disguised as logging ("analytics_logger" → urllib.request)
3. Eval/exec with variable arguments ("calculator" → eval(user_input))
4. Dynamic imports that load dangerous modules at runtime

Approach (inspired by Bandit + Semgrep):
- Walk the AST of each tool function body
- Track dangerous API calls (subprocess, os, eval, urllib, socket)
- Optionally follow one level of function calls (intra-file resolution)
- Return discovered capabilities that the name/description analysis missed

This is NOT full taint analysis (that requires data-flow graphs and is 10x harder).
This IS Bandit-level dangerous-call detection scoped to tool function bodies.
"""

import ast
from dataclasses import dataclass
from pathlib import Path

from lucin.models import ToolCapability

# === Dangerous API signatures ===
# Maps (module.function OR builtin) → capability it implies
DANGEROUS_EXEC_CALLS = {
    # subprocess
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    # os execution
    "os.system",
    "os.popen",
    "os.exec",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    # builtins
    "eval",
    "exec",
    "compile",
    "__import__",
    # importlib
    "importlib.import_module",
}

# Read-only network calls (GET, HEAD, etc.) — these FETCH data in, not send it out.
# Tools using only these are sources, not egress sinks (no trifecta risk on their own).
FETCH_ONLY_NETWORK_CALLS = {
    "requests.get",
    "requests.head",
    "httpx.get",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
}

DANGEROUS_NETWORK_CALLS = {
    # urllib
    "urllib.request.urlopen",
    "urllib.request.Request",
    "urllib.request.urlretrieve",
    # requests library
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.request",
    "requests.head",
    "requests.patch",
    # httpx
    "httpx.get",
    "httpx.post",
    "httpx.Client",
    "httpx.AsyncClient",
    # socket
    "socket.socket",
    "socket.create_connection",
    "socket.gethostbyname",
    # aiohttp
    "aiohttp.ClientSession",
}

DANGEROUS_FILE_READ_CALLS = {
    "open",  # Will need context (mode='r')
    "Path.read_text",
    "Path.read_bytes",
    "os.listdir",
    "os.walk",
    "os.scandir",
    "glob.glob",
    "glob.iglob",
}

DANGEROUS_FILE_WRITE_CALLS = {
    "Path.write_text",
    "Path.write_bytes",
    "Path.mkdir",
    "os.makedirs",
    "os.mkdir",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "shutil.rmtree",
    "shutil.copy",
    "shutil.move",
}

# Obfuscation indicators — these suggest hidden dangerous operations
# If present alongside execution calls, elevate severity
OBFUSCATION_CALLS = {
    "base64.b64decode",
    "base64.b64encode",
    "base64.decodebytes",
    "codecs.decode",
    "binascii.unhexlify",
    "bytes.fromhex",
    "marshal.loads",
    "pickle.loads",
    "compile",
}


def inspect_function_body(
    func_node: ast.FunctionDef,
    source: str = "",
    import_aliases: dict[str, str] | None = None,
) -> list[ToolCapability]:
    """Inspect a function's AST for dangerous API calls.

    Returns capabilities discovered from the function body that may not be
    apparent from the function's name or docstring alone.

    This catches the "innocent name, dangerous body" evasion pattern.

    Args:
        func_node: The function definition AST node
        source: Original source code (for context)
        import_aliases: Map of alias → real module path (e.g., {"runner": "os.popen"})
    """
    capabilities = set()
    aliases = import_aliases or {}

    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            call_signature = _resolve_call_name(node)

            # Apply import alias resolution
            if call_signature and call_signature in aliases:
                call_signature = aliases[call_signature]
            elif call_signature:
                # Try resolving just the module part (sp.run → subprocess.run)
                parts = call_signature.split(".", 1)
                if parts[0] in aliases:
                    resolved_module = aliases[parts[0]]
                    call_signature = resolved_module + ("." + parts[1] if len(parts) > 1 else "")

            if call_signature:
                # Check each category
                if call_signature in DANGEROUS_EXEC_CALLS:
                    capabilities.add(ToolCapability.EXECUTE_CODE)
                elif call_signature in DANGEROUS_NETWORK_CALLS:
                    capabilities.add(ToolCapability.NETWORK_ACCESS)
                elif call_signature == "open":
                    # Mode-aware: open(f, "w"/"a"/"x"/"+") writes; default/"r" reads.
                    # Previously open() was always tagged READ regardless of mode.
                    capabilities.add(ToolCapability.FILE_SYSTEM)
                    if _open_is_write(node):
                        capabilities.add(ToolCapability.WRITE_DATA)
                    else:
                        capabilities.add(ToolCapability.READ_DATA)
                elif call_signature in DANGEROUS_FILE_READ_CALLS:
                    capabilities.add(ToolCapability.READ_DATA)
                    capabilities.add(ToolCapability.FILE_SYSTEM)
                elif call_signature in DANGEROUS_FILE_WRITE_CALLS:
                    capabilities.add(ToolCapability.WRITE_DATA)
                    capabilities.add(ToolCapability.FILE_SYSTEM)
                else:
                    # Partial matches for dynamic patterns
                    _check_partial_matches(call_signature, node, capabilities)

        # Check for `shell=True` in keyword arguments (subprocess indicator)
        if isinstance(node, ast.keyword):
            if node.arg == "shell" and isinstance(node.value, ast.Constant) and node.value.value is True:
                capabilities.add(ToolCapability.EXECUTE_CODE)

    # Check for obfuscation+execution combination
    # Pattern: base64.b64decode() + eval/exec in same function = hidden code execution
    has_obfuscation = False
    has_exec_builtin = False
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            call_name = _resolve_call_name(node)
            # Apply aliases
            if call_name and call_name in aliases:
                call_name = aliases[call_name]
            elif call_name:
                parts = call_name.split(".", 1)
                if parts[0] in aliases:
                    call_name = aliases[parts[0]] + ("." + parts[1] if len(parts) > 1 else "")

            if call_name in OBFUSCATION_CALLS:
                has_obfuscation = True
            if call_name in ("eval", "exec", "compile"):
                has_exec_builtin = True

    if has_obfuscation and has_exec_builtin:
        capabilities.add(ToolCapability.EXECUTE_CODE)

    # Also: if function has ONLY obfuscation calls (decode + no obvious use),
    # it might be decoding shellcode for later use — flag as suspicious
    if has_obfuscation and not capabilities:
        # Check if decoded content is passed to a function that COULD execute
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                call_name = _resolve_call_name(node)
                # Exact-signature membership only. The previous version used substring
                # matching (`"run" in call_name`), which fired on benign names like
                # `arun`, `rerun`, `prune`, `run_chain` — a false-positive source.
                if call_name and (call_name in DANGEROUS_EXEC_CALLS
                                  or call_name in ("eval", "exec", "compile")):
                    capabilities.add(ToolCapability.EXECUTE_CODE)
                    break

    return list(capabilities)


def check_parameter_taint(func_node: ast.FunctionDef) -> dict[str, bool]:
    """Check if function parameters flow into dangerous calls (taint tracking v1).

    Returns a dict mapping capability → is_tainted_by_parameter.

    If a parameter flows directly into subprocess.run(), eval(), etc.,
    the tool is INJECTABLE (parameter-controlled execution).
    If the dangerous call uses only hardcoded values, it's dangerous
    but NOT directly injectable via the tool's input.

    This is the simplest form of taint analysis — single-function,
    tracks whether ANY parameter name appears as an argument to a
    dangerous call within the same function body.
    """
    # Get parameter names
    param_names = set()
    for arg in func_node.args.args:
        param_names.add(arg.arg)
    # Skip 'self', 'cls', 'ctx', 'context' (not user-controlled)
    param_names -= {"self", "cls", "ctx", "context", "run_manager", "config", "runtime"}

    if not param_names:
        return {}

    taint_results = {
        "exec_tainted": False,
        "network_tainted": False,
        "file_tainted": False,
    }

    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue

        call_name = _resolve_call_name(node)
        if not call_name:
            continue

        # Check if any argument to this call is a parameter (or derived from one)
        args_contain_param = _args_reference_params(node, param_names)

        if not args_contain_param:
            continue

        # Parameter flows into a dangerous call — this is tainted
        if call_name in DANGEROUS_EXEC_CALLS or call_name in ("eval", "exec"):
            taint_results["exec_tainted"] = True
        elif call_name in DANGEROUS_NETWORK_CALLS:
            taint_results["network_tainted"] = True
        elif call_name in DANGEROUS_FILE_READ_CALLS or call_name in DANGEROUS_FILE_WRITE_CALLS:
            taint_results["file_tainted"] = True

        # Also check for shell=True with param as command
        if call_name in ("subprocess.run", "subprocess.call", "subprocess.Popen"):
            if args_contain_param:
                taint_results["exec_tainted"] = True

    return taint_results


def _args_reference_params(call_node: ast.Call, param_names: set) -> bool:
    """Check if any argument to a function call references a parameter name.

    Handles:
    - Direct: subprocess.run(cmd, ...) where cmd is a parameter
    - Simple variable: subprocess.run(x, ...) where x was assigned from param
    - f-string: subprocess.run(f"cmd {param}", ...)
    """
    # Check positional arguments
    for arg in call_node.args:
        if _expr_references_params(arg, param_names):
            return True

    # Check keyword arguments (especially first positional or 'input'/'command'/'cmd' kwargs)
    for kw in call_node.keywords:
        if kw.arg in ("input", "command", "cmd", "code", "expression", "query", "sql"):
            if _expr_references_params(kw.value, param_names):
                return True
        # Also check all kwarg values
        if _expr_references_params(kw.value, param_names):
            return True

    return False


def _expr_references_params(expr: ast.expr, param_names: set) -> bool:
    """Check if an expression references any parameter name."""
    if isinstance(expr, ast.Name):
        return expr.id in param_names
    elif isinstance(expr, ast.JoinedStr):
        # f-string: check all values
        for value in expr.values:
            if isinstance(value, ast.FormattedValue):
                if _expr_references_params(value.value, param_names):
                    return True
    elif isinstance(expr, ast.BinOp):
        # String concatenation: "prefix" + param
        return (_expr_references_params(expr.left, param_names) or
                _expr_references_params(expr.right, param_names))
    elif isinstance(expr, ast.Call):
        # str(param), param.encode(), etc.
        for arg in expr.args:
            if _expr_references_params(arg, param_names):
                return True
        if isinstance(expr.func, ast.Attribute) and isinstance(expr.func.value, ast.Name):
            if expr.func.value.id in param_names:
                return True
    elif isinstance(expr, ast.Subscript):
        # param[0], param["key"]
        if isinstance(expr.value, ast.Name) and expr.value.id in param_names:
            return True
    return False


def build_import_alias_map(tree: ast.Module) -> dict[str, str]:
    """Build a map of import aliases to their real module paths.

    Handles:
    - `import subprocess as sp` → {"sp": "subprocess"}
    - `from os import popen as runner` → {"runner": "os.popen"}
    - `from os import system` → {"system": "os.system"}
    - `import os` → {"os": "os"} (identity, for completeness)
    - `from subprocess import run, Popen` → {"run": "subprocess.run", "Popen": "subprocess.Popen"}
    """
    aliases = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # import subprocess as sp
                real_name = alias.name  # "subprocess"
                used_name = alias.asname or alias.name  # "sp" or "subprocess"
                aliases[used_name] = real_name

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                # from os import popen as runner
                real_name = f"{module}.{alias.name}" if module else alias.name
                used_name = alias.asname or alias.name
                aliases[used_name] = real_name

    return aliases


def inspect_function_body_with_callees(
    func_node: ast.FunctionDef,
    func_map: dict[str, ast.FunctionDef],
    import_aliases: dict[str, str] | None = None,
    max_depth: int = 1,
) -> list[ToolCapability]:
    """Inspect a function body AND follow one level of local function calls.

    This catches: tool_func() → helper() → os.system()

    We inspect the tool function itself, then for any function calls within it
    that resolve to local functions in func_map, we also inspect THOSE bodies.
    This gives us one-hop call resolution without full call graph construction.

    Args:
        func_node: The tool function to inspect
        func_map: All function definitions in the same file
        import_aliases: Import alias resolution map
        max_depth: How many hops to follow (default 1)
    """
    # First: inspect the function itself
    capabilities = set(inspect_function_body(func_node, import_aliases=import_aliases))

    if max_depth <= 0:
        return list(capabilities)

    # Second: find all function calls within the body that map to local functions
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            callee_name = _resolve_call_name(node)
            if callee_name:
                # `self._helper()` / `cls._helper()` resolve to the DOTTED name
                # ("self._docker_exec"), which never matched `func_map`, whose
                # keys are bare method names. Class-based toolkits hide their exec
                # behind exactly that shape — measured cost: 4 real recall misses
                # (camel terminal/docker/code-exec, promptflow REPL). Strip the
                # receiver so the method body is actually followed.
                if callee_name.startswith(("self.", "cls.")):
                    callee_name = callee_name.split(".", 1)[1]
            if callee_name and callee_name in func_map:
                # This is a call to a local function — inspect its body too
                callee_func = func_map[callee_name]
                # Recursive with reduced depth to prevent infinite loops
                callee_caps = inspect_function_body_with_callees(
                    callee_func, func_map, import_aliases, max_depth - 1
                )
                capabilities.update(callee_caps)

    return list(capabilities)


def exec_is_body_confirmed(func_node: ast.FunctionDef,
                           tree: ast.Module | None = None) -> bool:
    """Is EXECUTE_CODE provable from this tool's OWN code (incl. local callees)?

    Used ONLY to grade a finding's SEVERITY, never to add or remove a capability
    — so it cannot introduce new findings (and therefore cannot regress the
    benign-corpus precision gate). Follows `self.*`/`cls.*` methods and local
    helpers one hop, so class-based toolkits (`self._docker_exec(...)`) count as
    confirmed.

    True  = we saw a real exec sink -> the CRITICAL claim is earned.
    False = the tool's body is readable and shows NO exec -> the capability came
            from the tool's NAME/description alone, so the finding is a
            capability *suspicion*, not demonstrated code execution.
    """
    aliases = build_import_alias_map(tree) if tree is not None else None
    if tree is not None:
        func_map = {f.name: f for f in ast.walk(tree)
                    if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))}
        caps = inspect_function_body_with_callees(func_node, func_map, aliases)
    else:
        caps = inspect_function_body(func_node, import_aliases=aliases)
    return ToolCapability.EXECUTE_CODE in caps


def inspect_file_for_tool_bodies(filepath: str, tool_func_names: list[str]) -> dict[str, list[ToolCapability]]:
    """Inspect specific function bodies in a file for hidden capabilities.

    Args:
        filepath: Path to the Python file
        tool_func_names: Names of functions that are registered as tools

    Returns:
        Dict mapping function name → list of discovered capabilities
    """
    results = {}

    try:
        source = Path(filepath).read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (FileNotFoundError, SyntaxError, UnicodeDecodeError):
        return results

    # Build a map of all function definitions (sync + async — E2)
    func_map = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_map[node.name] = node

    # Inspect each tool function
    for func_name in tool_func_names:
        if func_name in func_map:
            caps = inspect_function_body(func_map[func_name], source)
            if caps:
                results[func_name] = caps

    # Also look for lambda tools (common pattern: Tool(func=lambda x: ...))
    for node in ast.walk(tree):
        if isinstance(node, ast.Lambda):
            # Check if lambda contains dangerous calls
            caps = _inspect_lambda(node)
            if caps:
                # Try to identify which tool this lambda belongs to
                results["<lambda>"] = caps

    return results


def _resolve_call_name(call_node: ast.Call) -> str | None:
    """Resolve the full name of a function call.

    Examples:
        subprocess.run(...) → "subprocess.run"
        os.popen(...) → "os.popen"
        eval(...) → "eval"
        __import__(...) → "__import__"
        requests.post(...) → "requests.post"
    """
    func = call_node.func

    if isinstance(func, ast.Name):
        # Direct call: eval(), exec(), open()
        return func.id

    elif isinstance(func, ast.Attribute):
        # Attribute call: os.system(), subprocess.run()
        parts = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            parts.reverse()
            return ".".join(parts)

    return None


def is_fetch_only_function(
    func_node: ast.FunctionDef,
    import_aliases: dict[str, str] | None = None,
) -> bool:
    """Return True if the function uses ONLY read-network calls (GET/HEAD).

    A tool that exclusively uses requests.get(), urllib.urlopen(), httpx.get()
    is a data-fetch source, not an egress sink. This prevents trifecta FPs on
    weather, currency, and search tools.

    Corpus evidence: smolagents' convert_currency/get_weather/get_news use
    requests.get() — they are fetch tools, not exfiltration sinks.
    """
    aliases = import_aliases or {}
    has_network = False
    has_send_network = False

    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue
        sig = _resolve_call_name(node)
        if sig and sig in aliases:
            sig = aliases[sig]
        if not sig:
            continue
        if sig in DANGEROUS_NETWORK_CALLS:
            has_network = True
            if sig not in FETCH_ONLY_NETWORK_CALLS:
                has_send_network = True
                break

    return has_network and not has_send_network


def _open_is_write(node: ast.Call) -> bool:
    """Return True if an open() call opens for writing/appending.

    Reads the mode from the 2nd positional arg or the ``mode=`` keyword.
    Write modes contain 'w', 'a', 'x', or '+'. open()'s default is 'r', so an
    unknown or absent mode is treated as read (conservative for the WRITE class).
    """
    mode = None
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        mode = node.args[1].value
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = kw.value.value
    if not isinstance(mode, str):
        return False
    return any(c in mode for c in ("w", "a", "x", "+"))


def _check_partial_matches(call_name: str, node: ast.Call, capabilities: set):
    """Check for dynamic-dispatch evasion via getattr() with a literal function name.

    Catches the genuine evasion pattern:
    - getattr(os, 'popen')(...) → exec
    - getattr(os, 'system')(...) → exec

    NOTE: bare method-name matching (e.g. ``x.run()`` → EXEC, ``x.get()`` → NETWORK)
    was DELETED in Phase 0. It was the #1 false-positive source: it tagged
    ``dict.get()``, ``os.environ.get()``, ``chain.run()``, ``app.run()``,
    ``f.read()`` etc. as dangerous, manufacturing CRITICAL findings on benign code.
    Real dangerous calls are caught by exact-signature matching (DANGEROUS_*_CALLS)
    plus import-alias resolution; this getattr() path handles the one dynamic case
    that exact matching cannot see. Precision over recall by design.
    """
    # getattr() with dangerous function names (string literal only → no FP on dynamic attr)
    if isinstance(node.func, ast.Name) and node.func.id == "getattr":
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            attr_name = node.args[1].value
            if isinstance(attr_name, str):
                if attr_name in ("system", "popen", "exec", "eval", "run"):
                    capabilities.add(ToolCapability.EXECUTE_CODE)
                elif attr_name in ("urlopen", "request"):
                    capabilities.add(ToolCapability.NETWORK_ACCESS)


def _inspect_lambda(node: ast.Lambda) -> list[ToolCapability]:
    """Inspect a lambda body for dangerous calls."""
    capabilities = set()
    for child in ast.walk(node.body):
        if isinstance(child, ast.Call):
            call_name = _resolve_call_name(child)
            if call_name:
                if call_name in DANGEROUS_EXEC_CALLS:
                    capabilities.add(ToolCapability.EXECUTE_CODE)
                elif call_name in DANGEROUS_NETWORK_CALLS:
                    capabilities.add(ToolCapability.NETWORK_ACCESS)
    return list(capabilities)


# ---------------------------------------------------------------------------
# Intraprocedural taint — monotone worklist over a single function's AST
# ---------------------------------------------------------------------------
# This is Phase 1's taint engine foundation (Blueprint §4.3, Codex §1).
# Tracks taint propagation THROUGH assignments, not just at call sites.
# Detects: param → intermediate_var → dangerous_call (which ast.walk misses).
# Scope: single function, flow-sensitive via statement ordering, field-insensitive.
# No external deps — pure stdlib ast.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TaintFlow:
    """One confirmed taint flow: a parameter reached a dangerous sink."""
    param: str               # which parameter is tainted
    sink_call: str           # which dangerous call it reached
    sink_type: str           # "exec", "network", or "file"
    via: list[str]           # intermediate variable names traversed


def intraproc_taint(func_node: ast.FunctionDef,
                    import_aliases: dict[str, str] | None = None) -> list[TaintFlow]:
    """Monotone-worklist intraprocedural taint analysis.

    Returns every confirmed TaintFlow where a user-controlled parameter
    (directly or via assignments) reaches an exec/network/file sink.

    Algorithm:
    1. Seed: each user-visible parameter is tainted.
    2. Propagate: for each assignment `x = f(...)` where any argument
       is tainted, `x` becomes tainted (join — once tainted, stays tainted).
    3. Check: when a dangerous call's arguments are tainted, record a flow.
    4. Iterate until no new tainted names are added (finite — bounded by
       the set of names in the function, guaranteed to terminate).

    This is strictly more precise than the existing check_parameter_taint
    which uses ast.walk (no ordering) and misses through-assignment flows.
    """
    aliases = import_aliases or {}

    SKIP_PARAMS = {"self", "cls", "ctx", "context", "run_manager", "config", "runtime"}
    params: set[str] = {
        a.arg for a in func_node.args.args
        if a.arg not in SKIP_PARAMS
    }
    if not params:
        return []

    tainted: set[str] = set(params)
    flows: list[TaintFlow] = []

    def _resolve(node: ast.expr) -> str | None:
        """Resolve a call node to its canonical signature."""
        sig = _resolve_call_name(node) if isinstance(node, ast.Call) else None
        if sig and sig in aliases:
            return aliases[sig]
        if sig:
            parts = sig.split(".", 1)
            if parts[0] in aliases:
                return aliases[parts[0]] + ("." + parts[1] if len(parts) > 1 else "")
        return sig

    def _names_in(node: ast.expr) -> set[str]:
        """Collect all Name ids referenced in an expression."""
        return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}

    def _is_tainted(node: ast.expr) -> bool:
        return bool(_names_in(node) & tainted)

    def _sink_type(call_sig: str) -> str | None:
        if call_sig in DANGEROUS_EXEC_CALLS or call_sig in ("eval", "exec", "compile"):
            return "exec"
        if call_sig in DANGEROUS_NETWORK_CALLS:
            return "network"
        if call_sig in DANGEROUS_FILE_WRITE_CALLS or call_sig in DANGEROUS_FILE_READ_CALLS:
            return "file"
        return None

    # Phase 1: propagate taint through assignments to fixpoint.
    # We iterate the full body until no new names are added (guaranteed finite —
    # bounded by the number of distinct names in the function).
    changed = True
    while changed:
        changed = False
        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign):
                if _is_tainted(node.value):
                    for target in node.targets:
                        for name in _names_in(target):
                            if name not in tainted:
                                tainted.add(name)
                                changed = True
            elif isinstance(node, ast.AnnAssign):
                if node.value and _is_tainted(node.value) and isinstance(node.target, ast.Name):
                    if node.target.id not in tainted:
                        tainted.add(node.target.id)
                        changed = True

    # Phase 2: check ALL call sites (not just bare-expression calls —
    # catches calls in return stmts, assignments, if-conditions, etc.)
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue
        sig = _resolve(node)
        if not sig:
            continue
        st = _sink_type(sig)
        if not st:
            continue
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        for arg in all_args:
            if _is_tainted(arg):
                tainted_args = _names_in(arg) & tainted
                param_hit = sorted(tainted_args & params)
                via = sorted(tainted_args - params)
                flows.append(TaintFlow(
                    param=param_hit[0] if param_hit else sorted(tainted_args)[0],
                    sink_call=sig,
                    sink_type=st,
                    via=via,
                ))
                break  # one flow per call site is enough

    # Deduplicate by (param, sink_call)
    seen: set[tuple] = set()
    unique = []
    for f in flows:
        key = (f.param, f.sink_call)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# Source-to-sink taint for standalone scripts (skill bundles).
#
# `intraproc_taint` above seeds taint from a TOOL FUNCTION's own parameters —
# the right model when the LLM calls a function with LLM-controlled arguments.
# A bundled skill script is typically a standalone program instead: its
# dangerous inputs are SOURCE CALLS (a remote fetch, an env var read, a file
# read, stdin), not parameters. This walks the whole module using the same
# fixpoint-worklist propagation, seeded from source calls instead of params.
#
# Source/sink categorization is modeled on NVIDIA/SkillSpector's taint
# analyzer (github.com/NVIDIA/SkillSpector, Apache-2.0,
# nodes/analyzers/behavioral_taint_tracking.py) but reuses this module's own
# DANGEROUS_* sink tables above rather than a separate ontology, so a finding
# here and a finding from the main scanner's own detectors always agree on
# what counts as a dangerous call.
# ---------------------------------------------------------------------------

DESERIALIZE_SINKS = {
    "pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load",
    "marshal.loads", "marshal.load", "dill.loads", "dill.load",
    "yaml.load", "yaml.unsafe_load", "yaml.full_load", "joblib.load",
}

CREDENTIAL_SOURCES = {"os.environ.get", "os.environ", "os.getenv"}
FILE_READ_SOURCES = {"open", "Path.read_text", "Path.read_bytes"}
USER_INPUT_SOURCES = {"input", "sys.stdin.read", "sys.stdin.readline"}
# Network reads are a source when their RESPONSE is untrusted external data —
# the same calls are also sinks when tainted data is passed as their payload.
NETWORK_READ_SOURCES = set(DANGEROUS_NETWORK_CALLS)

_ALL_SKILL_SOURCES = (
    CREDENTIAL_SOURCES | FILE_READ_SOURCES | USER_INPUT_SOURCES | NETWORK_READ_SOURCES
)
_ALL_SKILL_SINKS = (
    DANGEROUS_EXEC_CALLS | DANGEROUS_NETWORK_CALLS | DANGEROUS_FILE_WRITE_CALLS | DESERIALIZE_SINKS
)


@dataclass
class SourceSinkFlow:
    """One confirmed flow: an untrusted/external source reached a dangerous sink."""
    source_call: str    # e.g. "requests.get", "os.environ"
    sink_call: str      # e.g. "pickle.loads", "subprocess.run"
    sink_type: str      # "exec" | "network" | "file_write" | "deserialize"
    var_name: str       # tainted variable name, empty for a direct (inline) flow
    lineno: int


def _sink_type_for(sig: str) -> str | None:
    if sig in DANGEROUS_EXEC_CALLS:
        return "exec"
    if sig in DESERIALIZE_SINKS:
        return "deserialize"
    if sig in DANGEROUS_NETWORK_CALLS:
        return "network"
    if sig in DANGEROUS_FILE_WRITE_CALLS:
        return "file_write"
    return None


def _is_os_environ(node: ast.expr) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "environ" and \
        isinstance(node.value, ast.Name) and node.value.id == "os"


def source_sink_taint(tree: ast.Module,
                       import_aliases: dict[str, str] | None = None) -> list[SourceSinkFlow]:
    """Module-level source-to-sink taint analysis for standalone scripts.

    Returns every confirmed flow where a source call's result (directly, or via
    a chain of assignments) reaches a dangerous sink call. This is what makes
    `AG-SKILL-CHAIN` a genuine flow-composition detector instead of "N dangerous
    imports co-occur in the same file" — see
    `launch/evolving conviction/PHASE_6_PLAN.md` §5.3 option (b) / §5.2.4 (the
    differential run against SkillSpector found 0 differentiated findings for
    the import-presence version this replaces).

    Performance note: an earlier version re-walked the ENTIRE tree, and
    re-walked each assignment's value subtree, on every round of the fixpoint
    loop — quadratic-or-worse on large real files (17 of 3,229 `.py` files in
    the 337-skill corpus took >3s each, some effectively hanging). Assignments
    are now collected once; each fixpoint round is O(#assignments), not
    O(tree size), with the one-time per-assignment subtree walk paid exactly
    once regardless of how many rounds the fixpoint takes.
    """
    aliases = import_aliases or {}
    tainted: dict[str, str] = {}  # var name -> originating source signature
    flows: list[SourceSinkFlow] = []

    def _resolve(node: ast.expr) -> str | None:
        sig = _resolve_call_name(node) if isinstance(node, ast.Call) else None
        if sig and sig in aliases:
            return aliases[sig]
        if sig:
            parts = sig.split(".", 1)
            if parts[0] in aliases:
                return aliases[parts[0]] + ("." + parts[1] if len(parts) > 1 else "")
        return sig

    def _names_in(node: ast.expr) -> set[str]:
        return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}

    def _direct_source_in_expr(node: ast.expr) -> str | None:
        """A source-call signature *literally present* in this expression —
        does not depend on the current `tainted` set, so it is safe to compute
        exactly once per assignment rather than once per fixpoint round."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                sig = _resolve(sub)
                if sig and sig in _ALL_SKILL_SOURCES:
                    if sig == "open" and _open_is_write(sub):
                        continue  # writing, not reading — not a source
                    return sig
            # os.environ["KEY"] (Subscript) and os.environ.items()/.keys() —
            # `_resolve_call_name` only resolves Call nodes, so a bare env-var
            # reference via subscript or a non-`.get(`/`.getenv(` attribute
            # access needs its own check.
            elif isinstance(sub, ast.Subscript) and _is_os_environ(sub.value):
                return "os.environ"
            elif isinstance(sub, ast.Attribute) and _is_os_environ(sub.value):
                return "os.environ"
        return None

    # One-time collect: every assignment's target names, its literal (tainted-
    # independent) source if any, and the names it references — each subtree
    # walked exactly once, regardless of how many fixpoint rounds follow.
    assignments: list[tuple[set, str | None, set]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            target_names: set = set()
            for target in node.targets:
                target_names |= _names_in(target)
            assignments.append((target_names, _direct_source_in_expr(node.value), _names_in(node.value)))
        elif isinstance(node, ast.AnnAssign) and node.value and isinstance(node.target, ast.Name):
            assignments.append(({node.target.id}, _direct_source_in_expr(node.value), _names_in(node.value)))

    # Phase 1: propagate taint to fixpoint. `tainted` is monotonic — a name is
    # set AT MOST ONCE and never overwritten — which is what actually
    # guarantees termination. An earlier version overwrote on every
    # difference; when two separate assignments give the same target
    # different fixed sources (e.g. an if/else: `x = os.environ.get(...)` in
    # one branch, `x = input(...)` in the other), each round's pass would
    # flip `x` back and forth between the two forever (found by timing out
    # on 17 of 3,229 real corpus files — `.keys()` was called 24M+ times on
    # one 697-line file). Once a name is known tainted, which upstream source
    # produced it first is not worth re-litigating every round; each round is
    # now O(#assignments) and can add at most one new tainted name, so the
    # whole loop is bounded by `len(assignments)` rounds, guaranteed.
    changed = True
    while changed:
        changed = False
        for target_names, direct_src, value_names in assignments:
            src = direct_src
            if src is None:
                hit = value_names & tainted.keys()
                if hit:
                    src = tainted[min(hit)]
            if src:
                for name in target_names:
                    if name not in tainted:
                        tainted[name] = src
                        changed = True

    # Phase 2: check every call site's arguments for a source reaching a sink.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        sig = _resolve(node)
        if not sig or sig not in _ALL_SKILL_SINKS:
            continue
        st = _sink_type_for(sig)
        if not st:
            continue
        if sig == "open" and not _open_is_write(node):
            continue  # reading, not writing — not this sink class

        lineno = getattr(node, "lineno", 1)
        # `env=` on an exec sink (subprocess.*, Popen, ...) passes the CHILD
        # PROCESS's environment — copying/filtering `os.environ` into it is
        # the standard, benign way to inherit or scrub env vars for a
        # subprocess. That is a categorically different thing from tainted
        # data flowing into the COMMAND itself. Corpus-confirmed FP: two of
        # Anthropic's own official reference skills (`skill-creator`,
        # ground-truth-benign) do exactly `env = {k: v for k, v in
        # os.environ.items() if k != "X"}; subprocess.run(cmd, env=env)`.
        skip_kw = {"env"} if st == "exec" else set()
        all_args = list(node.args) + [kw.value for kw in node.keywords if kw.arg not in skip_kw]
        for arg in all_args:
            direct_src = None
            for sub in ast.walk(arg):
                if isinstance(sub, ast.Call):
                    s2 = _resolve(sub)
                    if s2 and s2 in _ALL_SKILL_SOURCES:
                        direct_src = s2
                        break
            if direct_src:
                flows.append(SourceSinkFlow(
                    source_call=direct_src, sink_call=sig, sink_type=st,
                    var_name="", lineno=lineno,
                ))
                continue
            names = _names_in(arg) & set(tainted)
            if names:
                name = sorted(names)[0]
                flows.append(SourceSinkFlow(
                    source_call=tainted[name], sink_call=sig, sink_type=st,
                    var_name=name, lineno=lineno,
                ))

    seen: set[tuple] = set()
    unique = []
    for f in flows:
        key = (f.source_call, f.sink_call)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
