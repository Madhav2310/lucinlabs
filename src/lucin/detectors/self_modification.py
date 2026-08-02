"""AG-023: Agent Self-Modification Capability Detection.

Detects when an agent has the ability to modify its own:
- Configuration (system prompt, temperature, model)
- Tools (add/remove tools, modify tool descriptions)
- Permissions (escalate its own access)
- Memory (write to its own persistent state)
- Code (modify its own source files)

This is the "god mode" vulnerability — if an agent can modify itself,
a prompt injection can make it grant itself arbitrary capabilities.

Real-world basis:
- Agents of Chaos (arXiv:2602.20021): Agents modified their own behavior
  by writing to their persistent state, then acting on the modified state
  in subsequent interactions.
- OWASP Agentic #3 (Memory Poisoning): Self-modification of memory IS
  self-modification of behavior.
- Any agent with file write access to its own config/source directory
  can effectively rewrite its own instructions.

The fundamental principle: an agent should never be able to
escalate its own capabilities. Permissions should be EXTERNALLY imposed,
not self-governed.
"""

import ast
import re
from pathlib import Path

from lucin.models import Agent, Finding, Severity, Tool, ToolCapability
from lucin.owasp import owasp_ref


# Patterns in code that indicate self-modification capability
SELF_MODIFICATION_PATTERNS = [
    # Modifying own system prompt
    (r"system_prompt\s*=", "system prompt modification"),
    (r"system_message\s*=", "system message modification"),
    (r"instructions\s*=", "instructions modification"),
    # Adding/removing tools at runtime
    (r"\.add_tool\(", "runtime tool addition"),
    (r"\.remove_tool\(", "runtime tool removal"),
    (r"tools\s*\.\s*append\(", "dynamic tool list modification"),
    (r"tools\s*\.\s*extend\(", "dynamic tool list extension"),
    (r"register_.*tool", "dynamic tool registration"),
    # Modifying own config
    (r"agent\.config", "agent config access"),
    (r"self\.config", "self-config modification"),
    (r"update_config\(", "config update"),
    # Model/temperature changes
    (r"model\s*=\s*", "model override"),
    (r"temperature\s*=\s*[^0]", "temperature modification"),
]


def detect_self_modification(agent: Agent) -> list[Finding]:
    """Detect if an agent can modify its own configuration or capabilities."""
    findings = []

    # Check 1: Does the agent have file write access to its own source directory?
    if agent.source_file:
        findings.extend(_check_source_write_access(agent))

    # Check 2: Does the agent have tools that modify agent state?
    findings.extend(_check_state_modification_tools(agent))

    # Check 3: Check source code for self-modification patterns
    if agent.source_file:
        findings.extend(_check_code_patterns(agent))

    return findings


# Signals (in a tool NAME/description) that a writer targets the agent's OWN
# config/source/behavior — not arbitrary user files.
_SELF_WRITE_NAME_SIGNALS = (
    "config", "prompt", "system_prompt", "settings", "source", "self",
    "agent_file", "instructions", "persona", "manifest", "__file__",
)


def _writes_to_own_source(agent: Agent) -> bool:
    """Best-effort evidence that the agent's code writes to its OWN source/config.

    E8 FP FIX: the old check flagged AG-023 for *every* tool that merely had
    WRITE_DATA + FILE_SYSTEM — i.e. every generic file-writer became "writes own
    source", which is not self-modification (that risk is AG-002/AG-006). We now
    require a real self-referential-write signal: a write sink in the agent's own
    source whose path argument references `__file__` / `__module__` / the module
    path (`Path(__file__)`, `os.path.dirname(__file__)`, `sys.argv[0]`).
    """
    if not agent.source_file:
        return False
    path = Path(agent.source_file)
    if not path.exists():
        return False
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, SyntaxError):
        return False

    _WRITE_SINKS = {"open", "write_text", "write_bytes", "writelines",
                    "replace", "copy", "copyfile", "copy2", "dump", "write"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = node.func.attr if isinstance(node.func, ast.Attribute) else (
            node.func.id if isinstance(node.func, ast.Name) else "")
        if fname not in _WRITE_SINKS:
            continue
        # Any argument (or receiver) referencing __file__ / argv[0] → self-write.
        refs = {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
        names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
        if "__file__" in names or "__file__" in refs or "argv" in refs:
            return True
    return False


def _check_source_write_access(agent: Agent) -> list[Finding]:
    """Check if the agent can write to its own source/config directory.

    Requires BOTH a write-capable filesystem tool AND real evidence that the
    agent's code writes to its own source/config (E8) — a bare file-writer is
    not self-modification.
    """
    findings = []

    source_dir = str(Path(agent.source_file).parent)

    # Gate on real self-referential-write evidence OR a self/config-write tool
    # name. Without either signal this is just a generic file writer (AG-002/006).
    self_write_evidence = _writes_to_own_source(agent)

    for tool in agent.tools:
        # Tool has write capability + file system access
        has_write = ToolCapability.WRITE_DATA in tool.capabilities
        has_fs = ToolCapability.FILE_SYSTEM in tool.capabilities
        name_signal = any(s in (tool.name + " " + tool.description).lower()
                          for s in _SELF_WRITE_NAME_SIGNALS)

        if has_write and has_fs and (self_write_evidence or name_signal):
            findings.append(Finding(
                id="AG-023",
                title="Self-Modification: File Write Access to Own Source",
                severity=Severity.HIGH,
                description=(
                    f"Agent '{agent.name}' has tool '{tool.name}' with file write "
                    f"capability. If this tool can write to the agent's own source "
                    f"directory ({source_dir}), the agent can modify its own code, "
                    f"configuration, or tool definitions.\n\n"
                    f"A prompt injection could make the agent rewrite its system prompt, "
                    f"add malicious tools, or remove safety guardrails."
                ),
                agent_name=agent.name,
                tool_name=tool.name,
                attack_scenario=(
                    "1. Attacker sends prompt injection to the agent\n"
                    "2. Agent uses file_write to modify its own config/source\n"
                    "3. Modified config removes safety restrictions\n"
                    "4. All subsequent interactions operate without guardrails\n"
                    "5. The modification persists across sessions"
                ),
                blast_radius=(
                    "Complete agent compromise. Once self-modified, the agent "
                    "operates without its original safety constraints indefinitely."
                ),
                owasp_ref=owasp_ref("AG-023"),
                fix_suggestion=(
                    "1. Restrict file write tools to a specific output directory:\n"
                    "   → Never allow writes to the agent's own source/config path\n"
                    "   → Use a sandbox directory: /tmp/agent-output/ (not ./)\n"
                    "2. Make agent configuration IMMUTABLE at runtime:\n"
                    "   → Load config at startup, don't allow runtime modification\n"
                    "   → Use read-only filesystem mounts for agent source\n"
                    "3. Version control + integrity checks:\n"
                    "   → Hash agent config at startup, verify hasn't changed"
                ),
                source_file=agent.source_file,
            ))
            break  # One finding per agent for this category

    return findings


def _check_state_modification_tools(agent: Agent) -> list[Finding]:
    """Check for tools that explicitly modify agent state."""
    findings = []

    # Look for tools whose names suggest self-modification
    modification_tool_patterns = [
        "update_config", "modify_settings", "change_model",
        "add_tool", "remove_tool", "update_prompt",
        "set_temperature", "modify_agent", "reconfigure",
        "self_update", "change_instructions",
    ]

    for tool in agent.tools:
        tool_lower = tool.name.lower()
        for pattern in modification_tool_patterns:
            if pattern in tool_lower:
                findings.append(Finding(
                    id="AG-023",
                    title=f"Self-Modification: Tool '{tool.name}' Modifies Agent State",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Agent '{agent.name}' has tool '{tool.name}' which appears "
                        f"to modify the agent's own configuration or capabilities.\n\n"
                        f"An agent that can modify itself can escalate privileges, "
                        f"remove guardrails, and persist malicious modifications."
                    ),
                    agent_name=agent.name,
                    tool_name=tool.name,
                    attack_scenario=(
                        "A prompt injection could instruct the agent to use this tool "
                        "to remove its own safety restrictions, add new capabilities, "
                        "or change its behavior permanently."
                    ),
                    blast_radius="Complete, persistent agent compromise.",
                    owasp_ref=owasp_ref("AG-023"),
                    fix_suggestion=(
                        "Remove self-modification tools entirely.\n"
                        "Agent configuration should be managed externally "
                        "(by humans or a separate management system), never by the agent itself."
                    ),
                    source_file=tool.source_file,
                    source_line=tool.source_line,
                ))
                break  # One per tool

    return findings


def _check_code_patterns(agent: Agent) -> list[Finding]:
    """Check source code for patterns indicating self-modification logic."""
    findings = []

    if not agent.source_file:
        return findings

    path = Path(agent.source_file)
    if not path.exists():
        return findings

    try:
        content = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, PermissionError):
        return findings

    # Only flag if the file actually defines this agent
    if agent.framework == "mcp":
        return findings  # MCP configs don't have code patterns

    matched_patterns = []
    for pattern, description in SELF_MODIFICATION_PATTERNS:
        if re.search(pattern, content):
            matched_patterns.append(description)

    # Only report if multiple patterns match (one is often innocent)
    if len(matched_patterns) >= 2:
        findings.append(Finding(
            id="AG-023",
            title="Self-Modification: Dynamic Agent Configuration",
            severity=Severity.MEDIUM,
            description=(
                f"Agent '{agent.name}' source code contains patterns suggesting "
                f"dynamic self-configuration: {', '.join(matched_patterns[:4])}.\n\n"
                f"While some of these may be legitimate initialization, the combination "
                f"suggests the agent can modify its own behavior at runtime."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "If configuration is modifiable at runtime (not just at initialization), "
                "a prompt injection could alter the agent's behavior for all future interactions."
            ),
            blast_radius="Potentially persistent behavioral modification.",
            owasp_ref=owasp_ref("AG-023"),
            fix_suggestion=(
                "1. Set configuration at initialization only (not modifiable after startup)\n"
                "2. Use immutable data structures for agent config (frozen dataclasses)\n"
                "3. Validate any runtime config changes against an allowlist"
            ),
            source_file=agent.source_file,
        ))

    return findings
