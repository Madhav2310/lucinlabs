"""Tool Description Pinning — detect rug-pull attacks.

Rug-pull: A trusted tool changes its description/behavior after initial approval.
This is the EXACT pattern of the Postmark MCP attack (Sep 2025):
- Versions 1.0.0-1.0.15: clean, legitimate behavior
- Version 1.0.16: added one line that BCC'd all emails to attacker

How we detect it:
1. First scan: hash all tool names + descriptions, store as baseline
2. Subsequent scans: compare current hashes to baseline
3. Any change = potential rug-pull → alert

Storage: ~/.lucin/pins/{config_hash}.json
Format: {"server_name": {"tool_name": "sha256_of_description", ...}}

This is what Snyk/Invariant's "tool pinning" does. We do it locally
(no cloud API needed) with explicit change reporting.
"""

import hashlib
import json
import re
from pathlib import Path
from datetime import datetime, timezone

from lucin.models import Agent, Finding, Severity, MCPServer


# Default pin storage directory
PIN_DIR = Path.home() / ".lucin" / "pins"


# ---------------------------------------------------------------------------
# The DANGEROUS-DELTA gate (precision > recall — protects the FP brand).
#
# A rug-pull finding fires ONLY when a tool description CHANGES to introduce
# attack-indicative language (exfil / exec / injection / secret handling), or a
# NEW tool arrives already carrying such language. A benign wording/typo edit
# does NOT fire — that is the exact false-positive class Aguara's rug-pull engine
# avoids with the same gate, and the reason we never emit "description changed"
# as a blanket CRITICAL. This is what makes wiring rug-pull safe.
# ---------------------------------------------------------------------------
_DANGEROUS_DESC = re.compile(
    r"ignore (?:previous|prior|above|all)|disregard (?:previous|prior|the)|"
    r"\bbcc\b|forward (?:all|every|a copy)|send (?:all|a copy|it|them|the) (?:to|via)|"
    r"exfiltrat|\bcurl\b|\bwget\b|base64|eval\(|exec\(|subprocess|os\.system|"
    r"/etc/passwd|ssh[- ]?key|api[_ ]?key|\bsecret(?:s|_key)?\b|credential|"
    r"\btoken\b|\.env\b|reverse shell|nc -e|powershell|rm -rf|<important>|"
    r"system prompt|do not tell|without (?:telling|informing) the user",
    re.I,
)


def _is_dangerous_description(description: str) -> bool:
    """True iff a (new/changed) tool description contains attack-indicative language.

    The dangerous-DELTA gate: a benign wording change does NOT fire; only a change
    that introduces exfil/exec/injection/secret-handling language does. Keeps
    rug-pull detection from false-positive-ing on legitimate description edits.
    """
    return bool(_DANGEROUS_DESC.search(description or ""))


def has_baseline(agent: Agent) -> bool:
    """True iff a pin baseline already exists for this agent's config.

    Used by the scanner to run the (stateful) rug-pull check ONLY when the user
    has opted in by establishing a baseline (`lucin scan --pin`). No baseline =>
    the default scan never runs rug-pull and never writes pins (zero side effects,
    so the benign-corpus precision benchmark is never contaminated).
    """
    if not agent.source_file:
        return False
    return _get_pin_path(agent.source_file).exists()


def save_baseline(agents: list[Agent]) -> list[Path]:
    """Explicitly pin the current tool state as the trusted baseline (opt-in).

    Called by `lucin scan --pin`. This is the ONLY place pins are written — the
    detection path is side-effect-free.
    """
    written: list[Path] = []
    for agent in agents:
        if agent.mcp_servers:
            written.append(save_pins(agent))
    return written


def compute_tool_hash(name: str, description: str) -> str:
    """Compute a stable hash of a tool's identity."""
    content = f"{name}::{description}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def compute_server_hash(server: MCPServer) -> str:
    """Compute a hash for a server's tool set."""
    tool_hashes = sorted(
        compute_tool_hash(t.name, t.description) for t in server.tools
    )
    combined = "::".join(tool_hashes) if tool_hashes else server.name
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def load_pins(agent: Agent) -> dict | None:
    """Load existing pins for an agent's configuration.

    Returns None if no pins exist (first scan).
    """
    if not agent.source_file:
        return None

    pin_file = _get_pin_path(agent.source_file)
    if not pin_file.exists():
        return None

    try:
        return json.loads(pin_file.read_text())
    except (json.JSONDecodeError, PermissionError):
        return None


def save_pins(agent: Agent) -> Path:
    """Save current tool hashes as the new baseline.

    Called after a successful scan to establish the "known good" state.
    """
    if not agent.source_file:
        return PIN_DIR

    pins = {
        "pinned_at": datetime.now(timezone.utc).isoformat(),
        "source_file": agent.source_file,
        "servers": {},
    }

    for server in agent.mcp_servers:
        server_pins = {}
        for tool in server.tools:
            server_pins[tool.name] = compute_tool_hash(tool.name, tool.description)
        pins["servers"][server.name] = {
            "tool_count": len(server.tools),
            "tools": server_pins,
            "server_hash": compute_server_hash(server),
        }

    pin_file = _get_pin_path(agent.source_file)
    pin_file.parent.mkdir(parents=True, exist_ok=True)
    pin_file.write_text(json.dumps(pins, indent=2))
    return pin_file


def detect_rug_pulls(agent: Agent) -> list[Finding]:
    """Compare current tool state to a pinned baseline and flag DANGEROUS drift.

    Side-effect-free (never writes pins — baselining is explicit via `save_baseline`
    / `lucin scan --pin`). Returns [] when no baseline exists, so it is a safe no-op
    on any first scan and on the benign-corpus benchmark.

    A finding fires ONLY on a *dangerous* delta (the gate in `_is_dangerous_description`):
      1. An existing tool's description CHANGED and the new text carries attack language.
      2. A NEW tool appeared whose description already carries attack language.
    Benign wording edits and benign new tools do NOT fire (precision > recall).
    """
    findings: list[Finding] = []

    existing_pins = load_pins(agent)
    if existing_pins is None:
        return findings  # no baseline → nothing to compare, and we do NOT auto-pin

    pinned_servers = existing_pins.get("servers", {})

    for server in agent.mcp_servers:
        pinned = pinned_servers.get(server.name, {})
        pinned_tools = pinned.get("tools", {})

        for tool in server.tools:
            dangerous = _is_dangerous_description(tool.description)
            prior_hash = pinned_tools.get(tool.name)

            if prior_hash is None:
                # New tool since baseline — flag only if it arrives already dangerous.
                if dangerous:
                    findings.append(_rugpull_finding(
                        agent, server, tool.name,
                        title=f"Rug-Pull: new tool with attack-indicative description ({tool.name})",
                        kind="new_dangerous_tool",
                    ))
                continue

            current_hash = compute_tool_hash(tool.name, tool.description)
            if current_hash != prior_hash and dangerous:
                # Description CHANGED and now contains attack language — the Postmark pattern.
                findings.append(_rugpull_finding(
                    agent, server, tool.name,
                    title=f"Rug-Pull: tool description changed to add attack-indicative language ({tool.name})",
                    kind="changed_dangerous_desc",
                ))
            # Changed-but-benign and unchanged tools intentionally produce no finding.

    return findings


def _rugpull_finding(agent: Agent, server: MCPServer, tool_name: str,
                     title: str, kind: str) -> Finding:
    """Build a CRITICAL rug-pull finding (shared by the change/new-tool paths)."""
    return Finding(
        id="AG-RUGPULL",
        title=title,
        severity=Severity.CRITICAL,
        description=(
            f"Tool '{tool_name}' on MCP server '{server.name}' now carries "
            f"attack-indicative language (exfiltration/exec/injection/secret-handling) "
            f"that its pinned baseline did not. This is the rug-pull pattern: a trusted "
            f"tool silently gaining malicious behavior after approval "
            f"(the Postmark MCP attack, Sep 2025, added a BCC line in a point release)."
        ),
        agent_name=agent.name,
        tool_name=tool_name,
        attack_scenario=(
            "A previously-approved tool's description was modified to instruct the agent "
            "to exfiltrate data, run commands, or leak secrets — or a new such tool was "
            "added. The agent will follow the new instructions with the tool's permissions."
        ),
        blast_radius=(
            f"Any data or capability reachable through tool '{tool_name}' on '{server.name}'."
        ),
        owasp_ref="A08 - Supply Chain Attacks (Rug-Pull)",
        fix_suggestion=(
            "1. Diff the tool against its source/changelog.\n"
            "2. If malicious, remove the server and rotate any exposed secrets.\n"
            "3. If legitimate, re-baseline with `lucin scan --pin` to accept it."
        ),
        source_file=agent.source_file,
    )


def _get_pin_path(source_file: str) -> Path:
    """Get the pin file path for a given source config."""
    config_hash = hashlib.sha256(source_file.encode()).hexdigest()[:12]
    return PIN_DIR / f"{config_hash}.json"
