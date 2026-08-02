"""MCP Config Auto-Discovery — find agent configurations across IDEs.

Scans known paths where Cursor, Windsurf, Claude Desktop, VS Code,
and other tools store their MCP server configurations.

This gives Snyk Agent-Scan parity: they discover configs across 13+ platforms.
We scan the same locations and report what we find.

Usage:
    from lucin.discovery import discover_mcp_configs
    configs = discover_mcp_configs()
    for path in configs:
        result = scan_target(path)
"""

import os
import re
import platform
from pathlib import Path


# Known MCP config locations by platform
# Source: Snyk Agent-Scan well_known_clients.py + community documentation
_DISCOVERY_PATHS = {
    "darwin": {  # macOS
        "Claude Desktop": [
            "~/Library/Application Support/Claude/claude_desktop_config.json",
        ],
        "Cursor": [
            "~/.cursor/mcp.json",
            "~/Library/Application Support/Cursor/User/globalStorage/mcp.json",
        ],
        "Windsurf": [
            "~/.windsurf/mcp.json",
            "~/Library/Application Support/Windsurf/User/globalStorage/mcp.json",
        ],
        "VS Code": [
            "~/Library/Application Support/Code/User/globalStorage/mcp.json",
            "~/.vscode/mcp.json",
        ],
        "VS Code Insiders": [
            "~/Library/Application Support/Code - Insiders/User/globalStorage/mcp.json",
        ],
        "Zed": [
            "~/.config/zed/mcp.json",
        ],
        "Continue": [
            "~/.continue/config.json",
        ],
    },
    "linux": {
        "Claude Desktop": [
            "~/.config/Claude/claude_desktop_config.json",
        ],
        "Cursor": [
            "~/.cursor/mcp.json",
            "~/.config/Cursor/User/globalStorage/mcp.json",
        ],
        "Windsurf": [
            "~/.windsurf/mcp.json",
            "~/.config/Windsurf/User/globalStorage/mcp.json",
        ],
        "VS Code": [
            "~/.config/Code/User/globalStorage/mcp.json",
            "~/.vscode/mcp.json",
        ],
        "Continue": [
            "~/.continue/config.json",
        ],
    },
    "win32": {  # Windows
        "Claude Desktop": [
            "~/AppData/Roaming/Claude/claude_desktop_config.json",
        ],
        "Cursor": [
            "~/.cursor/mcp.json",
            "~/AppData/Roaming/Cursor/User/globalStorage/mcp.json",
        ],
        "Windsurf": [
            "~/.windsurf/mcp.json",
            "~/AppData/Roaming/Windsurf/User/globalStorage/mcp.json",
        ],
        "VS Code": [
            "~/AppData/Roaming/Code/User/globalStorage/mcp.json",
        ],
    },
}

# Paths that are the SAME on every platform (home-relative), plus glob patterns.
# Added 2026-07-30 after measuring the gap: on a machine with ~/.claude.json (46 KB),
# ~/.claude/settings.json and two installed skills, `lucin discover` found NOTHING —
# the per-platform table covered IDE MCP files but not the coding agent that is
# currently the most common way to run tools on a developer machine.
_COMMON_PATHS = {
    "Claude Code": [
        "~/.claude.json",                    # MCP servers + project history
        "~/.claude/settings.json",
        "~/.claude/settings.local.json",
    ],
    "Gemini CLI": ["~/.gemini/settings.json"],
    "Continue": ["~/.continue/config.json"],
    "Zed": ["~/.config/zed/settings.json"],
    "Amazon Q": ["~/.aws/amazonq/mcp.json"],
    "Cline": [
        "~/Library/Application Support/Code/User/globalStorage/"
        "saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
    ],
}

# Glob patterns — skills are directories of instructions the model executes, so a
# poisoned SKILL.md is as dangerous as a poisoned tool description.
_COMMON_GLOBS = {
    "Claude Code skills": ["~/.claude/skills/*/SKILL.md"],
    "Cursor rules": ["~/.cursor/rules/*.mdc"],
}

# Project-level config files (relative to cwd or project root)
_PROJECT_CONFIGS = [
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
    "mcp.json",
    "mcp_config.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    "claude_desktop_config.json",
]


def discover_mcp_configs(include_project: bool = True) -> list[dict]:
    """Discover all MCP configurations on the system.

    Returns a list of dicts:
    [
        {"path": Path(...), "platform": "Claude Desktop", "scope": "user"},
        {"path": Path(...), "platform": "project", "scope": "project"},
    ]
    """
    found = []
    system = platform.system().lower()

    # Map platform names
    if system == "darwin":
        platform_key = "darwin"
    elif system == "linux":
        platform_key = "linux"
    elif system == "windows":
        platform_key = "win32"
    else:
        platform_key = "linux"  # Default fallback

    # Check user-level IDE configs
    platform_paths = _DISCOVERY_PATHS.get(platform_key, {})
    for ide_name, paths in platform_paths.items():
        for path_str in paths:
            expanded = Path(os.path.expanduser(path_str))
            if expanded.exists() and expanded.is_file():
                found.append({
                    "path": expanded,
                    "platform": ide_name,
                    "scope": "user",
                })

    # Cross-platform paths + globs (Claude Code, skills, Gemini CLI, Zed, ...).
    for name, paths in _COMMON_PATHS.items():
        for path_str in paths:
            expanded = Path(os.path.expanduser(path_str))
            if expanded.is_file():
                found.append({"path": expanded, "platform": name, "scope": "user"})
    for name, patterns in _COMMON_GLOBS.items():
        for pattern in patterns:
            # Split "~/.claude/skills/*/SKILL.md" into a concrete root and the
            # glob remainder, then let pathlib do the matching. (The first version
            # of this hand-rolled the split and silently matched nothing.)
            expanded = os.path.expanduser(pattern)
            parts = Path(expanded).parts
            star = next((i for i, p in enumerate(parts) if "*" in p), None)
            if star is None:
                continue
            root, rel = Path(*parts[:star]), str(Path(*parts[star:]))
            try:
                matches = sorted(root.glob(rel))
            except OSError:
                matches = []
            for m in matches:
                if m.is_file():
                    found.append({"path": m, "platform": name, "scope": "user"})

    # De-duplicate: several tables legitimately list the same file.
    seen: set[Path] = set()
    unique = []
    for entry in found:
        try:
            key = entry["path"].resolve()
        except OSError:
            key = entry["path"]
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    found = unique

    # Check project-level configs
    if include_project:
        cwd = Path.cwd()
        for config_name in _PROJECT_CONFIGS:
            config_path = cwd / config_name
            if config_path.exists() and config_path.is_file():
                found.append({
                    "path": config_path,
                    "platform": "project",
                    "scope": "project",
                })

    return found


# ---------------------------------------------------------------------------
# Secret redaction. Discovery reads the user's real machine, and MCP configs
# routinely carry API keys in `env` blocks. Nothing here is ever uploaded, but it can
# still be PRINTED — into a terminal, a CI log, a pasted bug report. A tool that
# leaks the credentials it found while looking for leaked credentials is worse than
# no tool, so any value that looks like a secret is masked before display.
# ---------------------------------------------------------------------------

_SECRET_KEY = re.compile(
    r"(key|token|secret|password|passwd|credential|auth|bearer|api[-_ ]?key|"
    r"access[-_ ]?key|private|session|cookie|signature|dsn)", re.I)
# Real provider prefixes — kept narrow so ordinary config strings are not masked.
_SECRET_VALUE = re.compile(
    r"^(sk-|pk-|ghp_|gho_|github_pat_|xox[baprs]-|AKIA|ASIA|AIza|ya29\.|hf_|"
    r"glpat-|dop_v1_|shpat_|eyJ[A-Za-z0-9_-]{10,})")


def looks_secret(key: str, value: object) -> bool:
    """True if this key/value pair should never be displayed verbatim.

    The value is checked, not just the key. A first version keyed off the name alone
    plus a "long opaque string" heuristic, and on this machine's real configs it
    declared `command`, `cwd`, `PYTHONPATH` and `budgetTokens` to be credentials —
    because a long filesystem path matches a token alphabet, and "token" appears in
    the name of an integer setting. That is the same over-eager-matching mistake this
    project keeps fixing in its own detectors, so: paths are not secrets, numbers are
    not secrets, and a suggestive NAME is only enough when the value is a plausible
    secret string.
    """
    if not isinstance(value, str):
        return False                       # ints/bools/None are not credentials
    v = value.strip()
    if not v:
        return False
    if _SECRET_VALUE.match(v):
        return True                        # a real provider prefix is decisive
    # Filesystem paths, URLs and command lines are not credentials, however long.
    looks_pathlike = (v.startswith(("/", "~", "./", "../", "$")) or "/" in v
                      or v.startswith(("http://", "https://")) or " " in v)
    if looks_pathlike:
        return False
    if _SECRET_KEY.search(key or ""):
        # A credential-ish name plus an opaque-looking value: mask it.
        return len(v) >= 12 and not v.isdigit()
    # No name signal: require a genuinely token-shaped value.
    return len(v) >= 32 and bool(re.fullmatch(r"[A-Za-z0-9_\-+=]+", v))


def redact(key: str, value: object) -> str:
    """Mask a secret for display, keeping a 4-char tail so the owner can still tell
    WHICH credential it is without the string being reusable."""
    if not looks_secret(key, value):
        return str(value)
    s = str(value)
    return "****" if len(s) <= 8 else f"{'*' * 8}{s[-4:]} (redacted, {len(s)} chars)"


def credential_keys(path: Path) -> list[str]:
    """NAMES of credential-looking keys in a config — never the values.

    Lets the CLI say "3 credentials present" without ever holding a secret.
    """
    if path.suffix != ".json":
        return []
    try:
        import json
        data = json.loads(path.read_text(errors="replace"))
    except Exception:  # noqa: BLE001 — a malformed config is normal, not fatal
        return []
    names: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "env" and isinstance(v, dict):
                    names.extend(ek for ek, ev in v.items() if looks_secret(ek, ev))
                    continue
                if looks_secret(k, v) and not isinstance(v, (dict, list)):
                    names.append(k)
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return sorted(set(names))


def discover_and_report() -> str:
    """Discover configs and return a formatted report."""
    configs = discover_mcp_configs()

    if not configs:
        return "No MCP configurations found on this system."

    lines = [f"Found {len(configs)} MCP configuration(s):", ""]
    for cfg in configs:
        lines.append(f"  [{cfg['scope'].upper()}] {cfg['platform']}: {cfg['path']}")

    return "\n".join(lines)
