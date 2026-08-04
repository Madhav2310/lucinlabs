"""AG-FRAMEWORK-PIN: Unpinned agent framework dependencies.

Corpus-derived detector (2026-07-28). Structural observation:
  - Anthropic's computer-use uses date-versioned tools (EditTool20250728,
    BashTool20250124) — upgrading the framework silently changes tool behavior.
  - CrewAI examples use uv.lock but requirements.txt often has `crewai>=0.x`
  - Most repos have unpinned agent framework versions

Pattern: `requirements.txt` or `pyproject.toml` with:
  crewai           (no version pin)
  langchain>=0.1   (lower-bound only — allows any future version)
  openai-agents    (no pin)

Why this matters for security:
  1. Tool behavior can change silently on `pip install --upgrade`
  2. A supply-chain compromise of a framework package version affects
     all downstream agents (Anthropic's "rug-pull" lesson)
  3. Unpinned `npx -y @modelcontextprotocol/server-xxx` is caught by AG-015;
     unpinned Python framework is the same risk via pip

This is complementary to AG-015 (MCP supply chain) — same attack, different
package manager.
"""

import re
from pathlib import Path

from lucin.models import Agent, EvidenceClass, Finding, Severity
from lucin.owasp import owasp_ref

# Major agent frameworks whose version should be pinned in production
AGENT_FRAMEWORK_PACKAGES = {
    "langchain", "langchain-core", "langchain-community", "langchain-openai",
    "langgraph", "langserve",
    "crewai", "crewai-tools",
    "openai-agents", "openai",
    "anthropic",
    "pydantic-ai",
    "autogen", "autogen-agentchat", "ag2", "pyautogen",
    "smolagents",
    "llama-index", "llama-index-core", "llama_index",
    "agno", "phidata",
    "griptape",
    "mem0ai",
    "dspy",
    "haystack-ai",
    "semantic-kernel",
}

# A "pinned" requirement has an exact version (==, ===)
_PINNED_RE = re.compile(r"===?[\d.]+")
# An unpinned requirement has no version specifier, or only >= / ~= / ^ / >
_UNPINNED_RE = re.compile(r"^([a-zA-Z0-9_\-\[\]]+)\s*(?:>=|~=|\^|>|$)", re.MULTILINE)


def _parse_requirements(content: str) -> list[tuple[str, str]]:
    """Return list of (package_name, spec_string) for each non-comment line."""
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-r"):
            continue
        # Strip extras and environment markers
        line = re.sub(r"\[.*?\]", "", line)
        line = re.sub(r";.*", "", line).strip()
        m = re.match(r"^([a-zA-Z0-9_\-\.]+)(.*)", line)
        if m:
            pkg = m.group(1).lower().replace("_", "-")
            spec = m.group(2).strip()
            results.append((pkg, spec))
    return results


def _parse_pyproject(content: str) -> list[tuple[str, str]]:
    """Very simple TOML dependency extractor (no full TOML parse needed)."""
    results = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ('[project]', '[tool.poetry.dependencies]',
                        '[tool.pdm.dev-dependencies]'):
            in_deps = True
            continue
        if stripped.startswith("[") and stripped != "[":
            in_deps = False
        if in_deps:
            m = re.match(r'"?([a-zA-Z0-9_\-\.]+)"?\s*=\s*"([^"]*)"', stripped)
            if m:
                results.append((m.group(1).lower().replace("_", "-"), m.group(2)))
    return results


def _is_pinned(spec: str) -> bool:
    """Return True if the spec pins to an exact version."""
    return bool(_PINNED_RE.search(spec))


def detect_framework_pin(agent: Agent) -> list[Finding]:
    """Scan requirements.txt and pyproject.toml for unpinned agent frameworks."""
    findings = []
    if not agent.source_file:
        return findings

    search_dir = Path(agent.source_file).parent
    checked: set[Path] = set()

    for req_name in ("requirements.txt", "requirements-dev.txt",
                     "requirements-lock.txt", "pyproject.toml", "setup.cfg"):
        req_path = search_dir / req_name
        # Also check one level up (monorepo pattern)
        if not req_path.exists():
            req_path = search_dir.parent / req_name
        if not req_path.exists() or req_path in checked:
            continue
        checked.add(req_path)

        try:
            content = req_path.read_text(encoding="utf-8")
        except Exception:
            continue

        if req_path.suffix == ".toml":
            deps = _parse_pyproject(content)
        else:
            deps = _parse_requirements(content)

        unpinned = [
            (pkg, spec) for pkg, spec in deps
            if pkg in AGENT_FRAMEWORK_PACKAGES and not _is_pinned(spec)
        ]

        if not unpinned:
            continue

        pkg_list = ", ".join(f"`{p}`{(' ' + s) if s else ''}" for p, s in unpinned[:5])
        findings.append(Finding(
            id="AG-FRAMEWORK-PIN",
            title=f"Unpinned Agent Framework Dependency in {req_path.name}",
            severity=Severity.MEDIUM,
            description=(
                f"Agent framework package(s) {pkg_list} are not pinned to an exact "
                f"version in {req_path.name}.\n\n"
                f"Corpus lesson: Anthropic's computer-use uses date-versioned tools "
                f"(EditTool20250728, BashTool20250124). When the framework is upgraded, "
                f"tool behavior changes silently — the same rug-pull risk as unpinned "
                f"MCP servers (AG-015), but via pip."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "1. Developer runs `pip install --upgrade` or CI rebuilds the environment\n"
                "2. Agent framework upgrades to a new version with changed tool behavior\n"
                "3. Agent behaves differently in production than in development\n"
                "Supply-chain variant: an attacker publishes a malicious patch version of "
                "a popular agent framework, exploiting unpinned installs."
            ),
            blast_radius=(
                "Silent behavioral change on every re-install or CI rebuild. "
                "Supply-chain compromise via framework package update."
            ),
            owasp_ref=owasp_ref("AG-FRAMEWORK-PIN"),
            fix_suggestion=(
                f"Pin to exact versions in {req_path.name}:\n"
                + "".join(f"  {p}=={s.lstrip('>=~^') or 'X.Y.Z'}\n"
                          for p, s in unpinned[:3])
                + "\nOr use a lock file: `pip-compile requirements.in` → `requirements.txt`\n"
                "Or: `uv lock` / `poetry lock` generates a reproducible lock file."
            ),
            source_file=str(req_path),
            evidence_class=EvidenceClass.WITNESSED,
            witness=[f"unpinned: {', '.join(p for p, _ in unpinned[:5])} in {req_path.name}"],
        ))

    return findings
