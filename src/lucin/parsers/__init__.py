"""Agent definition parsers for different frameworks."""

from pathlib import Path

from lucin.models import Agent
from lucin.parsers.langchain_parser import parse_langchain
from lucin.parsers.mcp_parser import parse_mcp_config
from lucin.parsers.crewai_parser import parse_crewai
from lucin.parsers.autogen_parser import parse_autogen
from lucin.parsers.swarm_parser import parse_swarm
from lucin.parsers.pydantic_ai_parser import parse_pydantic_ai
from lucin.parsers.google_adk_parser import parse_google_adk
from lucin.parsers.llamaindex_parser import parse_llamaindex
from lucin.parsers.generic_parser import parse_generic


_PARSERS_BY_FRAMEWORK = {
    "langchain": [parse_langchain],
    "mcp": [parse_mcp_config],
    "crewai": [parse_crewai],
    "autogen": [parse_autogen],
    "swarm": [parse_swarm],
    "generic": [parse_generic],
}

# Order matters — most specific first, generic last (as fallback).
_AUTO_PARSERS = [
    parse_crewai, parse_autogen, parse_langchain, parse_swarm,
    parse_pydantic_ai, parse_google_adk, parse_llamaindex,
    parse_mcp_config, parse_generic,
]


def detect_and_parse(target: Path, framework: str = "auto",
                     diagnostics: list[str] | None = None) -> list[Agent]:
    """Detect framework and parse agent definitions.

    Parser order matters — most specific first, generic last (as fallback).
    The generic parser skips files already matched by specific parsers.

    Deduplication: when multiple parsers find the same agent in the same file,
    we keep the one from the more specific parser (which has better tool extraction).

    CRASH-ISOLATION (E1): each parser is a "parse unit" wrapped in try/except.
    A single malformed file that makes one parser raise (e.g. a `.mcp.json` with
    a non-dict `headers` block) must NOT abort the entire scan — the remaining
    parsers still run so the rest of the repo is scanned. Errors are collected in
    `diagnostics` (if provided) rather than propagating.
    """
    agents: list[Agent] = []

    parsers = _AUTO_PARSERS if framework == "auto" else _PARSERS_BY_FRAMEWORK.get(framework, [])
    for parser in parsers:
        try:
            agents.extend(parser(target))
        except Exception as exc:  # noqa: BLE001 — crash-isolation is deliberate
            if diagnostics is not None:
                name = getattr(parser, "__name__", repr(parser))
                diagnostics.append(f"parser {name} raised {type(exc).__name__}: {exc}")

    if framework == "auto":
        # Deduplicate: same file + same name = keep the one with more tools
        agents = _deduplicate_agents(agents)

    return agents


def _deduplicate_agents(agents: list[Agent]) -> list[Agent]:
    """Remove duplicate agents found by multiple parsers for the same file.

    Strategy: group by (source_file, agent_name). For duplicates, keep the
    agent with the most tools (more specific parser = better extraction).
    If tied, prefer non-generic framework.
    """
    seen: dict[tuple[str, str], Agent] = {}

    for agent in agents:
        key = (agent.source_file or "", agent.name)

        if key not in seen:
            seen[key] = agent
        else:
            existing = seen[key]
            # Keep the one with more tools (better extraction)
            if len(agent.tools) > len(existing.tools):
                seen[key] = agent
            elif len(agent.tools) == len(existing.tools):
                # Prefer specific framework over generic
                if existing.framework == "generic" and agent.framework != "generic":
                    seen[key] = agent

    return list(seen.values())
