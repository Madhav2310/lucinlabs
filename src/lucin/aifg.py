"""Agent Information-Flow Graph (AIFG) — the formal core of THE_BLUEPRINT.

The AIFG is the shared representation underlying all three product layers:
- SCAN (static): build it from source, run graph queries, emit findings+witnesses
- PROVE (dynamic): instantiate risky paths as attacks
- GUARD (runtime): enforce IFC labels at the tool boundary

Every security property is a graph query. The lethal trifecta (exfiltration
vulnerability) is labeled reachability. The minimal fix is a min vertex cut.

This module implements:
1. The IFC label lattice (integrity × confidentiality)
2. AIFG construction from an Agent's parsed tools
3. Trifecta reachability query with a proof-witness path
4. Min vertex cut (min-cut remediation) via node-splitting + BFS max-flow

Relationship to existing code:
- dataflow.py: capability-based flow graph, used by AG-002/AG-COMP detectors.
  The AIFG is the formal successor — it adds IFC labels and sound graph
  algorithms. The two coexist; detectors will migrate to AIFG queries in
  Phase 1 as they are rebuilt.
- body_inspector.py: produces ToolCapability sets that seed AIFG node labels.
- THE_BLUEPRINT.md §III: formal specification this implements.
- THE_BLUEPRINT_CODEX.md §1–2: reference algorithms (taint engine, min-cut).

stdlib only — no external deps required.
"""

from __future__ import annotations

import ast
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

from lucin.models import Agent, Tool, ToolCapability


# ---------------------------------------------------------------------------
# 1. The IFC label lattice (Blueprint §3.2)
# ---------------------------------------------------------------------------

class Integrity(IntEnum):
    """Biba integrity lattice. Higher = more trusted.
    Rule: Untrusted data may NOT raise to Trusted without an endorser.
    Default for LLM output, tool returns, web/email content = UNTRUSTED.
    Default for developer config, system prompt = TRUSTED.
    """
    UNTRUSTED = 0
    TRUSTED = 1


class Confidentiality(IntEnum):
    """Bell-LaPadula confidentiality lattice. Higher = more secret.
    Rule: Secret data may NOT flow to Public without a declassifier.
    """
    PUBLIC = 0
    INTERNAL = 1
    SECRET = 2


@dataclass(frozen=True)
class IFCLabel:
    """The composite label attached to every node/value in the AIFG."""
    integrity: Integrity = Integrity.TRUSTED
    confidentiality: Confidentiality = Confidentiality.PUBLIC

    def join(self, other: "IFCLabel") -> "IFCLabel":
        """Merge two labels (used when data from multiple sources combines).
        Integrity: take the MINIMUM (most-untrusted wins — one tainted input
                   taints the result).
        Confidentiality: take the MAXIMUM (most-secret wins).
        Monotone → fixpoint guaranteed (Knaster-Tarski). [VERIFIED]
        """
        return IFCLabel(
            integrity=Integrity(min(self.integrity, other.integrity)),
            confidentiality=Confidentiality(max(self.confidentiality, other.confidentiality)),
        )

    def is_untrusted(self) -> bool:
        return self.integrity == Integrity.UNTRUSTED

    def is_secret(self) -> bool:
        return self.confidentiality >= Confidentiality.SECRET

    def is_internal_or_above(self) -> bool:
        return self.confidentiality >= Confidentiality.INTERNAL


# Shorthand label constructors
TRUSTED_PUBLIC   = IFCLabel(Integrity.TRUSTED,   Confidentiality.PUBLIC)
TRUSTED_SECRET   = IFCLabel(Integrity.TRUSTED,   Confidentiality.SECRET)
UNTRUSTED_PUBLIC = IFCLabel(Integrity.UNTRUSTED, Confidentiality.PUBLIC)
UNTRUSTED_SECRET = IFCLabel(Integrity.UNTRUSTED, Confidentiality.SECRET)


# --- Canonical label vocabulary (the ONE shared string<->enum mapping) -------
# Both the static builder (build_aifg) and the runtime reconstruction
# (ProvenanceGraph.to_aifg / AgentGraph.to_aifg) MUST use this single mapping,
# so "shared label vocabulary" is a code fact, not a coincidence. Runtime code
# (guard/provenance.py, guard/ifc_runtime.py) stores integrity/confidentiality
# as lowercase strings; this is the sole canonical decoder.

_INTEGRITY_FROM_STR = {
    "untrusted": Integrity.UNTRUSTED,
    "trusted":   Integrity.TRUSTED,
}
_CONFIDENTIALITY_FROM_STR = {
    "public":   Confidentiality.PUBLIC,
    "internal": Confidentiality.INTERNAL,
    "secret":   Confidentiality.SECRET,
}


def ifc_label_from_strings(integrity: str, confidentiality: str) -> IFCLabel:
    """Decode the runtime string vocabulary into the canonical IFCLabel.

    Conservative defaults: unknown integrity -> UNTRUSTED (sound for
    trifecta), unknown confidentiality -> PUBLIC (does not manufacture a
    false secret-flow). This is the single point where runtime telemetry
    labels become the SAME enum type used by the static AIFG.
    """
    integ = _INTEGRITY_FROM_STR.get((integrity or "").strip().lower(),
                                    Integrity.UNTRUSTED)
    conf = _CONFIDENTIALITY_FROM_STR.get((confidentiality or "").strip().lower(),
                                         Confidentiality.PUBLIC)
    return IFCLabel(integrity=integ, confidentiality=conf)


# ---------------------------------------------------------------------------
# 2. AIFG node and edge types
# ---------------------------------------------------------------------------

class EdgeKind(str):
    """Edge tag: 'data' (value flows) or 'control' (influences whether/how a
    node fires). Both are needed to express the trifecta:
      - Tainted control edge: attacker can trigger the sink
      - Tainted data edge:    attacker's secret reaches the sink's payload
    """
    DATA    = "data"
    CONTROL = "control"


@dataclass
class AIFGNode:
    """One node in the AIFG.

    node_id: unique identifier (tool name or synthetic)
    label:   IFC label for data this node produces
    is_source: produces/reads data (file, DB, RAG, web, tool return)
    is_sink:   consumes data externally (network egress, exec, write)
    is_llm:    the LLM node — joins all context labels, propagates to output
    is_egress: crosses the trust boundary outward (network, email, public write)
    tool:      the underlying Tool object, if any
    """
    node_id: str
    label: IFCLabel = field(default_factory=lambda: TRUSTED_PUBLIC)
    is_source: bool = False
    is_sink: bool = False
    is_llm: bool = False
    is_egress: bool = False
    # True iff this node INGESTS content from OUTSIDE the trust boundary
    # (web fetch, RAG/retrieval, inbound message, user-supplied file). This — NOT
    # the __llm__ node — is the untrusted-control ORIGIN of the lethal trifecta.
    is_untrusted_input: bool = False
    tool: Tool | None = None


@dataclass
class AIFGEdge:
    """A directed edge in the AIFG."""
    src: str
    dst: str
    kind: str = EdgeKind.DATA   # 'data' or 'control'


# ---------------------------------------------------------------------------
# 3. The AIFG itself
# ---------------------------------------------------------------------------

@dataclass
class AIFG:
    """Agent Information-Flow Graph.

    Built once per Agent; queried by detectors and (in Phase 3) enforced
    at runtime. All security properties are expressed as graph queries here.
    """
    agent_name: str
    nodes: dict[str, AIFGNode] = field(default_factory=dict)
    edges: list[AIFGEdge] = field(default_factory=list)

    # ---- graph accessors ------------------------------------------------

    def successors(self, node_id: str, kind: str | None = None) -> list[str]:
        return [e.dst for e in self.edges
                if e.src == node_id and (kind is None or e.kind == kind)]

    def predecessors(self, node_id: str, kind: str | None = None) -> list[str]:
        return [e.src for e in self.edges
                if e.dst == node_id and (kind is None or e.kind == kind)]

    def reachable(self, start: str, kind: str | None = None) -> set[str]:
        """BFS reachability from `start` following edges of `kind` (or all)."""
        seen: set[str] = set()
        q = deque([start])
        while q:
            n = q.popleft()
            if n in seen:
                continue
            seen.add(n)
            q.extend(self.successors(n, kind))
        return seen

    # ---- serialization --------------------------------------------------

    def to_dict(self) -> dict:
        """Dump graph as a plain dict — for the 'observable: dump the graph'
        Phase 1 criterion."""
        return {
            "agent": self.agent_name,
            "nodes": [
                {
                    "id": n.node_id,
                    "label": {
                        "integrity": n.label.integrity.name,
                        "confidentiality": n.label.confidentiality.name,
                    },
                    "is_source": n.is_source,
                    "is_sink": n.is_sink,
                    "is_egress": n.is_egress,
                    "is_untrusted_input": n.is_untrusted_input,
                    "is_llm": n.is_llm,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {"src": e.src, "dst": e.dst, "kind": e.kind}
                for e in self.edges
            ],
        }


# ---------------------------------------------------------------------------
# 4. Build the AIFG from a parsed Agent
# ---------------------------------------------------------------------------

def _label_for_tool(tool: Tool, is_untrusted_input: bool) -> IFCLabel:
    """Assign the IFC label for a tool node.

    Confidentiality: tools that read data/files/DBs could return secrets/PII →
    INTERNAL; everything else PUBLIC.

    Integrity — the C2 fix (was VACUOUS): a tool is UNTRUSTED **iff it is a
    genuine untrusted-INPUT source** (it ingests attacker-influenceable content
    from outside the trust boundary — web fetch, RAG/retrieval, inbound message,
    user-supplied file). Ordinary developer-authored tools that operate on
    trusted/internal data (read a config DB, send an email, run a query) are
    TRUSTED. This is what makes AG-TRIFECTA's (T) condition MEAN something: the
    old code labelled *every* tool UNTRUSTED (both branches of a dead `if`), so
    (T) was always satisfied and the detector reduced to "has a data tool AND an
    egress tool". Untrusted-ness now requires a real external-input source.
    """
    caps = tool.capabilities

    if ToolCapability.READ_DATA in caps or ToolCapability.FILE_SYSTEM in caps:
        conf = Confidentiality.INTERNAL   # could contain secrets/PII
    else:
        conf = Confidentiality.PUBLIC

    integ = Integrity.UNTRUSTED if is_untrusted_input else Integrity.TRUSTED
    return IFCLabel(integrity=integ, confidentiality=conf)


# Egress vocabulary — shared by the static builder AND the runtime
# reconstruction so a tool is classified as an exfiltration sink the SAME way
# whether we see it in source or in telemetry.
_FETCH_ONLY_NAMES = (
    # Known search/retrieval services
    "web_search", "web_search_tool", "serperdev", "seper_dev",
    "tavily", "scrapewebsite", "websitesearch", "websitetool",
    "firecrawl", "bing_search", "google_search", "duckduckgo",
    "http_get", "url_fetch", "read_url", "exa",
    # Semantic read-only prefixes/patterns (corpus-derived 2026-07-28)
    # fetch_ prefix: fetch_results, fetch_data, fetch_openai_results
    # search suffix/content: any tool for querying a read-only source
    # retrieve: vector store / RAG retrieval tools
)
_FETCH_ONLY_PATTERNS = (
    "fetch_", "_search", "search_", "retrieve", "lookup",
    "get_content", "get_result",
)

# Leading verbs that mean "push data OUT" (egress). If a tool NAME starts with
# one of these, it is a sink regardless of any fetch-ish word later in the name.
# This is the E3 fix for the substring FN: `send_to_search_queue` contains
# `_search`, so the old `p in name` fetch-suppression wrongly classified this
# SEND tool as a read-only fetch. A leading send verb is decisive.
_EGRESS_LEADING_VERBS = (
    "send", "post", "publish", "push", "upload", "notify", "email",
    "forward", "deliver", "transmit", "emit", "dispatch", "export",
    "exfiltrate", "leak", "webhook", "sync_to", "write_to",
)


def _first_token(name: str) -> str:
    """First NON-EMPTY underscore/hyphen-delimited token of a (lowercased) name.

    Leading separators must not swallow the verb: `_get_or_fetch_email` splits to
    ['', 'get', ...], and returning '' there made the verb invisible (it fell
    through to the conservative-egress default). Skip empties.
    """
    import re as _re
    parts = [p for p in _re.split(r"[_\-]", name) if p]
    return parts[0] if parts else name


# Verb tokens that UNAMBIGUOUSLY push data outward, anywhere in the name.
# Deliberately excludes noun-ambiguous words ('email' is a noun in
# `get_or_fetch_email` — an address being READ, not an act of emailing).
_EGRESS_VERB_TOKENS = frozenset({
    "send", "post", "publish", "push", "upload", "notify", "forward",
    "deliver", "transmit", "emit", "dispatch", "export", "exfiltrate",
    "leak", "webhook", "submit", "broadcast", "tweet",
})

# Verb tokens that pull data IN. A network tool whose verb is one of these is a
# SOURCE, not an exfiltration sink — even if body inspection could not prove
# `is_fetch_only`. Without this, ANY unrecognised network tool defaulted to
# egress, which made `download_object` / `scrape_page` / `web_fetch_tool` fake
# trifecta sinks (measured on 81 real agent repos, 2026-07-30). That is the same
# error class as deciding a sink by CATEGORY instead of by what the code does.
_FETCH_VERB_TOKENS = frozenset({
    "download", "fetch", "scrape", "crawl", "retrieve", "search", "query",
    "lookup", "get", "read", "list", "load", "pull", "find", "browse",
    "view", "describe", "inspect", "poll", "peek",
})


def _matches_fetch_pattern(name: str) -> bool:
    """True if the tool NAME matches a read-only fetch pattern, using PREFIX /
    token-boundary matching instead of a raw substring `in` (E3).

    - `fetch_`/`search_` : a leading prefix (the verb IS fetch/search).
    - `_search`          : a trailing suffix (e.g. `web_search`, `code_search`).
    - `retrieve`/`lookup`/`get_content`/`get_result` : the name STARTS with the
      pattern, or the pattern appears as a whole token — never as an incidental
      substring buried inside an unrelated word.
    """
    import re as _re
    tokens = set(_re.split(r"[_\-]", name))
    for p in _FETCH_ONLY_PATTERNS:
        core = p.strip("_")
        if p.endswith("_"):          # prefix pattern: fetch_, search_
            if name.startswith(p):
                return True
        elif p.startswith("_"):      # suffix pattern: _search
            if name.endswith(p) or name == core:
                return True
        else:                        # word pattern: retrieve, lookup, get_content
            if name.startswith(core) or core in tokens:
                return True
    return False

# DNS resolver tool names. DNS is a covert egress / exfiltration channel (DNS
# tunnelling: secrets are smuggled inside the queried hostname), so a DNS tool
# is an EGRESS sink even when no network capability was inferred and even though
# its name contains "lookup" (normally a fetch-only pattern). Matched against the
# separator-normalised name so "dns_lookup" == "dnslookup" == "dns-lookup".
_DNS_EGRESS_NAMES = (
    "dnslookup", "dnsquery", "dnsresolve", "resolvedns",
    "nslookup", "dnsexfil", "dnsrequest",
)


def _normalize_tool_name(name: str) -> str:
    """Lowercase and strip separators so underscore/dash variants match the
    canonical vocabulary (e.g. 'scrape_website' -> 'scrapewebsite')."""
    return (name or "").lower().replace("_", "").replace("-", "")


# Separator-normalised fetch-name vocabulary. Matching normalised-vs-normalised
# lets underscore/dash variants match ('scrape_website' matches 'scrapewebsite')
# WITHOUT breaking the entries that already contain underscores ('web_search').
_FETCH_ONLY_NAMES_NORM = tuple(_normalize_tool_name(k) for k in _FETCH_ONLY_NAMES)


def is_egress_by_name(name: str, *,
                      has_network: bool = False,
                      has_write: bool = False,
                      is_fetch_only: bool = False) -> bool:
    """Egress classifier keyed on tool NAME + capability flags.

    The single shared decision procedure (see `_is_egress_tool` for the
    Tool-object path and `ProvenanceGraph.to_aifg` for the runtime path).

      - FETCH tools (web_search, scrape, http_get) are SOURCES — they pull
        data IN. They carry UNTRUSTED data but are not exfiltration sinks.
      - SEND tools (send_email, http_post, webhook, slack) are SINKS — they
        push data OUT. These are the true egress sinks for trifecta detection.
    """
    name = (name or "").lower()
    name_norm = _normalize_tool_name(name)
    if is_fetch_only:
        return False   # confirmed fetch-only — source, not egress
    # A leading SEND verb is decisive: this tool pushes data OUT (egress) even
    # if a fetch-ish word appears later in the name (E3 — `send_to_search_queue`).
    if _first_token(name) in _EGRESS_LEADING_VERBS:
        return True
    # DNS resolvers are covert egress channels — classify as egress regardless
    # of inferred network capability and despite the "lookup" fetch pattern.
    if any(kw in name_norm for kw in _DNS_EGRESS_NAMES):
        return True
    if has_network:
        # Match the fetch-name vocabulary on the separator-normalised name so
        # underscore variants ('scrape_website') match ('scrapewebsite').
        if any(kw in name_norm for kw in _FETCH_ONLY_NAMES_NORM):
            return False   # confirmed read-only fetch tool by name
        if _matches_fetch_pattern(name):
            return False   # name pattern (prefix/suffix/token) suggests fetch
        # VERB-INTENT resolution (before the conservative default). The vocab
        # checks above are prefix/substring-anchored, so compound names like
        # `web_fetch_tool` / `download_object` / `_get_or_fetch_email` slipped
        # through and were treated as egress sinks.
        import re as _re
        tokens = {t for t in _re.split(r"[_\-]", name) if t}
        if tokens & _EGRESS_VERB_TOKENS:
            return True    # an outward verb anywhere wins (`get_and_send_report`)
        if _first_token(name) in _FETCH_VERB_TOKENS:
            return False   # the tool's own verb pulls data IN
        if tokens & _FETCH_VERB_TOKENS:
            return False   # a fetch verb elsewhere, no egress verb → source
        return True        # unrecognized network tool — conservative: egress
    return has_write       # write-data tools can exfiltrate to shared stores


def _is_egress_tool(tool: Tool) -> bool:
    """Return True if this tool crosses the trust boundary outward.

    Thin wrapper over `is_egress_by_name` (the shared vocabulary) reading the
    capability flags off the Tool object. Behaviour is identical to the prior
    inline implementation — this only extracts the decision so the runtime
    reconstruction can reuse the exact same rule.

    This distinction eliminates the false positives on CrewAI's SerperDevTool,
    ScrapeWebsiteTool, WebsiteSearchTool etc. (all fetch tools).
    """
    caps = tool.capabilities
    return is_egress_by_name(
        tool.name,
        has_network=ToolCapability.NETWORK_ACCESS in caps,
        has_write=ToolCapability.WRITE_DATA in caps,
        is_fetch_only=getattr(tool, "is_fetch_only", False),
    )


# --- Untrusted-INPUT source vocabulary (the (T) origin of the trifecta) ------
# A tool is an UNTRUSTED-INPUT source iff it INGESTS content from OUTSIDE the
# trust boundary: the LLM then reasons over attacker-influenceable text, so an
# injected instruction inside that content can steer any downstream sink. This
# is Willison's "untrusted content" leg of the lethal trifecta. The __llm__ node
# is NOT an untrusted origin by default — a genuine source of external content
# must be present in the agent for AG-TRIFECTA to fire.
#
# Two signals, in order of robustness:
#   (1) CAPABILITY (primary): a network tool that FETCHES (GET/read, not egress)
#       pulls external content in. `is_fetch_only` (body_inspector) or a
#       network tool the egress classifier rules a fetch → untrusted input.
#   (2) NAME vocabulary (secondary): non-network ingestion — reading a
#       user-supplied file, an inbound message/comment/issue, a RAG/retrieved
#       doc. Matched on the separator-normalised name (see _normalize_tool_name).
_UNTRUSTED_INPUT_NAMES = (
    # user-supplied / uploaded content (attacker controls the bytes)
    "read_user_file", "read_user_input", "user_input", "user_provided",
    "read_upload", "read_attachment", "get_attachment", "user_uploaded",
    # inbound messages / comments / issues / tickets (attacker can send these)
    "read_email", "read_inbox", "get_message", "read_message", "receive_message",
    "read_comment", "read_issue", "read_pr", "read_ticket", "read_review",
    "read_mention", "read_notification",
    # RAG / retrieval / knowledge base (retrieved docs are untrusted content)
    "retrieve", "rag_query", "rag_search", "knowledge_base", "vector_search",
    "semantic_search", "query_docs", "search_docs",
    # knowledge_search / search_knowledge: the exact RAG-retrieval compound that
    # fell through (neither "knowledge" nor "search" is a standalone keyword, and
    # no listed compound substring-matches "knowledgesearch"). Canonical RAG shape
    # — retrieved KB docs are attacker-influenceable. (FN found on 14_rag_agent,
    # 2026-07-30; validated FP-neutral on the benign corpus before landing.)
    "knowledge_search", "search_knowledge",
    # web fetch / scrape / crawl / search (external content in)
    "fetch_web", "web_fetch", "read_url", "fetch_url", "scrape", "crawl",
    "web_search",
)
_UNTRUSTED_INPUT_NAMES_NORM = tuple(_normalize_tool_name(k)
                                    for k in _UNTRUSTED_INPUT_NAMES)


def is_untrusted_input_by_name(name: str, *, is_fetch: bool = False) -> bool:
    """Classify a tool NAME (+ a fetch flag) as an untrusted-input source.

    The single shared decision procedure (mirrors is_egress_by_name for sinks).
    """
    if is_fetch:
        return True   # network fetch/retrieval pulls external content IN
    name_norm = _normalize_tool_name(name)
    return any(kw in name_norm for kw in _UNTRUSTED_INPUT_NAMES_NORM)


def _is_untrusted_input_tool(tool: Tool) -> bool:
    """Return True iff this Tool ingests attacker-influenceable external content.

    Reads capability flags off the Tool object and defers to the shared
    name/fetch decision procedure so SCAN classifies untrusted input the same
    way everywhere.
    """
    caps = tool.capabilities
    has_network = ToolCapability.NETWORK_ACCESS in caps
    # A network tool that is NOT an egress sink is pulling data IN (a fetch).
    is_fetch = (getattr(tool, "is_fetch_only", False)
                or (has_network and not _is_egress_tool(tool)))
    return is_untrusted_input_by_name(tool.name, is_fetch=is_fetch)


def build_aifg(agent: Agent) -> AIFG:
    """Build an AIFG from a parsed Agent.

    Populates nodes from the agent's tools (labels seeded by body_inspector
    capability sets), then adds data+control edges based on which tools
    can feed which other tools (capability-compatible pairs), plus an LLM
    node that joins all sources and propagates to all sinks.

    Phase 1 note: edge construction here is CONSERVATIVE (any source can
    feed any sink via the LLM context — the LLM is a single implicit join
    node). The Phase 1 taint engine (Codex §1) will refine this to
    data-flow-precise edges from actual source analysis.
    """
    g = AIFG(agent_name=agent.name)

    # LLM node — joins everything in context, propagates to all outputs.
    # C2 FIX: the LLM node is TRUSTED by default. It is NOT the untrusted-control
    # origin — that would make the trifecta vacuous (every agent has an LLM).
    # The untrusted origin must be a genuine untrusted-INPUT source tool; only
    # then does injected content reach the LLM and steer a sink.
    llm_node = AIFGNode(
        node_id="__llm__",
        label=TRUSTED_PUBLIC,
        is_llm=True,
    )
    g.nodes[llm_node.node_id] = llm_node

    # Tool nodes
    for tool in agent.tools:
        untrusted_input = _is_untrusted_input_tool(tool)
        label = _label_for_tool(tool, untrusted_input)
        is_src = (ToolCapability.READ_DATA in tool.capabilities or
                  ToolCapability.FILE_SYSTEM in tool.capabilities)
        is_snk = (ToolCapability.EXECUTE_CODE in tool.capabilities or
                  _is_egress_tool(tool))
        node = AIFGNode(
            node_id=tool.name,
            label=label,
            is_source=is_src,
            is_sink=is_snk,
            is_egress=_is_egress_tool(tool),
            is_untrusted_input=untrusted_input,
            tool=tool,
        )
        g.nodes[tool.name] = node

    # Edge construction. Two kinds of data flow reach a sink:
    #
    #  (1) LLM-MEDIATED (the common case for LLM agents): a source's output
    #      enters the LLM context and the LLM emits it to a sink. We model this
    #      EXPLICITLY through the __llm__ join node:
    #          source --data--> __llm__ --data--> sink
    #      plus the control edge __llm__ --control--> sink (the LLM decides
    #      whether/how the sink fires).
    #
    #  (2) REAL DIRECT dataflow: when the agent's SOURCE shows a specific source
    #      tool's output actually reaching a specific sink tool WITHIN THE FILE
    #      (a source-tool function whose result is tainted into a sink-tool's
    #      dangerous operation). These are recovered from real intraprocedural /
    #      in-file taint (parsers/body_inspector, see _real_direct_edges) and
    #      added as direct source --data--> sink edges.
    #
    # WITNESS REALISM (see tests/test_aifg_coherence.py):
    # This REPLACES the old complete-bipartite over-approximation (every source ×
    # every sink) with the two mechanisms above. It is REACHABILITY-EQUIVALENT to
    # the old builder for detection — every source still reaches every sink for a
    # given agent, now via the explicit __llm__ join instead of a fabricated
    # direct edge — so recall and the 0%-FP corpus are preserved by construction
    # (verified: benchmarks/build_benign_corpus.py 0.0% FP, recall_corpus.py
    # trifecta 3/3). The GAIN is witness HONESTY: a data witness now reads
    # `secret_source -> __llm__ -> sink`, which truthfully names the LLM as the
    # flow mediator, instead of the old `secret_source -> sink` that falsely
    # implied a direct tool-to-tool call. Where real in-file taint DOES connect a
    # specific source to a specific sink, a direct edge is present and the
    # shortest-path witness uses it (genuine evidence, not a template).
    #
    # HONEST BOUNDARY (unchanged truth, now made explicit in the graph): for
    # LLM-mediated multi-tool agents, static analysis still cannot prove WHICH
    # source fed a given sink — that per-flow disambiguation is a RUNTIME property
    # (ProvenanceGraph.to_aifg records observed 1:1 lineage). The static witness
    # routes through __llm__ precisely to reflect that irreducible mediation.
    _seen_edges: set[tuple[str, str, str]] = set()

    def _add_edge(src: str, dst: str, kind: str) -> None:
        key = (src, dst, kind)
        if src != dst and key not in _seen_edges:
            _seen_edges.add(key)
            g.edges.append(AIFGEdge(src, dst, kind))

    for node in g.nodes.values():
        if node.is_llm:
            continue
        if node.is_source:
            # source → LLM (data): source output enters LLM context
            _add_edge(node.node_id, "__llm__", EdgeKind.DATA)
        if node.is_untrusted_input:
            # C2 FIX — the untrusted-control ORIGIN. Untrusted external content
            # enters the LLM context (data) AND an injected instruction inside it
            # can steer whatever the LLM does next (control). This control edge is
            # what lets query_trifecta's (T) walk back from an egress sink to a
            # REAL untrusted source (never __llm__ by itself).
            _add_edge(node.node_id, "__llm__", EdgeKind.DATA)
            _add_edge(node.node_id, "__llm__", EdgeKind.CONTROL)
        if node.is_sink:
            # LLM → sink (control): LLM decides whether/how the sink fires
            _add_edge("__llm__", node.node_id, EdgeKind.CONTROL)
            # LLM → sink (data): the LLM can forward any context data to the sink
            # (this is the honest, explicit model of the mediated data path)
            _add_edge("__llm__", node.node_id, EdgeKind.DATA)

    # (2) Real direct source→sink edges from in-file taint (best-effort, additive:
    # reachability is already complete via __llm__, so these only sharpen witness
    # paths — they can never manufacture a new finding).
    source_ids = {n.node_id for n in g.nodes.values() if n.is_source and not n.is_llm}
    sink_ids   = {n.node_id for n in g.nodes.values() if n.is_sink   and not n.is_llm}
    if source_ids and sink_ids:
        for src_id, snk_id in _real_direct_edges(agent, source_ids, sink_ids):
            g.edges.append(AIFGEdge(src_id, snk_id, EdgeKind.DATA))

    return g


def _called_names(node: ast.AST) -> set[str]:
    """Names of functions called anywhere inside `node`."""
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


def _real_direct_edges(agent: Agent,
                       source_ids: set[str],
                       sink_ids: set[str]) -> set[tuple[str, str]]:
    """Recover REAL direct source→sink data edges from in-file taint.

    A direct edge (src_tool, snk_tool) is emitted only when the agent's own
    source shows the source tool's output ACTUALLY reaching the sink tool's
    dangerous operation within the file — i.e. the sink tool's function calls
    the source tool's function and the returned value is tainted into a
    dangerous sink inside the sink function's body. This is genuine
    intraprocedural / one-hop-interprocedural taint evidence (reusing
    parsers.body_inspector), NOT the old complete-bipartite template.

    Best-effort and purely ADDITIVE: any parse/IO failure yields no edges, and
    because __llm__ mediation already connects every source to every sink, a
    returned edge can only shorten a witness path, never create a new finding.
    """
    from lucin.parsers.body_inspector import (
        intraproc_taint, DANGEROUS_EXEC_CALLS, DANGEROUS_NETWORK_CALLS,
        DANGEROUS_FILE_WRITE_CALLS, _resolve_call_name,
    )

    tool_names = {t.name for t in agent.tools}
    by_file: dict[str, list[str]] = defaultdict(list)
    for t in agent.tools:
        if t.source_file:
            by_file[t.source_file].append(t.name)

    edges: set[tuple[str, str]] = set()
    _SINK_SIGS = (DANGEROUS_EXEC_CALLS | DANGEROUS_NETWORK_CALLS
                  | DANGEROUS_FILE_WRITE_CALLS | {"eval", "exec", "compile"})

    for path, names in by_file.items():
        try:
            source = Path(path).read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (OSError, ValueError, SyntaxError):
            continue
        func_map = {n.name: n for n in ast.walk(tree)
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

        for snk in names:
            if snk not in sink_ids or snk not in func_map:
                continue
            snk_fn = func_map[snk]

            # Which source-tool functions does the sink function call, and is
            # that call's RESULT bound to a variable that reaches a dangerous
            # sink inside snk_fn? (real one-hop dataflow src -> snk sink)
            tainted: set[str] = set()          # vars holding a source tool's output
            for n in ast.walk(snk_fn):
                if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
                    callee = _resolve_call_name(n.value)
                    callee = callee.split(".")[-1] if callee else None
                    if (callee in source_ids and callee in tool_names
                            and callee != snk):
                        for tgt in n.targets:
                            for name in (x.id for x in ast.walk(tgt)
                                         if isinstance(x, ast.Name)):
                                tainted.add(name)
            if not tainted:
                continue

            # propagate through further assignments (once tainted, stays)
            changed = True
            while changed:
                changed = False
                for n in ast.walk(snk_fn):
                    if isinstance(n, ast.Assign):
                        if {x.id for x in ast.walk(n.value)
                                if isinstance(x, ast.Name)} & tainted:
                            for name in (x.id for x in ast.walk(n)
                                         if isinstance(x, ast.Name)):
                                if name not in tainted:
                                    tainted.add(name); changed = True

            # does any tainted var flow into a dangerous sink call in snk_fn?
            for n in ast.walk(snk_fn):
                if not isinstance(n, ast.Call):
                    continue
                sig = _resolve_call_name(n)
                if not sig or sig not in _SINK_SIGS:
                    continue
                argnames = {x.id for a in list(n.args) + [k.value for k in n.keywords]
                            for x in ast.walk(a) if isinstance(x, ast.Name)}
                if argnames & tainted:
                    # attribute the edge to every source tool the sink fn calls
                    for src_id in source_ids:
                        if src_id in _called_names(snk_fn) and src_id != snk:
                            edges.add((src_id, snk))
                    break

    return edges


# ---------------------------------------------------------------------------
# 5. Trifecta reachability query (Blueprint §3.3) — THE FLAGSHIP
# ---------------------------------------------------------------------------

@dataclass
class TrifectaFinding:
    """One exfiltration vulnerability: the lethal trifecta.

    Exists iff:
      (T) untrusted source u →_control  egress sink s  (attacker steers the sink)
      (S) secret     source k →_data    egress sink s  (secret data reaches payload)
      (E) s ∈ ExternalEgress                           (crosses trust boundary)
      (¬D) no declassifier/endorser mediates either path

    Every finding carries proof-witness paths for both (T) and (S) — the
    concrete chains an analyst can use to understand and fix the vuln.
    """
    egress_sink: str
    control_path: list[str]    # untrusted source → ... → sink (control edges)
    data_path: list[str]       # secret source → ... → sink (data edges)
    control_source: str
    data_source: str

    def witness_summary(self) -> str:
        ctrl = " → ".join(self.control_path)
        data = " → ".join(self.data_path)
        return (
            f"Exfiltration via '{self.egress_sink}':\n"
            f"  Control path (attacker can steer): {ctrl}\n"
            f"  Data path (secret reaches payload): {data}"
        )


def query_trifecta(g: AIFG) -> list[TrifectaFinding]:
    """Find all lethal-trifecta exfiltration vulnerabilities in the AIFG.

    Algorithm: O(S × E × (V+E)) where S = #sinks, E = #egress sinks.
    In practice instant for agent-sized graphs (tens of nodes).

    For each egress sink:
      1. BFS backwards on control edges — find reachable untrusted sources.
      2. BFS backwards on data edges — find reachable secret sources.
      3. Both conditions met → trifecta; record the shortest witness paths.
    """
    findings: list[TrifectaFinding] = []

    egress_sinks = [n for n in g.nodes.values() if n.is_egress]

    for sink in egress_sinks:
        # --- (T) control: which untrusted nodes can steer this sink? ---
        # Walk backwards along control edges from the sink.
        ctrl_reachable = _bfs_reverse(g, sink.node_id, EdgeKind.CONTROL)
        untrusted_ctrl_sources = [
            nid for nid in ctrl_reachable
            if g.nodes[nid].label.is_untrusted() and nid != sink.node_id
        ]

        # --- (S) data: which secret nodes can reach this sink? ---
        data_reachable = _bfs_reverse(g, sink.node_id, EdgeKind.DATA)
        # Bell-LaPadula: INTERNAL or SECRET must not flow to PUBLIC egress
        # without a declassifier. Both violate the confidentiality rule.
        secret_data_sources = [
            nid for nid in data_reachable
            if g.nodes[nid].label.is_internal_or_above() and nid != sink.node_id
        ]

        if not untrusted_ctrl_sources or not secret_data_sources:
            continue    # trifecta not satisfied for this sink

        # Pick one witness path per condition. For the CONTROL source prefer a
        # genuine untrusted-INPUT source (and never the __llm__ mediator) so the
        # witness names the REAL attacker-influenceable origin, not "the LLM".
        # (The runtime/multi-agent projections that carry untrusted-ness only on
        # a label — no is_untrusted_input flag — fall back gracefully.)
        def _pick_ctrl(sources: list[str]) -> str:
            ranked = sorted(
                sources,
                key=lambda nid: (
                    0 if g.nodes[nid].is_untrusted_input else
                    1 if not g.nodes[nid].is_llm else 2,
                    nid,
                ),
            )
            return ranked[0]

        ctrl_src = _pick_ctrl(untrusted_ctrl_sources)
        data_src = sorted(secret_data_sources)[0]
        ctrl_path = _shortest_path(g, ctrl_src, sink.node_id, EdgeKind.CONTROL)
        data_path = _shortest_path(g, data_src, sink.node_id, EdgeKind.DATA)

        if ctrl_path and data_path:
            findings.append(TrifectaFinding(
                egress_sink=sink.node_id,
                control_path=ctrl_path,
                data_path=data_path,
                control_source=ctrl_src,
                data_source=data_src,
            ))

    return findings


def _bfs_reverse(g: AIFG, target: str, kind: str) -> set[str]:
    """BFS backward over edges of `kind` from `target`."""
    seen: set[str] = set()
    q = deque([target])
    while q:
        n = q.popleft()
        if n in seen:
            continue
        seen.add(n)
        q.extend(g.predecessors(n, kind))
    return seen


def _shortest_path(g: AIFG, src: str, dst: str,
                   kind: str | None = None) -> list[str] | None:
    """Shortest path from src to dst (BFS), following edges of `kind`."""
    if src == dst:
        return [src]
    queue: deque[list[str]] = deque([[src]])
    seen: set[str] = {src}
    while queue:
        path = queue.popleft()
        for nxt in g.successors(path[-1], kind):
            if nxt == dst:
                return path + [nxt]
            if nxt not in seen:
                seen.add(nxt)
                queue.append(path + [nxt])
    return None


# ---------------------------------------------------------------------------
# 6. Min-cut remediation (Blueprint §3.4, Codex §2)
#    Minimal set of tools to restrict to provably break all exfil paths.
# ---------------------------------------------------------------------------

def min_tool_cut(g: AIFG,
                 untrusted_ctrl_sources: list[str],
                 egress_sinks: list[str],
                 removable: set[str]) -> set[str]:
    """Return the minimal set of tool node-ids to restrict.

    Uses the node-splitting max-flow construction (Menger's theorem):
    split each removable node v into v_in → v_out with capacity 1;
    all real edges get capacity ∞; saturated unit-edges name the min cut.
    [VERIFIED: Menger's theorem, Blueprint §3.4, Codex §2]

    removable: tool names that CAN be restricted (typically all tools,
               minus critical infrastructure the operator cannot remove).
    """
    # Build the split graph
    cap: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    INF = float("inf")
    S, T = "__CUT_SOURCE__", "__CUT_SINK__"

    for nid in g.nodes:
        if nid in removable:
            cap[f"{nid}::in"][f"{nid}::out"] += 1.0      # unit-cost cut
        else:
            cap[f"{nid}::in"][f"{nid}::out"] += INF       # cannot cut

    for e in g.edges:
        cap[f"{e.src}::out"][f"{e.dst}::in"] += INF       # real edges: free

    for src in untrusted_ctrl_sources:
        cap[S][f"{src}::in"] += INF
    for snk in egress_sinks:
        cap[f"{snk}::out"][T] += INF

    # Edmonds-Karp (BFS augmenting paths)
    _edmonds_karp(cap, S, T)

    # Nodes in min cut = split-edges where ::in is reachable from S but ::out is not
    reach = _bfs_residual(cap, S)
    return {
        nid for nid in removable
        if f"{nid}::in" in reach and f"{nid}::out" not in reach
    }


def _edmonds_karp(cap: dict, s: str, t: str) -> float:
    """Edmonds-Karp max-flow, modifies `cap` in-place (residual graph)."""
    flow = 0.0
    while True:
        parent = _bfs_path(cap, s, t)
        if parent is None:
            break
        # Bottleneck
        b, v = float("inf"), t
        while v != s:
            u = parent[v]
            b = min(b, cap[u][v])
            v = u
        # Augment
        v = t
        while v != s:
            u = parent[v]
            cap[u][v] -= b
            cap[v][u] += b
            v = u
        flow += b
    return flow


def _bfs_path(cap: dict, s: str, t: str) -> dict[str, str] | None:
    parent: dict[str, str] = {s: s}
    q = deque([s])
    while q:
        u = q.popleft()
        for v, c in cap[u].items():
            if v not in parent and c > 1e-9:
                parent[v] = u
                if v == t:
                    return parent
                q.append(v)
    return None


def _bfs_residual(cap: dict, s: str) -> set[str]:
    seen: set[str] = set()
    q = deque([s])
    while q:
        u = q.popleft()
        if u in seen:
            continue
        seen.add(u)
        for v, c in cap[u].items():
            if v not in seen and c > 1e-9:
                q.append(v)
    return seen
