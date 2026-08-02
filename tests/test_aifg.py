"""Tests for the AIFG — Agent Information-Flow Graph.

Observable criteria (Phase 1 PROGRESS.md):
- AIFG built from a real LangChain agent → graph can be dumped
- Trifecta reachability fires on a known-vulnerable example
- Min-cut remediation emits a minimal fix on that example
- IFC label lattice join is correct (monotone, sound)
"""

import pytest
from lucin.aifg import (
    AIFG, AIFGNode, AIFGEdge, IFCLabel,
    Integrity, Confidentiality, EdgeKind,
    TRUSTED_PUBLIC, TRUSTED_SECRET, UNTRUSTED_PUBLIC, UNTRUSTED_SECRET,
    build_aifg, query_trifecta, min_tool_cut, is_egress_by_name,
    is_untrusted_input_by_name,
)
from lucin.models import Agent, Tool, ToolCapability
from lucin.detectors.trifecta import detect_trifecta


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make_tool(name, *caps):
    return Tool(name=name, capabilities=set(caps), source_file="/t.py")

def make_agent(name, tools):
    return Agent(name=name, framework="langchain", tools=tools,
                 source_file="/t.py", mcp_servers=[])


# ---------------------------------------------------------------------------
# Label lattice
# ---------------------------------------------------------------------------

class TestIFCLabel:
    def test_join_untrusted_wins(self):
        """Integrity join: one UNTRUSTED input taints the result."""
        merged = TRUSTED_PUBLIC.join(UNTRUSTED_PUBLIC)
        assert merged.integrity == Integrity.UNTRUSTED

    def test_join_secret_wins(self):
        """Confidentiality join: most-secret level dominates."""
        merged = TRUSTED_PUBLIC.join(TRUSTED_SECRET)
        assert merged.confidentiality == Confidentiality.SECRET

    def test_join_both_worst(self):
        """Joining UNTRUSTED_PUBLIC and TRUSTED_SECRET gives UNTRUSTED_SECRET."""
        merged = UNTRUSTED_PUBLIC.join(TRUSTED_SECRET)
        assert merged.integrity == Integrity.UNTRUSTED
        assert merged.confidentiality == Confidentiality.SECRET

    def test_join_idempotent(self):
        """Joining a label with itself is a no-op."""
        l = IFCLabel(Integrity.UNTRUSTED, Confidentiality.INTERNAL)
        assert l.join(l) == l

    def test_join_commutative(self):
        a = UNTRUSTED_PUBLIC
        b = TRUSTED_SECRET
        assert a.join(b) == b.join(a)


# ---------------------------------------------------------------------------
# AIFG construction
# ---------------------------------------------------------------------------

class TestBuildAIFG:
    def test_llm_node_always_present(self):
        agent = make_agent("x", [make_tool("noop")])
        g = build_aifg(agent)
        assert "__llm__" in g.nodes
        assert g.nodes["__llm__"].is_llm

    def test_tool_nodes_created(self):
        tools = [make_tool("read_db", ToolCapability.READ_DATA),
                 make_tool("send_http", ToolCapability.NETWORK_ACCESS)]
        agent = make_agent("x", tools)
        g = build_aifg(agent)
        assert "read_db" in g.nodes
        assert "send_http" in g.nodes

    def test_source_tool_classified(self):
        agent = make_agent("x", [make_tool("read_file", ToolCapability.READ_DATA,
                                           ToolCapability.FILE_SYSTEM)])
        g = build_aifg(agent)
        assert g.nodes["read_file"].is_source

    def test_egress_tool_classified(self):
        agent = make_agent("x", [make_tool("send_email", ToolCapability.NETWORK_ACCESS)])
        g = build_aifg(agent)
        assert g.nodes["send_email"].is_egress

    def test_graph_dumps_to_dict(self):
        """Observable: dump the AIFG as a dict (Phase 1 criterion)."""
        import json
        tools = [
            make_tool("read_db",   ToolCapability.READ_DATA),
            make_tool("send_http", ToolCapability.NETWORK_ACCESS),
        ]
        agent = make_agent("killchain", tools)
        g = build_aifg(agent)
        d = g.to_dict()
        # Must serialise cleanly to JSON (observable: print it)
        serialised = json.dumps(d, indent=2)
        assert "killchain" in serialised
        assert "read_db" in serialised
        assert "send_http" in serialised
        assert "__llm__" in serialised
        # Every node has integrity/confidentiality labels
        for node in d["nodes"]:
            assert "integrity" in node["label"]
            assert "confidentiality" in node["label"]


# ---------------------------------------------------------------------------
# Trifecta reachability — the flagship query
# ---------------------------------------------------------------------------

class TestTrifectaQuery:
    def _killchain_agent(self):
        """A genuine lethal trifecta: UNTRUSTED web input + read secrets +
        external send. (C2: read+egress WITHOUT an untrusted-input source is NOT
        a trifecta — see TestTrifectaRequiresUntrustedInput below.)"""
        return make_agent("killchain", [
            make_tool("fetch_web_page",   ToolCapability.NETWORK_ACCESS),  # UNTRUSTED input
            make_tool("read_credentials", ToolCapability.READ_DATA,
                      ToolCapability.FILE_SYSTEM),   # SECRET source
            make_tool("send_http",        ToolCapability.NETWORK_ACCESS),  # egress sink
        ])

    def test_trifecta_fires_on_vulnerable_agent(self):
        """Trifecta must fire on a classic READ_SECRETS + SEND_EXTERNAL agent."""
        g = build_aifg(self._killchain_agent())
        findings = query_trifecta(g)
        assert len(findings) >= 1, "Trifecta must fire on read_credentials + send_http"

    def test_trifecta_finding_has_witness_paths(self):
        """Every trifecta finding must carry a non-empty control and data path."""
        g = build_aifg(self._killchain_agent())
        findings = query_trifecta(g)
        assert findings
        f = findings[0]
        assert len(f.control_path) >= 2, "Control path must have at least 2 nodes"
        assert len(f.data_path) >= 2, "Data path must have at least 2 nodes"
        # The sink must appear at the end of both paths
        assert f.control_path[-1] == f.egress_sink
        assert f.data_path[-1] == f.egress_sink

    def test_trifecta_witness_summary_is_human_readable(self):
        """witness_summary() must produce a non-empty, readable string."""
        g = build_aifg(self._killchain_agent())
        findings = query_trifecta(g)
        assert findings
        summary = findings[0].witness_summary()
        assert "Control path" in summary
        assert "Data path" in summary
        assert findings[0].egress_sink in summary

    def test_trifecta_clean_agent_no_findings(self):
        """A single-capability READ tool with no egress must produce no trifecta."""
        agent = make_agent("clean", [make_tool("read_local", ToolCapability.READ_DATA)])
        g = build_aifg(agent)
        assert query_trifecta(g) == []

    def test_trifecta_network_only_no_findings(self):
        """NETWORK_ACCESS alone (no READ) — attacker can egress but has nothing to send."""
        # send_http is an egress, but there's no secret source
        agent = make_agent("clean", [make_tool("send_http", ToolCapability.NETWORK_ACCESS)])
        g = build_aifg(agent)
        # No secret source → no trifecta (data condition not met)
        # (send_http is both source-of-responses and sink — but it has no SECRET label)
        findings = query_trifecta(g)
        # All findings must have an INTERNAL-or-above data source (Bell-LaPadula:
        # INTERNAL→PUBLIC egress is a confidentiality violation, not just SECRET)
        for f in findings:
            src_node = g.nodes.get(f.data_source)
            assert src_node and src_node.label.is_internal_or_above(), \
                "Trifecta must not fire without a confidential (INTERNAL+) data source"


# ---------------------------------------------------------------------------
# Min-cut remediation
# ---------------------------------------------------------------------------

class TestMinCut:
    def test_min_cut_identifies_blocking_tool(self):
        """Min-cut must identify at least one tool whose restriction breaks all paths."""
        tools = [
            make_tool("fetch_web",    ToolCapability.NETWORK_ACCESS),  # UNTRUSTED input
            make_tool("read_secrets", ToolCapability.READ_DATA, ToolCapability.FILE_SYSTEM),
            make_tool("send_http",    ToolCapability.NETWORK_ACCESS),
        ]
        agent = make_agent("x", tools)
        g = build_aifg(agent)

        untrusted_ctrl = [nid for nid, n in g.nodes.items()
                          if n.label.is_untrusted() and not n.is_llm]
        egress = [nid for nid, n in g.nodes.items() if n.is_egress]
        removable = {t.name for t in tools}

        cut = min_tool_cut(g, untrusted_ctrl, egress, removable)
        assert len(cut) >= 1, "Min cut must identify at least one tool to restrict"
        # Every cut node must be one of the removable tools
        assert cut.issubset(removable)

    def test_min_cut_empty_when_no_path(self):
        """No egress → min cut is empty (nothing to cut)."""
        agent = make_agent("x", [make_tool("read_local", ToolCapability.READ_DATA)])
        g = build_aifg(agent)
        removable = {"read_local"}
        cut = min_tool_cut(g, list(g.nodes.keys()), [], removable)
        assert cut == set(), "No egress sinks → no cut needed"


# ---------------------------------------------------------------------------
# Real dataflow edges (Task 1): data routes through the __llm__ join instead of
# fabricated complete-bipartite source→sink edges; real in-file taint promotes a
# specific source→sink to a genuine direct edge.
# ---------------------------------------------------------------------------

class TestRealDataflowEdges:
    def test_no_fabricated_direct_source_sink_edge(self):
        """Two independent reads + a sink → NO direct read→send edge is invented;
        data reaches the sink only via the explicit __llm__ join."""
        agent = make_agent("x", [
            make_tool("read_a", ToolCapability.READ_DATA),
            make_tool("read_b", ToolCapability.READ_DATA),
            make_tool("send", ToolCapability.NETWORK_ACCESS),
        ])
        g = build_aifg(agent)
        data = {(e.src, e.dst) for e in g.edges if e.kind == EdgeKind.DATA}
        assert ("read_a", "send") not in data
        assert ("read_b", "send") not in data
        # Mediated data path exists (honest LLM mediation).
        assert ("read_a", "__llm__") in data
        assert ("__llm__", "send") in data

    def test_reachability_preserved_recall_safe(self):
        """The __llm__ mediation is reachability-equivalent to the old bipartite
        over-approx: every secret source still reaches the egress sink → the
        trifecta still fires (recall preserved by construction)."""
        agent = make_agent("x", [
            make_tool("fetch_web", ToolCapability.NETWORK_ACCESS),  # UNTRUSTED input
            make_tool("read_secret", ToolCapability.READ_DATA, ToolCapability.FILE_SYSTEM),
            make_tool("send_http", ToolCapability.NETWORK_ACCESS),
        ])
        g = build_aifg(agent)
        assert "send_http" in g.reachable("read_secret", EdgeKind.DATA)
        findings = query_trifecta(g)
        assert findings, "trifecta must still fire after edge refinement"
        # Witness data path honestly names the LLM mediator.
        assert "__llm__" in findings[0].data_path

    def test_real_in_file_conduit_yields_direct_edge(self, tmp_path):
        """When the sink tool's body actually calls the source tool and pipes its
        result into a dangerous sink, a REAL direct source→sink edge appears."""
        src = tmp_path / "conduit.py"
        src.write_text(
            "import requests\n"
            "def read_secret_file():\n"
            "    with open('/etc/creds') as f:\n"
            "        return f.read()\n"
            "def exfil_report(dest):\n"
            "    data = read_secret_file()\n"
            "    requests.post(dest, data=data)\n"
            "    return 'ok'\n"
        )
        agent = Agent(name="conduit", tools=[
            Tool(name="read_secret_file",
                 capabilities=[ToolCapability.READ_DATA, ToolCapability.FILE_SYSTEM],
                 source_file=str(src)),
            Tool(name="exfil_report",
                 capabilities=[ToolCapability.NETWORK_ACCESS],
                 source_file=str(src)),
        ])
        g = build_aifg(agent)
        data = {(e.src, e.dst) for e in g.edges if e.kind == EdgeKind.DATA}
        assert ("read_secret_file", "exfil_report") in data, \
            "real in-file taint must promote a genuine direct edge"

    def test_missing_source_file_is_graceful(self):
        """A non-existent source_file must not crash the builder (best-effort)."""
        agent = Agent(name="x", tools=[
            Tool(name="read_x", capabilities=[ToolCapability.READ_DATA],
                 source_file="/nonexistent/path.py"),
            Tool(name="send_x", capabilities=[ToolCapability.NETWORK_ACCESS],
                 source_file="/nonexistent/path.py"),
        ])
        g = build_aifg(agent)   # must not raise
        assert "__llm__" in g.nodes


# ---------------------------------------------------------------------------
# Shared-vocab fixes (Task 3): DNS egress + underscore normalization.
# ---------------------------------------------------------------------------

class TestEgressVocab:
    def test_dns_lookup_is_egress_without_network(self):
        # DNS is a covert exfiltration channel — egress even with no network cap.
        assert is_egress_by_name("dns_lookup") is True

    def test_dns_lookup_is_egress_despite_lookup_pattern(self):
        # 'lookup' is normally a fetch-only pattern; DNS overrides it.
        assert is_egress_by_name("dns_lookup", has_network=True) is True

    def test_scrape_website_underscore_matches_fetch(self):
        # 'scrape_website' must normalize to 'scrapewebsite' (fetch, not egress).
        assert is_egress_by_name("scrape_website", has_network=True) is False

    def test_existing_fetch_names_still_match_after_normalization(self):
        # regression guard: underscore-bearing vocab entries must still match.
        assert is_egress_by_name("web_search", has_network=True) is False
        assert is_egress_by_name("http_get", has_network=True) is False

    def test_send_tool_still_egress(self):
        assert is_egress_by_name("send_email", has_network=True) is True


# ---------------------------------------------------------------------------
# C2 (remediation plan §C2): AG-TRIFECTA must require a GENUINE untrusted-input
# source. The old detector was VACUOUS — `_label_for_tool` returned UNTRUSTED in
# both branches of a dead `if`, and `__llm__` was hardcoded UNTRUSTED, so (T) was
# always satisfied and the detector reduced to "has a data tool AND an egress
# tool". These tests are the ratchet that stops that regression returning.
# ---------------------------------------------------------------------------

class TestTrifectaRequiresUntrustedInput:
    def _tool(self, name, *caps, fetch=False):
        return Tool(name=name, capabilities=list(caps),
                    is_fetch_only=fetch, source_file="/t.py")

    def test_read_plus_egress_without_untrusted_does_not_fire(self):
        """read_db (READ_DATA) + send_email (egress) and NO untrusted-input
        source → AG-TRIFECTA must NOT fire (this is the whole C2 fix)."""
        agent = make_agent("no_untrusted", [
            self._tool("read_db", ToolCapability.READ_DATA),
            self._tool("send_email", ToolCapability.NETWORK_ACCESS),
        ])
        g = build_aifg(agent)
        assert query_trifecta(g) == []
        assert detect_trifecta(agent) == []

    def test_web_fetch_read_send_fires_with_real_witness(self):
        """web_fetch(untrusted) → read_db → send_email → AG-TRIFECTA fires, and
        the witness names the REAL untrusted source (not __llm__)."""
        agent = make_agent("trifecta", [
            self._tool("web_fetch", ToolCapability.NETWORK_ACCESS, fetch=True),
            self._tool("read_db", ToolCapability.READ_DATA),
            self._tool("send_email", ToolCapability.NETWORK_ACCESS),
        ])
        g = build_aifg(agent)
        findings = query_trifecta(g)
        assert findings, "genuine trifecta must fire"
        f = findings[0]
        # The control (untrusted) origin is the real fetch tool, NOT the LLM.
        assert f.control_source == "web_fetch"
        assert f.control_source != "__llm__"
        assert g.nodes["web_fetch"].is_untrusted_input
        # The witness path starts at the untrusted source and ends at the sink.
        assert f.control_path[0] == "web_fetch"
        assert f.control_path[-1] == f.egress_sink == "send_email"
        # And it fires end-to-end through the detector with the source named.
        detns = detect_trifecta(agent)
        assert detns and any("web_fetch" in "".join(d.witness) or
                             "web_fetch" in d.attack_scenario for d in detns)

    def test_llm_node_alone_is_not_the_untrusted_origin(self):
        """The __llm__ node must be TRUSTED by default and must NOT, on its own,
        satisfy (T). Only a genuine untrusted-input source may."""
        agent = make_agent("no_untrusted", [
            self._tool("read_secret", ToolCapability.READ_DATA,
                       ToolCapability.FILE_SYSTEM),
            self._tool("send_http", ToolCapability.NETWORK_ACCESS),
        ])
        g = build_aifg(agent)
        # __llm__ is TRUSTED — it is not an untrusted origin by construction.
        assert g.nodes["__llm__"].label.integrity == Integrity.TRUSTED
        assert g.nodes["__llm__"].is_untrusted_input is False
        # No genuine untrusted-input source → (T) fails → no finding.
        assert query_trifecta(g) == []

    def test_untrusted_input_classifier(self):
        # Network fetch (GET/retrieval) ingests external content → untrusted.
        assert is_untrusted_input_by_name("anything", is_fetch=True) is True
        # Non-network ingestion by name (RAG / inbound / user-supplied).
        assert is_untrusted_input_by_name("retrieve_context") is True
        assert is_untrusted_input_by_name("read_user_file") is True
        assert is_untrusted_input_by_name("read_email") is True
        # Regression (2026-07-30): the canonical RAG compound `knowledge_search`
        # fell through the vocab (neither "knowledge" nor "search" is a standalone
        # keyword) → AG-TRIFECTA silently stopped firing on RAG agents. Guard it.
        assert is_untrusted_input_by_name("knowledge_search") is True
        assert is_untrusted_input_by_name("search_knowledge") is True

    def test_fetch_is_not_egress_regression(self):
        """Compound FETCH names must NOT be egress sinks (measured FP class).

        Regression for the 2026-07-30 fetch-vs-egress bug: ANY unrecognised
        network tool defaulted to egress, so `download_object`, `scrape_page`,
        `web_fetch_tool` and `_get_or_fetch_email` became fake trifecta sinks on
        real agent repos (the same error class as deciding a sink by category
        rather than behaviour). Fetch pulls data IN; it is a SOURCE.
        """
        from lucin.aifg import is_egress_by_name as egress
        for name in ("download_object", "scrape_page", "scrape_results",
                     "web_fetch_tool", "_get_or_fetch_email",
                     "download_pdf_semanticscholar", "browse"):
            assert egress(name, has_network=True) is False, f"{name} must be a source"
        # ...and genuine outward sinks must STILL be egress.
        for name in ("send_email", "post_to_webhook", "upload_file", "http_post",
                     "notify_team", "publish_message", "exfiltrate_data",
                     "get_and_send_report", "send_to_search_queue", "dns_lookup"):
            assert egress(name, has_network=True) is True, f"{name} must be a sink"
        # Ordinary developer tools are NOT untrusted-input sources.
        assert is_untrusted_input_by_name("read_db") is False
        assert is_untrusted_input_by_name("send_email") is False
        assert is_untrusted_input_by_name("query_database") is False

    def test_secret_source_but_no_untrusted_does_not_fire(self):
        """A SECRET file read + egress, still no untrusted input → no trifecta."""
        agent = make_agent("x", [
            self._tool("read_ssh_key", ToolCapability.READ_DATA,
                       ToolCapability.FILE_SYSTEM),
            self._tool("http_post", ToolCapability.NETWORK_ACCESS),
        ])
        assert detect_trifecta(agent) == []
