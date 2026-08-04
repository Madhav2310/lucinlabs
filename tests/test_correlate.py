import os
import tempfile

from lucin.temporal.correlate import TemporalCorrelator
from lucin.temporal.ledger import TemporalLedger

# Phase 6 (PHASE_6_PLAN.md §2.6, §5.1.3) removed TemporalCorrelator's naive-marker
# cross-session correlation: it flagged any MEMORY_WRITE containing one of a short
# string list, including the literal "```bash" — which fires on any legitimate memory
# snapshot holding a code fence. It had no benign-corpus FP measurement. What remains
# is the one non-heuristic part: verifying the ledger's cryptographic hash chain.


def test_intact_chain_yields_no_findings():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_ledger.db")
        ledger = TemporalLedger(db_path=db_path)
        ledger.record_event(agent_name="AgentX", event_type="MEMORY_WRITE", payload={"data": "anything"})

        correlator = TemporalCorrelator(ledger=ledger)
        assert correlator.check_memory_integrity() == []


def test_tampered_chain_is_flagged():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_ledger.db")
        ledger = TemporalLedger(db_path=db_path)
        ledger.record_event(agent_name="AgentX", event_type="MEMORY_WRITE", payload={"data": "anything"})

        with ledger.conn:
            ledger.conn.execute("UPDATE events SET payload = 'tampered' WHERE id = 2")

        correlator = TemporalCorrelator(ledger=ledger)
        findings = correlator.check_memory_integrity()

        assert len(findings) == 1
        assert findings[0].id == "AG-013-T3"


def test_benign_memory_containing_a_code_fence_is_not_flagged():
    """Regression: the deleted heuristic's own trigger string must not resurface."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_ledger.db")
        ledger = TemporalLedger(db_path=db_path)
        ledger.record_event(
            agent_name="AgentX",
            event_type="MEMORY_WRITE",
            payload={"data": "Here's how to run it:\n```bash\necho hello\n```"},
        )
        ledger.record_event(
            agent_name="AgentX",
            event_type="MEMORY_READ",
            payload={"data": "Here's how to run it:\n```bash\necho hello\n```"},
        )

        correlator = TemporalCorrelator(ledger=ledger)
        assert correlator.check_memory_integrity() == []
