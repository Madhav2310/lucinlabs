from lucin.models import Agent, Finding
from lucin.temporal.correlate import TemporalCorrelator
from lucin.temporal.ledger import TemporalLedger


def detect_memory_integrity(agent: Agent, ledger: TemporalLedger = None) -> list[Finding]:
    """
    AG-013: Memory Integrity (T3 - Temporal Correlated)

    NOT registered in PER_AGENT_DETECTORS/CROSS_AGENT_DETECTORS and not reachable from any
    `lucin scan`/`lucin verify` code path — no caller in the scan pipeline ever constructs
    and passes a `ledger`, so this always no-ops in production (see docs/limits.md and
    `launch/evolving conviction/PHASE_6_PLAN.md` §2.6, §5.1.3). Exercised directly by
    `tests/test_ledger.py`/`tests/test_correlate.py` only. Do not register until a scan
    path actually writes to the ledger.
    """
    if not ledger:
        return []

    correlator = TemporalCorrelator(ledger)
    findings = correlator.check_memory_integrity()

    # Filter to only return findings relevant to this agent or SYSTEM-level
    relevant_findings = []
    for f in findings:
        if f.agent_name == agent.name or f.agent_name == "SYSTEM":
            relevant_findings.append(f)

    return relevant_findings
