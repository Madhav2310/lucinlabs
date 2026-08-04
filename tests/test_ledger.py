import os

import pytest

from lucin.temporal.correlate import TemporalCorrelator
from lucin.temporal.ledger import TemporalLedger


def test_ledger_integrity_success(tmp_path):
    db_path = tmp_path / "ledger.db"
    ledger = TemporalLedger(str(db_path))

    # Record some events
    ledger.record_event("AgentA", "MEMORY_WRITE", {"data": "test1"})
    ledger.record_event("AgentB", "MEMORY_READ", {"data": "test1"})

    # Verify chain
    assert ledger.verify_integrity() is True

def test_ledger_integrity_tampering(tmp_path):
    db_path = tmp_path / "ledger.db"
    ledger = TemporalLedger(str(db_path))

    # Record some events
    ledger.record_event("AgentA", "MEMORY_WRITE", {"data": "test1"})

    # Tamper with the database
    with ledger.conn:
        ledger.conn.execute("UPDATE events SET payload = 'tampered' WHERE id = 2")

    # Verify chain fails
    assert ledger.verify_integrity() is False

def test_temporal_correlator(tmp_path):
    db_path = tmp_path / "ledger.db"
    ledger = TemporalLedger(str(db_path))
    correlator = TemporalCorrelator(ledger)

    # Chain is intact
    assert len(correlator.check_memory_integrity()) == 0

    # Tamper
    with ledger.conn:
        ledger.conn.execute("UPDATE events SET payload = 'tampered' WHERE id = 1")

    findings = correlator.check_memory_integrity()
    assert len(findings) == 1
    assert findings[0].id == "AG-013-T3"
    assert findings[0].title == "Cryptographic Chain Compromise (T3)"
