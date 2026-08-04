import os
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from lucin.temporal.ledger import TemporalLedger


def test_ledger_concurrency_no_forks():
    """Test that multiple threads writing to the ledger concurrently do not create chain forks."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_ledger.db")
        ledger = TemporalLedger(db_path=db_path)

        # Write 50 events concurrently
        def write_event(i):
            ledger.record_event(agent_name=f"agent_{i}", event_type="TEST", payload={"data": i})

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(write_event, i) for i in range(50)]
            # Wait for all to complete
            for f in futures:
                f.result()

        # If the EXCLUSIVE transaction works, the chain should be valid.
        # Otherwise (TOCTOU bug), there will be forks and verify_integrity will fail.
        assert ledger.verify_integrity() is True
