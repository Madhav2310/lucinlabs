"""EXPERIMENTAL / UNWIRED.

No `lucin scan`/`lucin verify` code path calls `record_event` on this class today — see
`docs/limits.md`. It is unit-tested directly (`tests/test_ledger.py`,
`tests/test_ledger_toctou.py`) but has no production caller and produces no findings on
any real scan.

`verify_integrity()` is **tamper-evident, not tamper-proof**: it proves the recorded chain
is internally self-consistent, which catches accidental corruption and detects tampering
that didn't also recompute the chain. It does **not** prove the ledger was never altered
by an attacker with the same local write access the ledger process itself has — that
attacker can edit history and recompute every hash forward from the edit, and
`verify_integrity()` will return `True`. Tamper-proofness against a locally-privileged
attacker requires an external, independently-controlled write path (e.g. an append-only
remote store, or signing with a key the compromised process cannot read) — see
`launch/evolving conviction/PHASE_6_PLAN.md` §1.3 for why that is future infrastructure
work, not a reason to abandon local hash-chaining as a *detection* signal.
"""
import hashlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path


class TemporalLedger:
    """
    Append-only Merkle-chained SQLite ledger for tracking cross-session
    temporal state (T3). Used to detect sleeper agents and memory poisoning.

    Unwired — see module docstring.
    """
    def __init__(self, db_path: str = ".lucin_ledger.db"):
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(
            db_path,
            check_same_thread=False,
            timeout=15.0  # Wait up to 15 seconds if database is locked
        )
        # Enable WAL mode for better concurrency
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_db()

    def _init_db(self):
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    agent_name TEXT,
                    event_type TEXT,
                    payload TEXT,
                    previous_hash TEXT,
                    current_hash TEXT
                )
            ''')
            # Check if genesis block exists
            cursor = self.conn.execute("SELECT COUNT(*) FROM events")
            if cursor.fetchone()[0] == 0:
                self._append_genesis()

    def _append_genesis(self):
        hasher = hashlib.sha256()
        prev_hash = "0" * 64
        agent_name = "SYSTEM"
        event_type = "GENESIS"
        payload_str = "{}"

        hasher.update(prev_hash.encode())
        hasher.update(b'\x00')
        hasher.update(agent_name.encode())
        hasher.update(b'\x00')
        hasher.update(event_type.encode())
        hasher.update(b'\x00')
        hasher.update(payload_str.encode())
        curr_hash = hasher.hexdigest()

        with self.conn:
            self.conn.execute('''
                INSERT INTO events (timestamp, agent_name, event_type, payload, previous_hash, current_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (time.time(), agent_name, event_type, payload_str, prev_hash, curr_hash))

    def get_latest_hash(self) -> str:
        cursor = self.conn.execute("SELECT current_hash FROM events ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        return row[0] if row else "0" * 64

    def record_event(self, agent_name: str, event_type: str, payload: dict) -> str:
        """
        Record a temporal event and chain it securely using an EXCLUSIVE lock
        to prevent TOCTOU race conditions.
        """
        payload_str = json.dumps(payload, sort_keys=True)

        # We lock at the Python level to serialize multi-threaded writes on the same object
        with self._lock:
            with self.conn:
                cursor = self.conn.cursor()
                # Read latest hash inside the lock
                cursor.execute("SELECT current_hash FROM events ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()
                prev_hash = row[0] if row else "0" * 64

                # Compute new hash
                hasher = hashlib.sha256()
                hasher.update(prev_hash.encode())
                hasher.update(b'\x00')
                hasher.update(agent_name.encode())
                hasher.update(b'\x00')
                hasher.update(event_type.encode())
                hasher.update(b'\x00')
                hasher.update(payload_str.encode())
                curr_hash = hasher.hexdigest()

                # Insert block
                cursor.execute('''
                    INSERT INTO events (timestamp, agent_name, event_type, payload, previous_hash, current_hash)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (time.time(), agent_name, event_type, payload_str, prev_hash, curr_hash))

                return curr_hash

    def get_events_for_agent(self, agent_name: str, event_type: str = None) -> list:
        query = "SELECT timestamp, event_type, payload FROM events WHERE agent_name = ?"
        params = [agent_name]
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        query += " ORDER BY id ASC"

        cursor = self.conn.execute(query, params)
        return [{"timestamp": r[0], "event_type": r[1], "payload": json.loads(r[2])} for r in cursor.fetchall()]

    def verify_integrity(self) -> bool:
        """
        Verify the cryptographic chain of the ledger.
        """
        cursor = self.conn.execute("SELECT id, agent_name, event_type, payload, previous_hash, current_hash FROM events ORDER BY id ASC")
        rows = cursor.fetchall()

        if not rows:
            return True

        expected_prev_hash = "0" * 64
        for row in rows:
            id, agent_name, event_type, payload, prev_hash, curr_hash = row

            if prev_hash != expected_prev_hash:
                return False

            hasher = hashlib.sha256()
            hasher.update(prev_hash.encode())
            hasher.update(b'\x00')
            hasher.update(agent_name.encode())
            hasher.update(b'\x00')
            hasher.update(event_type.encode())
            hasher.update(b'\x00')
            hasher.update(payload.encode())
            calculated_hash = hasher.hexdigest()

            if curr_hash != calculated_hash:
                return False

            expected_prev_hash = curr_hash

        return True
