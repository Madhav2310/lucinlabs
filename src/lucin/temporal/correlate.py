"""EXPERIMENTAL / UNWIRED.

Nothing in any `lucin scan`/`lucin verify` code path calls `TemporalLedger.record_event`
or constructs a `TemporalCorrelator` — see `docs/limits.md`. This module has no effect on
any shipped command today.

Phase 6 (`launch/evolving conviction/PHASE_6_PLAN.md` §2.6, §5.1.3) removed this module's
prior cross-session "memory poisoning" correlation: it flagged a `MEMORY_WRITE` as
adversarial if it contained any of a short marker list, one of which was the literal
string ``` ```bash ``` — a string that appears in any legitimate memory snapshot holding a
code fence. That heuristic had no benign-corpus measurement and is deleted rather than kept
disabled-but-present, per the project's rule that a rule which can't be measured doesn't ship.

What remains is the one part of the original design that is not a heuristic: verifying the
ledger's hash chain. This is a real cryptographic check, but it proves the chain is
internally consistent — it does **not** prove the ledger was never tampered with by
someone who could also recompute the chain (i.e. anyone with the same local write access
the ledger itself has). That is **tamper-evident**, never **tamper-proof**. See
`docs/limits.md`.
"""
from lucin.models import Finding, Severity
from lucin.temporal.ledger import TemporalLedger


class TemporalCorrelator:
    """Wraps `TemporalLedger.verify_integrity()` as a `Finding`. See module docstring."""

    def __init__(self, ledger: TemporalLedger):
        self.ledger = ledger

    def check_memory_integrity(self) -> list[Finding]:
        """Return a CRITICAL finding iff the ledger's hash chain fails to verify.

        Tamper-evident only (see module docstring) — an attacker with the same local
        write access the ledger has can recompute the chain, so a passing check here is
        not proof nothing was altered.
        """
        if self.ledger.verify_integrity():
            return []

        return [Finding(
            id="AG-013-T3",
            title="Cryptographic Chain Compromise (T3)",
            severity=Severity.CRITICAL,
            description="The Temporal Ledger cryptographic chain has been tampered with. State recovery is impossible.",
            agent_name="SYSTEM",
            attack_scenario="An attacker gained shell access and manually edited the SQLite ledger to cover their tracks.",
            blast_radius="The entire temporal tracking system is compromised.",
            owasp_ref="AG-013",
            fix_suggestion="Restore ledger from immutable backup and investigate system compromise.",
        )]
