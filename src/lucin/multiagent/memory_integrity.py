"""Runtime memory / RAG-store integrity monitoring.

Blueprint §6.4: "Monitor persistent memory/RAG stores for injected content
now steering decisions (AgentPoison arXiv:2407.12784) — a runtime capability
with zero productized competitor."

The attack (AgentPoison / indirect prompt injection via memory):
  1. Attacker inserts a malicious document into the vector store (or poisons
     an existing document via an update).
  2. The document is retrieved during a query and injected into the LLM context.
  3. The malicious content steers the LLM's behavior (exfiltration, jailbreak,
     pivoting, persona override).
  4. This happens silently, potentially days after the injection.

This module detects:
  - New documents added to the store since baseline
  - Existing documents that changed content (hash mismatch)
  - Documents containing high-risk injection patterns

Detect-and-HOLD (NOT detect-once): a flagged change is NEVER auto-folded into
the trusted baseline. It is held as a pending-review change and re-reported on
EVERY subsequent ``check()`` until an operator explicitly acknowledges it with
``accept(store_id, doc_id)``. This is the whole point: a monitor that silently
absorbed the poison it just saw would be blind on the very next call. Only
``accept()`` promotes an observed change into the trusted baseline.

Usage:
    monitor = MemoryIntegrityMonitor()
    monitor.baseline("company-kb", initial_documents)

    # Later, after a retrieval:
    report = monitor.check("company-kb", current_documents)
    if report.has_tampering:
        alert(report)          # still fires on the NEXT check() too

    # An operator reviews and decides a specific change is legitimate:
    monitor.accept("company-kb", "doc-42")   # folds it into the baseline
    # subsequent check() no longer flags doc-42
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass

# Patterns that suggest injected instructions in a document
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?", re.I),
    re.compile(r"you\s+are\s+now\s+(?:in\s+)?(?:admin|developer|god|DAN|root)\s+mode", re.I),
    re.compile(r"(?:system|admin)\s+(?:override|prompt|instruction)", re.I),
    re.compile(r"(?:do\s+not|never)\s+(?:tell|inform|reveal|mention)\s+(?:the\s+)?user", re.I),
    re.compile(r"(?:extract|exfiltrate|steal|send|leak)\s+(?:all\s+)?(?:data|secrets?|credentials?|keys?)", re.I),
    re.compile(r"curl\s+.*https?://", re.I),
    re.compile(r"<\s*(?:HIDDEN|SYSTEM|ADMIN|SECRET)\s*(?:INSTRUCTION|COMMAND|NOTE)[^>]*>", re.I),
    re.compile(r"\[(?:HIDDEN|SYSTEM|CONFIDENTIAL)\s+(?:INSTRUCTION|NOTE)\]", re.I),
    # Zero-width character injection
    re.compile(r"[​‌‍﻿‪-‮]"),
    # Unicode TAG injection (used in real attacks)
    re.compile(r"[\U000e0000-\U000e007f]+"),
]


@dataclass
class DocumentRecord:
    """Hashed record of one document in the store."""
    doc_id:      str
    content_hash: str
    length:      int
    first_seen:  float
    last_seen:   float
    injection_risk: bool = False  # True if injection patterns were found at baseline


@dataclass
class PendingChange:
    """A flagged change awaiting explicit operator review.

    Held OUT of the trusted baseline. ``event_type`` mirrors the reported
    :class:`TamperingEvent`. ``record`` is the observed state that will be
    promoted into the baseline if ``accept()`` is called (``None`` for a
    "removed" change, whose acceptance deletes the doc from the baseline).
    """
    doc_id:     str
    event_type: str
    record:     DocumentRecord | None


@dataclass
class TamperingEvent:
    """One detected integrity violation."""
    doc_id:    str
    event_type: str  # "added", "modified", "injection_detected", "removed"
    details:   str
    risk:      str   # "HIGH", "MEDIUM", "LOW"


@dataclass
class IntegrityReport:
    """Result of an integrity check against the baseline."""
    store_id:        str
    checked_at:      float
    baseline_docs:   int
    current_docs:    int
    events:          list[TamperingEvent]

    @property
    def has_tampering(self) -> bool:
        return bool(self.events)

    @property
    def high_risk_events(self) -> list[TamperingEvent]:
        return [e for e in self.events if e.risk == "HIGH"]

    def describe(self) -> str:
        if not self.events:
            return f"IntegrityReport({self.store_id}): CLEAN — {self.current_docs} docs, no changes"
        lines = [
            f"IntegrityReport({self.store_id}): {len(self.events)} event(s) detected",
            f"  Baseline: {self.baseline_docs} docs  Current: {self.current_docs} docs",
        ]
        for e in self.events:
            lines.append(f"  [{e.risk}] {e.event_type}: {e.doc_id}")
            lines.append(f"    {e.details}")
        return "\n".join(lines)


class MemoryIntegrityMonitor:
    """Monitors vector stores and memory backends for content tampering.

    Works with any store that exposes documents as {id: str, content: str}
    dicts or as plain (id, content) tuples.

    The monitor maintains a content-hash baseline per store. On each check,
    it compares the current state against the baseline and reports any:
      - New documents (could be poisoning)
      - Modified documents (could be poisoning of existing content)
      - Documents containing injection patterns

    Note: for vector stores, "content" is the text that will be embedded
    and retrieved. The hash is over the content string.
    """

    def __init__(self):
        # Trusted baseline: the ground truth a check() compares against.
        self._baselines: dict[str, dict[str, DocumentRecord]] = {}
        # Pending-review changes: flagged deltas NOT yet accepted. Rebuilt on
        # every check() to mirror the currently-outstanding flagged changes so
        # accept() can promote the exact change the operator was shown.
        self._pending: dict[str, dict[str, PendingChange]] = {}

    def baseline(self, store_id: str,
                 documents: list[dict | tuple]) -> dict[str, DocumentRecord]:
        """Establish a content-hash baseline for a store.

        documents can be:
          - list of {"id": str, "content": str} dicts
          - list of (id, content) tuples
        """
        records: dict[str, DocumentRecord] = {}
        now = time.time()

        for doc in documents:
            doc_id, content = self._parse_doc(doc)
            h = self._hash(content)
            injection_risk = self._has_injection(content)
            records[doc_id] = DocumentRecord(
                doc_id=doc_id,
                content_hash=h,
                length=len(content),
                first_seen=now,
                last_seen=now,
                injection_risk=injection_risk,
            )

        self._baselines[store_id] = records
        # A fresh baseline supersedes any outstanding pending review.
        self._pending[store_id] = {}
        return records

    def check(self, store_id: str,
              documents: list[dict | tuple]) -> IntegrityReport:
        """Compare current store state against the TRUSTED baseline.

        Returns an IntegrityReport with any detected tampering events. Flagged
        changes are NEVER folded into the baseline here — they are held as
        pending-review changes and will be re-reported on every subsequent
        ``check()`` until :meth:`accept` acknowledges them. Only unchanged docs
        (matching the trusted baseline) pass silently.
        """
        baseline = self._baselines.get(store_id, {})
        current: dict[str, str] = {}

        for doc in documents:
            doc_id, content = self._parse_doc(doc)
            current[doc_id] = content

        events: list[TamperingEvent] = []
        now = time.time()

        # Check for added documents
        for doc_id, content in current.items():
            if doc_id not in baseline:
                has_inject = self._has_injection(content)
                events.append(TamperingEvent(
                    doc_id=doc_id,
                    event_type="added",
                    details=(
                        f"New document not in baseline. "
                        f"Length: {len(content)}. "
                        f"{'⚠ Contains injection patterns!' if has_inject else 'No injection patterns detected.'}"
                    ),
                    risk="HIGH" if has_inject else "MEDIUM",
                ))
                # NOTE: the new doc is deliberately NOT folded into the baseline.
                # It is held for review (see pending-change build below) and will
                # be re-reported on every check() until accept() is called.

        # Check for modified documents
        for doc_id, record in list(baseline.items()):
            if doc_id not in current:
                events.append(TamperingEvent(
                    doc_id=doc_id,
                    event_type="removed",
                    details="Document present at baseline but missing now.",
                    risk="LOW",
                ))
                continue

            content = current[doc_id]
            h = self._hash(content)
            if h != record.content_hash:
                has_inject = self._has_injection(content)
                events.append(TamperingEvent(
                    doc_id=doc_id,
                    event_type="modified",
                    details=(
                        f"Content hash changed: {record.content_hash[:12]}... → {h[:12]}... "
                        f"Length: {record.length} → {len(content)}. "
                        f"{'⚠ New injection patterns detected!' if has_inject else ''}"
                    ),
                    risk="HIGH" if has_inject else "MEDIUM",
                ))
                # NOTE: the trusted baseline record is deliberately NOT mutated.
                # The modified content is held for review and re-reported on
                # every check() until accept() promotes it.

        # Scan all current docs for injection patterns (even unmodified ones)
        for doc_id, content in current.items():
            if doc_id in baseline and baseline[doc_id].injection_risk:
                # Already flagged at baseline — don't re-flag
                continue
            if self._has_injection(content) and not any(
                e.doc_id == doc_id for e in events
            ):
                events.append(TamperingEvent(
                    doc_id=doc_id,
                    event_type="injection_detected",
                    details="Injection patterns found in document content.",
                    risk="HIGH",
                ))

        # Rebuild the pending-review set to mirror the currently-outstanding
        # flagged changes. Each pending entry carries the observed state to be
        # promoted into the baseline if (and only if) accept() is called. This
        # is refreshed every check() so accept() always promotes the change the
        # operator was most recently shown.
        pending: dict[str, PendingChange] = {}
        for e in events:
            if e.event_type == "removed":
                pending[e.doc_id] = PendingChange(e.doc_id, "removed", None)
            else:
                content = current.get(e.doc_id, "")
                pending[e.doc_id] = PendingChange(
                    e.doc_id,
                    e.event_type,
                    DocumentRecord(
                        doc_id=e.doc_id,
                        content_hash=self._hash(content),
                        length=len(content),
                        first_seen=now,
                        last_seen=now,
                        injection_risk=self._has_injection(content),
                    ),
                )
        self._pending[store_id] = pending

        return IntegrityReport(
            store_id=store_id,
            checked_at=now,
            baseline_docs=len(baseline),
            current_docs=len(current),
            events=events,
        )

    def accept(self, store_id: str, doc_id: str) -> bool:
        """Explicitly acknowledge a pending-review change as legitimate.

        Promotes the last-observed state of ``doc_id`` into the trusted
        baseline (or, for a "removed" change, drops it from the baseline), so
        it is no longer re-reported by future ``check()`` calls. This is the
        ONLY path by which a flagged change enters the baseline.

        Returns True if a pending change for ``doc_id`` existed and was
        accepted; False if there was nothing pending for it.
        """
        change = self._pending.get(store_id, {}).pop(doc_id, None)
        if change is None:
            return False
        baseline = self._baselines.setdefault(store_id, {})
        if change.event_type == "removed":
            baseline.pop(doc_id, None)
        else:
            baseline[doc_id] = change.record
        return True

    def pending_changes(self, store_id: str) -> list[PendingChange]:
        """Return the flagged changes currently awaiting review for a store."""
        return list(self._pending.get(store_id, {}).values())

    def has_baseline(self, store_id: str) -> bool:
        return store_id in self._baselines

    def baseline_size(self, store_id: str) -> int:
        return len(self._baselines.get(store_id, {}))

    @staticmethod
    def _parse_doc(doc: dict | tuple) -> tuple[str, str]:
        if isinstance(doc, dict):
            return str(doc.get("id", doc.get("doc_id", "unknown"))), str(doc.get("content", doc.get("text", "")))
        return str(doc[0]), str(doc[1])

    @staticmethod
    def _hash(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def _has_injection(content: str) -> bool:
        return any(p.search(content) for p in _INJECTION_PATTERNS)
