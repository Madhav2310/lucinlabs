"""Ratchet test: every rule ID a detector can emit must be documented.

The docs pipeline generates rule pages *from* the catalog, so the guarantee runs one
way only — a rule cannot be documented without existing, but a rule CAN exist without
being documented, silently and with no error. That drift is invisible: the site builds
clean, the tests pass, and a user hits a finding whose rule page 404s.

This test pins the current gap. A NEW undocumented rule fails the build; closing an
existing one also fails, with instructions to shrink the allowlist. Either way the
number can only move deliberately.
"""

import re
from pathlib import Path

import lucin.rule_docs as rd


_SRC = Path(__file__).resolve().parent.parent / "src" / "lucin"
_ID_RE = re.compile(r'id="(AG-[A-Z0-9-]+)"')

# Rules that emit findings but have no documentation page, as measured 2026-07-30.
# This is honest debt, not an exemption: shrink it, never grow it.
KNOWN_UNDOCUMENTED = frozenset({
    "AG-028",
    "AG-CORS",
    "AG-DESERIALIZE",
    "AG-DOCKER-EXEC",
    "AG-ENV-FALLBACK",
    "AG-FRAMEWORK-PIN",
    "AG-MCP-TOKENLEAK",
    "AG-NOAUTH",
    "AG-PATH-TRAVERSAL",
    "AG-RAG-NO-SANITIZE",
    "AG-RUGPULL",
    "AG-SQL",
    "AG-SSRF",
})


def _emitted_rule_ids() -> set[str]:
    """Every rule ID constructed anywhere in the package."""
    ids: set[str] = set()
    for path in _SRC.rglob("*.py"):
        ids.update(_ID_RE.findall(path.read_text(encoding="utf-8", errors="replace")))
    return ids


def _documented_rule_ids() -> set[str]:
    """Rule IDs the site generator produces a page for (see site/build_rules.py)."""
    return set(rd.RULE_CATALOG) | set(rd._EXPLAIN_DOCS)


def test_no_new_undocumented_rules():
    """A rule added without a catalog entry must fail here, not 404 for a user."""
    undocumented = _emitted_rule_ids() - _documented_rule_ids()
    new = undocumented - KNOWN_UNDOCUMENTED
    assert not new, (
        f"New undocumented rule(s): {sorted(new)}. Add an entry to RULE_CATALOG in "
        f"src/lucin/rule_docs.py — a finding whose rule page does not exist is a "
        f"finding the user cannot act on."
    )


def test_undocumented_allowlist_has_not_gone_stale():
    """Documenting a listed rule must shrink the allowlist, so the debt stays honest."""
    undocumented = _emitted_rule_ids() - _documented_rule_ids()
    fixed = KNOWN_UNDOCUMENTED - undocumented
    assert not fixed, (
        f"Now documented, remove from KNOWN_UNDOCUMENTED: {sorted(fixed)}"
    )


def test_no_documented_rule_is_unreachable():
    """A documented rule no detector can emit is a page describing nothing."""
    orphans = _documented_rule_ids() - _emitted_rule_ids()
    assert not orphans, (
        f"Documented but never emitted: {sorted(orphans)}. Either wire the detector "
        f"or delete the page — docs for an unreachable rule overstate the surface."
    )
