"""Every rule that fires must have documented copy, and vice versa."""
import glob
import re

from lucin.rule_docs import _EXPLAIN_DOCS, RULE_CATALOG

DOCUMENTED = set(RULE_CATALOG) | set(_EXPLAIN_DOCS)


def _emitted_ids() -> set[str]:
    ids = set()
    for p in glob.glob("src/lucin/detectors/*.py"):
        text = open(p).read()
        ids |= set(re.findall(r'id="(AG-[A-Za-z0-9-]+)"', text))
        ids |= set(re.findall(r'"id"\s*:\s*"(AG-[A-Za-z0-9-]+)"', text))
    return ids


def test_every_registered_rule_has_a_doc_page():
    missing = _emitted_ids() - DOCUMENTED
    assert not missing, f"rules with no /rules/ page: {sorted(missing)}"


def test_no_orphan_doc_pages():
    """A doc page for a rule ID that no detector actually emits is drift, not documentation."""
    orphans = DOCUMENTED - _emitted_ids()
    assert not orphans, f"doc pages for rules that never fire: {sorted(orphans)}"
