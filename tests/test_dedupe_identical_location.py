"""Location-dedup must collapse duplicates WITHOUT merging distinct weaknesses.

Both directions are tested because getting one right and the other wrong is easy, and
the first implementation did exactly that: keyed on (id, file, line) alone, it collapsed
two different AG-007 findings that legitimately share a line (an AWS-key pattern match
and a Shannon-entropy match), silently deleting a real detection.
"""

from lucin.detectors import _dedupe_identical_location
from lucin.models import Finding, Severity


def _f(rid, file, line, title="t", witness=None):
    """`Finding.source_file`/`source_line` are str/int with ""/0 for absent, not None."""
    return Finding(id=rid, title=title, severity=Severity.HIGH, description="",
                   agent_name="a", source_file=file or "", source_line=line or 0,
                   witness=witness or [])


def test_collapses_identical_rule_and_location():
    """The AG-CORS case: one weakness re-emitted once per sibling agent."""
    fs = [_f("AG-CORS", "/r/server.py", 40) for _ in range(7)]
    assert len(_dedupe_identical_location(fs)) == 1


def test_keeps_distinct_weaknesses_sharing_a_line():
    """One line can carry two different weaknesses under the same rule."""
    fs = [_f("AG-007", "/r/a.py", 5, title="Hardcoded Secret: AWS Secret Key"),
          _f("AG-007", "/r/a.py", 5, title="High-Entropy Secret")]
    assert len(_dedupe_identical_location(fs)) == 2


def test_keeps_same_rule_at_different_lines():
    fs = [_f("AG-CORS", "/r/server.py", 40), _f("AG-CORS", "/r/server.py", 90)]
    assert len(_dedupe_identical_location(fs)) == 2


def test_keeps_same_rule_in_different_files():
    fs = [_f("AG-CORS", "/r/a.py", 40), _f("AG-CORS", "/r/b.py", 40)]
    assert len(_dedupe_identical_location(fs)) == 2


def test_never_merges_agent_scoped_findings_without_a_location():
    """No source_file means agent-scoped, not location-scoped — merging would be wrong."""
    fs = [_f("AG-002", "", 0), _f("AG-002", "", 0)]
    assert len(_dedupe_identical_location(fs)) == 2


def test_retains_the_copy_with_the_most_evidence():
    """Dedup must never cost the user an explanation."""
    thin = _f("AG-CORS", "/r/server.py", 40, witness=["a"])
    rich = _f("AG-CORS", "/r/server.py", 40, witness=["a", "b", "c"])
    out = _dedupe_identical_location([thin, rich])
    assert len(out) == 1 and len(out[0].witness) == 3


def test_preserves_input_order_of_survivors():
    """Determinism: dedup must not reorder, since _finalize's sort assumes stability."""
    fs = [_f("AG-CORS", "/r/b.py", 1), _f("AG-CORS", "/r/a.py", 1),
          _f("AG-CORS", "/r/b.py", 1)]
    out = _dedupe_identical_location(fs)
    assert [f.source_file for f in out] == ["/r/b.py", "/r/a.py"]
