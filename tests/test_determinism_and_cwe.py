"""Findings must be deterministically ordered and CWE-tagged.

Both properties were missing and both were found by a third-party benchmark run
(2026-07-30), not by this test suite:

* **Order was nondeterministic.** Detectors iterate sets of capabilities and tool
  names, and Python seeds string hashing per process, so the same scan returned the
  same findings in a different sequence on every run — verified as 4 different
  orderings across 4 runs of one repository. That breaks diffing, baselining, caching
  and any consumer that matches findings positionally.
* **No CWE field.** Findings carried only an OWASP-ASI reference, so every CWE-keyed
  consumer (SARIF taxonomies, enterprise triage, external benchmarks) was blind to
  them. The benchmark could not match a single finding without an external adapter.

Both are fixed at the single exit point (`detectors._finalize`) rather than in 27
detectors, so a future detector cannot reintroduce either by using a set internally —
which detectors legitimately do.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from lucin.detectors import _finalize, run_all_detectors
from lucin.models import Agent, Finding, Severity, Tool, ToolCapability
from lucin.rule_docs import RULE_CWE, cwes_for

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "real_world_tests" / "11_dangerous_agent" / "autonomous_coder.py"


def _f(fid, sev=Severity.HIGH, file="a.py", line=1, **kw) -> Finding:
    return Finding(id=fid, title=kw.pop("title", fid), severity=sev,
                   description="d", source_file=file, source_line=line, **kw)


# ------------------------------------------------------------------ ordering
def test_order_is_severity_first_then_location():
    out = _finalize([
        _f("AG-028", Severity.MEDIUM, "b.py", 5),
        _f("AG-TRIFECTA", Severity.CRITICAL, "z.py", 99),
        _f("AG-006", Severity.HIGH, "a.py", 2),
        _f("AG-007", Severity.HIGH, "a.py", 1),
    ])
    assert [x.id for x in out] == ["AG-TRIFECTA", "AG-007", "AG-006", "AG-028"], \
        "worst-first, then by file and line"


def test_sort_key_is_total_so_ties_cannot_fall_back_to_input_order():
    """Python's sort is stable: if the key ties, the nondeterministic input order
    survives. Two findings differing ONLY in witness must still sort deterministically."""
    a = _f("AG-001", witness=["zzz"])
    b = _f("AG-001", witness=["aaa"])
    assert [x.witness for x in _finalize([a, b])] == [["aaa"], ["zzz"]]
    assert [x.witness for x in _finalize([b, a])] == [["aaa"], ["zzz"]]


def test_repeated_finalize_is_idempotent():
    findings = [_f("AG-006", Severity.HIGH, "b.py", 3), _f("AG-001", Severity.CRITICAL)]
    once = [f.id for f in _finalize(list(findings))]
    twice = [f.id for f in _finalize(_finalize(list(findings)))]
    assert once == twice


@pytest.mark.skipif(not FIXTURE.exists(), reason="fixture missing")
def test_end_to_end_order_is_stable_across_processes():
    """The real regression: separate processes get separate hash seeds."""
    code = (
        "from lucin.scanner import scan_target;from pathlib import Path;import json\n"
        f"r=scan_target(Path(r'{FIXTURE}'))\n"
        "print(json.dumps([(f.id,f.source_line,f.severity.value) for f in r.findings]))\n"
    )
    runs = []
    for seed in ("0", "1", "12345"):
        out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                             text=True, cwd=ROOT, env={"PYTHONHASHSEED": seed,
                                                       "PATH": "/usr/bin:/bin"})
        line = [ln for ln in out.stdout.splitlines() if ln.startswith("[")]
        assert line, f"scan produced no output: {out.stderr[-300:]}"
        runs.append(line[-1])
    assert len(set(runs)) == 1, "finding order varied across hash seeds"


# ---------------------------------------------------------------------- CWE
def test_every_finding_gets_a_cwe_from_the_central_map():
    out = _finalize([_f("AG-001"), _f("AG-SQL"), _f("AG-TRIFECTA")])
    by_id = {f.id: f.cwe for f in out}
    assert by_id["AG-001"] == ["CWE-78", "CWE-94"]
    assert by_id["AG-SQL"] == ["CWE-89"]
    assert "CWE-1427" in by_id["AG-TRIFECTA"], "prompt-injection CWE for the trifecta"


def test_suffixed_rule_ids_inherit_their_prefix():
    """AG-COMP-LATERAL must inherit AG-COMP rather than silently losing its CWE."""
    assert cwes_for("AG-COMP-LATERAL") == RULE_CWE["AG-COMP"]
    assert cwes_for("AG-005a") == RULE_CWE["AG-005a"]
    assert cwes_for("AG-NOT-A-REAL-RULE") == []


def test_cwe_ids_are_well_formed():
    for rule, cwes in RULE_CWE.items():
        assert cwes, f"{rule} maps to an empty CWE list"
        for c in cwes:
            assert c.startswith("CWE-") and c[4:].isdigit(), f"{rule}: malformed {c}"


def test_registered_detectors_all_have_a_cwe_mapping():
    """A finding without a CWE is invisible to CWE-keyed consumers, so the mapping
    must keep pace with the registry."""
    agent = Agent(name="a", framework="generic", agent_evidence=["@tool decorator"],
                  tools=[Tool(name="run_cmd",
                              capabilities=[ToolCapability.EXECUTE_CODE])])
    for f in run_all_detectors([agent]):
        assert f.cwe, f"{f.id} produced a finding with no CWE mapping"


@pytest.mark.skipif(not FIXTURE.exists(), reason="fixture missing")
def test_sarif_carries_cwe_in_tags_and_properties():
    from lucin.sarif import to_sarif_string
    from lucin.scanner import scan_target
    result = scan_target(FIXTURE)
    doc = json.loads(to_sarif_string(result, cwd=FIXTURE.parent))
    results = doc["runs"][0]["results"]
    assert results, "no SARIF results"
    for r in results:
        props = r.get("properties", {})
        assert props.get("cwe"), f"{r['ruleId']} has no cwe in SARIF properties"
        # GitHub code scanning reads CWE out of tags in this exact shape
        assert any(t.startswith("external/cwe/cwe-") for t in props.get("tags", []))
