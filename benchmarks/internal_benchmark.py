"""Internal benchmark — precision/recall on the existing test corpus.

This is the first step toward the published FP-rate claim (Phase 1 goal:
< 5% FP on 100 real repos). Right now it measures on our own test fixtures,
which are author-written — NOT an independent benign corpus. That gap is
explicitly noted in the output.

What this measures:
  RECALL:    does the scanner catch known-vulnerable examples?
  PRECISION: does the scanner avoid firing on known-benign examples?

Both are measured separately; never combined into a single pass/fail score
(that was the prototype's benchmark bug).

Run:
  python benchmarks/internal_benchmark.py

Observable output: a table of precision/recall per finding type, plus
an honest disclaimer about the corpus limitations.
"""

import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from lucin.scanner import scan_target

# ---------------------------------------------------------------------------
# Vulnerable corpus — files that MUST produce findings
# ---------------------------------------------------------------------------
VULNERABLE = [
    {
        "file": ROOT / "benchmarks/vulnerable/shell_exec.py",
        "expected": {"AG-001"},
        "label": "shell_exec",
    },
    {
        "file": ROOT / "benchmarks/vulnerable/data_exfil.py",
        "expected": {"AG-002"},
        "label": "data_exfil",
    },
    {
        "file": ROOT / "benchmarks/vulnerable/hardcoded_key.py",
        "expected": {"AG-007"},
        "label": "hardcoded_key",
    },
    {
        "file": ROOT / "benchmarks/vulnerable/tool_poisoning.py",
        "expected": {"AG-011"},
        "label": "tool_poisoning",
    },
    {
        "file": ROOT / "real_world_tests/11_dangerous_agent/autonomous_coder.py",
        "expected": {"AG-001", "AG-002"},
        "label": "autonomous_coder (real-world)",
    },
    {
        "file": ROOT / "real_world_tests/02_langchain_python_repl/agent.py",
        "expected": {"AG-001"},
        "label": "langchain_python_repl (real-world)",
    },
    # New corpus-derived detectors (2026-07-28)
    {
        "file": ROOT / "benchmarks/vulnerable/sql_injection_tool.py",
        "expected": {"AG-SQL"},
        "label": "sql_injection_tool (corpus-derived: smolagents text_to_sql)",
    },
    {
        "file": ROOT / "benchmarks/vulnerable/docker_exec_tool.py",
        "expected": {"AG-DOCKER-EXEC"},
        "label": "docker_exec_tool (corpus-derived: OpenAI Agents Dapr)",
    },
    {
        "file": ROOT / "benchmarks/vulnerable/rag_no_sanitize.py",
        "expected": {"AG-RAG-NO-SANITIZE"},
        "label": "rag_no_sanitize (corpus-derived: every RAG tutorial)",
    },
    {
        "file": ROOT / "real_world_tests/16_rag_sql_docker/agent.py",
        "expected": {"AG-SQL", "AG-DOCKER-EXEC", "AG-RAG-NO-SANITIZE"},
        "label": "rag_sql_docker (combined real-world fixture)",
    },
]

# ---------------------------------------------------------------------------
# Benign corpus — files that MUST NOT produce CRITICAL findings
# (currently author-written; flagged as such in the output)
# ---------------------------------------------------------------------------
BENIGN = [
    {
        "file": ROOT / "benchmarks/safe/calculator.py",
        "forbidden_severity": {"critical"},
        "label": "calculator (safe)",
    },
    {
        "file": ROOT / "benchmarks/safe/readonly_search.py",
        "forbidden_severity": {"critical"},
        "label": "readonly_search (safe)",
    },
    {
        "file": ROOT / "real_world_tests/06_crewai_trip_planner/trip_agents.py",
        "forbidden_severity": {"critical"},
        "label": "crewai_trip_planner (real-world, should be ≤HIGH)",
    },
]


def run():
    print("=" * 70)
    print("Lucin Internal Benchmark")
    print("=" * 70)
    print()
    print("⚠  CORPUS LIMITATION: vulnerable cases are author-written; benign")
    print("   cases are author-written. This is NOT a real-world FP measurement.")
    print("   Phase 1 goal: run on 100 real cloned repos (needs network).")
    print()

    # --- Recall pass ---
    print("RECALL — known-vulnerable files")
    print("-" * 50)
    recall_hits = 0
    recall_total = 0
    for case in VULNERABLE:
        if not case["file"].exists():
            print(f"  SKIP  {case['label']} (file missing)")
            continue
        t0 = time.time()
        result = scan_target(case["file"])
        ms = (time.time() - t0) * 1000
        found_ids = {f.id for f in result.findings}
        hits = case["expected"] & found_ids
        misses = case["expected"] - found_ids
        recall_total += len(case["expected"])
        recall_hits += len(hits)
        status = "PASS" if not misses else "MISS"
        print(f"  {status:4s}  {case['label']}")
        if misses:
            print(f"        missing: {', '.join(sorted(misses))}")
        print(f"        found:   {', '.join(sorted(found_ids))} ({ms:.0f}ms)")

    recall_pct = (recall_hits / recall_total * 100) if recall_total else 0
    print()
    print(f"  Recall: {recall_hits}/{recall_total} expected findings caught = {recall_pct:.0f}%")

    # --- Precision pass ---
    print()
    print("PRECISION — known-benign files (no CRITICAL expected)")
    print("-" * 50)
    fp_count = 0
    benign_total = 0
    for case in BENIGN:
        if not case["file"].exists():
            print(f"  SKIP  {case['label']} (file missing)")
            continue
        t0 = time.time()
        result = scan_target(case["file"])
        ms = (time.time() - t0) * 1000
        fps = [f for f in result.findings if f.severity.value in case["forbidden_severity"]]
        benign_total += 1
        if fps:
            fp_count += 1
            print(f"  FP    {case['label']}")
            for f in fps:
                print(f"        {f.id} {f.severity.value.upper()} {f.title}")
        else:
            all_ids = {f.id for f in result.findings}
            print(f"  OK    {case['label']}  ({', '.join(sorted(all_ids)) or 'clean'}, {ms:.0f}ms)")
        print()

    precision_pct = ((benign_total - fp_count) / benign_total * 100) if benign_total else 0
    print(f"  Precision: {benign_total - fp_count}/{benign_total} benign files with no CRITICAL = {precision_pct:.0f}%")
    print()

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Recall    (vulnerable caught):  {recall_pct:.0f}%  ({recall_hits}/{recall_total})")
    print(f"  Precision (benign no-CRITICAL):  {precision_pct:.0f}%  ({benign_total-fp_count}/{benign_total})")
    print()
    print("  HONEST DISCLAIMER: these numbers are on author-written fixtures.")
    print("  They measure that the scanner hasn't regressed, NOT that the FP")
    print("  rate on real-world code is acceptable. The real FP measurement")
    print("  requires the 100-repo corpus (Phase 1, needs network).")
    print("=" * 70)


if __name__ == "__main__":
    run()
