"""Held-out RECALL corpus — measure Lucin's TRUE detection recall + false-
negative rate on distinct vulnerable agents, per vuln class.

    python benchmarks/recall_corpus.py            # full run
    python benchmarks/recall_corpus.py --json      # machine-readable summary

Why this file exists (anti-slop, grounded in plan/60_core_engine_roadmap.md §2.1):
SCAN's *precision* is real and reproducible (0% FP / 52 repos,
build_benign_corpus.py). Precision without a real recall denominator is half a
validation. The previous recall claim — "100% recall (5/5)" — was measured on 5
cases of which TWO were the *same* smolagents text_to_sql example (original +
an agentops copy), i.e. ~4 distinct vulns across only 2 vuln classes, with NO
measurable false-negative rate. A hostile reviewer reads that as meaningless.

This corpus replaces it with a real, held-out, self-contained set of DISTINCT
vulnerable agents across many vuln classes:
  - `origin: "real"`  = verbatim third-party code we did NOT write (cached under
    benchmarks/recall_corpus/<class>/<case>/; provenance/URL in manifest.json).
  - `origin: "constructed"` = author-written, CLEARLY LABELED, modeling a
    documented vuln class / CVE (cited in the file header + manifest).

A case is DETECTED (a HIT) iff `scan_target` emits at least one finding id in
the case's `expected` set (the ids that represent catching THAT vuln class).
Misses are reported with a reason DERIVED FROM THE LIVE REGISTRY (see
`_registered_rule_ids`), which separates two very different admissions:

  * "no registered detector emits X" — a genuine coverage gap. Today only
    path traversal: AG-PATH-TRAVERSAL is built and unit-tested but deliberately
    NOT registered, because the benign corpus contains byte-identical legitimate
    file tools (precision over recall).
  * "X IS registered but declined this shape" — a deliberate precision
    trade-off. Today SSRF (1/6) and container escape: `detect_ssrf` flags only
    taint in the URL's scheme/host position, because a bare `requests.get(url)`
    is indistinguishable from the many benign `fetch_url`/`visit_webpage` tools
    in the corpus (see `ssrf.py::_host_controlled`).

The manifest's per-case `class_has_detector` field is NO LONGER trusted for this:
it still says `false` for `ssrf` and `insecure_deserialization` while both
detectors are registered, and AG-DESERIALIZE in fact fires on 6/6 of its cases.
A hand-maintained field describing the registry will always drift from it.

We do NOT tune to hit a number: the measured recall is published as-is (it is
well under 100%), because that honesty is the deliverable.

Reproducible + offline: all cases are cached in-repo (no download needed).
Scanning is parallelized across CPUs (scan is CPU-bound AST work).
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

RC = ROOT / "benchmarks" / "recall_corpus"
MANIFEST = RC / "manifest.json"


def _registered_rule_ids() -> set[str]:
    """Rule IDs a REGISTERED detector can actually emit.

    The registry is the source of truth for "what runs" (CLAUDE.md), so the
    question "does a detector exist for this class?" must be answered from it —
    never from a hand-maintained manifest field, which goes stale silently.

    It went stale exactly this way: `manifest.json` still carries
    `class_has_detector: false` for `ssrf` and `insecure_deserialization` even
    though `detect_ssrf` and `detect_insecure_deserialization` are both
    registered. AG-DESERIALIZE fires on 6/6 of its cases while the manifest
    claimed no detector existed, and the five SSRF misses were reported as
    "no detector for class" when the real reason is that `detect_ssrf`
    deliberately declines the bare-parameter shape (ssrf.py, `_host_controlled`)
    to protect precision. Both statements are published numbers; one was false.
    """
    import inspect
    import re

    from lucin.detectors import CROSS_AGENT_DETECTORS, PER_AGENT_DETECTORS

    ids: set[str] = set()
    for fn in list(PER_AGENT_DETECTORS) + list(CROSS_AGENT_DETECTORS):
        module = inspect.getmodule(fn)
        if module is None:
            continue
        try:
            src = inspect.getsource(module)
        except (OSError, TypeError):
            continue
        ids.update(re.findall(r'id="(AG-[A-Z0-9-]+)"', src))
    return ids


def _scan_one(case: dict) -> dict:
    """Worker: scan one case dir, return the finding ids + hit/miss verdict."""
    # Import inside the worker so each process initialises cleanly.
    from lucin.scanner import scan_target
    target = RC / case["path"]
    result = {"id": case["id"], "vuln_class": case["vuln_class"],
              "origin": case["origin"], "expected": case["expected"],
              "class_has_detector": case["class_has_detector"]}
    if not target.exists():
        result.update(status="SKIP", found=[], detected=False)
        return result
    try:
        scan = scan_target(target)
        found = sorted({f.id for f in scan.findings})
    except Exception as e:  # a scan crash is a real miss, recorded honestly
        result.update(status="ERROR", found=[f"{type(e).__name__}: {e}"],
                      detected=False)
        return result
    detected = any(e in found for e in case["expected"])
    result.update(status="OK", found=found, detected=detected)
    return result


def main() -> int:
    as_json = "--json" in sys.argv
    manifest = json.loads(MANIFEST.read_text())
    cases = manifest["cases"]

    with Pool(min(cpu_count(), 8)) as pool:
        results = pool.map(_scan_one, cases)

    # ---- aggregate ----
    by_class: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by_class[r["vuln_class"]].append(r)

    measured = [r for r in results if r["status"] in ("OK", "ERROR")]
    skipped = [r for r in results if r["status"] == "SKIP"]
    hits = [r for r in measured if r["detected"]]
    recall = len(hits) / len(measured) if measured else 0.0

    real = [r for r in results if r["origin"] == "real"]
    constructed = [r for r in results if r["origin"] == "constructed"]
    real_meas = [r for r in real if r["status"] in ("OK", "ERROR")]
    real_hits = [r for r in real_meas if r["detected"]]

    if not as_json:
        print("=" * 78)
        print("HELD-OUT RECALL CORPUS — true detection recall + FN rate, per vuln class")
        print("=" * 78)
        print(f"{'vuln class':<26}{'detected/total':>16}{'recall':>9}  det?")
        print("-" * 78)
        worst = None
        for cls in sorted(by_class):
            rs = by_class[cls]
            m = [r for r in rs if r["status"] in ("OK", "ERROR")]
            h = [r for r in m if r["detected"]]
            cr = len(h) / len(m) if m else 0.0
            # Derived (self-maintaining): a class effectively has a working
            # detector iff at least one of its cases is detected. Avoids the
            # stale-manifest bug where a class kept "(NO DETECTOR)" after a
            # detector was added (e.g. AG-DESERIALIZE → insecure_deserialization).
            hasdet = any(r["detected"] for r in m)
            flag = "" if hasdet else "  (NO DETECTOR)"
            print(f"{cls:<26}{f'{len(h)}/{len(m)}':>16}{cr:>8.0%}{flag}")
            if worst is None or cr < worst[1]:
                worst = (cls, cr)
        print("-" * 78)
        print(f"{'OVERALL':<26}{f'{len(hits)}/{len(measured)}':>16}{recall:>8.0%}")
        print(f"  false-negative rate: {1 - recall:.0%}  "
              f"({len(measured) - len(hits)}/{len(measured)} distinct vulns missed)")
        print(f"  distinct vulns: {len(measured)}   vuln classes: {len(by_class)}"
              f"   (skipped: {len(skipped)})")
        print(f"  provenance split: {len(real)} real (third-party) / "
              f"{len(constructed)} constructed (labeled)")
        rr = len(real_hits) / len(real_meas) if real_meas else 0.0
        print(f"  recall on REAL third-party cases only: "
              f"{len(real_hits)}/{len(real_meas)} = {rr:.0%}")
        if worst:
            print(f"  worst-recall class: {worst[0]} ({worst[1]:.0%})")

        misses = [r for r in measured if not r["detected"]]
        print("-" * 78)
        print("  FALSE NEGATIVES (real vulns Lucin does NOT flag) — honest list:")
        registered = _registered_rule_ids()
        for r in sorted(misses, key=lambda x: x["id"]):
            # Derived from the live registry, never from the manifest field.
            # Distinguishes "we ship nothing for this class" (a coverage gap)
            # from "the detector is registered and declined this shape"
            # (a deliberate precision trade-off) — very different admissions.
            covered = sorted(set(r["expected"]) & registered)
            if not covered:
                why = f"no registered detector emits {r['expected']}"
            else:
                why = (f"got {r['found'] or '(none)'}, expected {r['expected']} "
                       f"— {','.join(covered)} IS registered but declined this shape")
            print(f"    MISS  {r['id']}  [{r['origin']}]  {why}")
        print("=" * 78)
        print("Reproduce: python benchmarks/recall_corpus.py   "
              "(cases + provenance in benchmarks/recall_corpus/manifest.json)")

    summary = {
        "distinct_vulns": len(measured),
        "vuln_classes": len(by_class),
        "hits": len(hits),
        "recall": round(recall, 4),
        "false_negative_rate": round(1 - recall, 4),
        "real": len(real), "constructed": len(constructed),
        "recall_real_only": round(len(real_hits) / len(real_meas), 4) if real_meas else 0,
        "skipped": len(skipped),
        "per_class": {
            cls: {
                "detected": sum(1 for r in by_class[cls] if r["detected"]),
                "total": sum(1 for r in by_class[cls] if r["status"] in ("OK", "ERROR")),
                "class_has_detector": by_class[cls][0]["class_has_detector"],
            } for cls in sorted(by_class)
        },
    }
    if as_json:
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
