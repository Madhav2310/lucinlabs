#!/usr/bin/env python3
"""Regression snapshot — the safety net for every behavioral change.

WHY THIS EXISTS
---------------
The 520-test suite passes today and would not have caught either of the two
regressions this project actually shipped:

  * the benign corpus drifting from a published "0 false positives" to 11
    (README still claims 0; `build_benign_corpus.py` prints 11), and
  * `_require_evidence_on_unproven_agents` being loosened from witness-only to
    witness-OR-`source_line`, which let 3 AG-007 false positives through.

Unit tests assert on fixtures. Corpus behavior is what the published numbers are
made of, and nothing watched it. This module watches it.

WHAT IT CAPTURES
----------------
For every corpus target, a canonical, order-independent tuple per finding:

    (corpus, target, rule_id, severity, evidence_class, has_witness)

Deliberately NOT captured: descriptions, line numbers, witness *text*. Those churn
on harmless edits and would make the snapshot noisy enough to be ignored, which is
how safety nets die. Line numbers in particular move whenever a fixture is
reformatted.

THE ASYMMETRY THAT MAKES THIS SAFE
----------------------------------
Verified in this repo's own harnesses:
  * `recall_corpus.py` compares finding IDs only — `{f.id for f in scan.findings}`.
    It never reads severity.
  * `build_benign_corpus.py` counts CRITICAL/HIGH only.

So a *downgrade* leaves the FP metric and cannot leave the recall metric, while a
*dropped finding* can damage both. That asymmetry is the whole non-regression
strategy, and it is encoded in the exit rules below:

    HARD FAIL   finding disappeared        -> recall regression
    HARD FAIL   evidence_class downgraded  -> the severity ceiling is the product
    HARD FAIL   severity increased         -> false-positive risk
    ALLOWED     severity decreased         -> the intended precision lever
    ALLOWED     new finding appeared       -> reported loudly, never auto-failed;
                                              a new detector is supposed to do this

`--strict` additionally fails on new findings, for release gating.

Reproduce:
    python benchmarks/regression_snapshot.py --write baseline.json
    python benchmarks/regression_snapshot.py --compare baseline.json
"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).parent.parent
BENIGN_DIR = ROOT / "benchmarks" / "corpus"
RECALL_DIR = ROOT / "benchmarks" / "recall_corpus"
SKILL_MANIFEST = ROOT / "benchmarks" / "skill_corpus_manifest.json"
SKILL_DIR = ROOT / "benchmarks" / "skill_corpus"

SCHEMA_VERSION = 1


# --------------------------------------------------------------------------
# Target enumeration — one entry per scannable unit, per corpus.
# --------------------------------------------------------------------------
def _benign_targets() -> list[tuple[str, str, Path]]:
    if not BENIGN_DIR.exists():
        return []
    return [("benign", d.name, d) for d in sorted(BENIGN_DIR.iterdir()) if d.is_dir()]


def _recall_targets() -> list[tuple[str, str, Path]]:
    """Read the recall manifest so this stays in lockstep with recall_corpus.py."""
    manifest = RECALL_DIR / "manifest.json"
    if not manifest.exists():
        return []
    data = json.loads(manifest.read_text())
    cases = data["cases"] if isinstance(data, dict) and "cases" in data else data
    out = []
    for case in cases:
        target = RECALL_DIR / case["path"]
        if target.exists():
            out.append(("recall", case["id"], target))
    return out


def _skill_targets() -> list[tuple[str, str, Path]]:
    """Reuse the manifest's *counted* skill dirs — the same 337 the published
    numbers are computed over. Recomputing the diversity cap here would let the
    snapshot silently drift from `skill_corpus_report.py`."""
    if not SKILL_MANIFEST.exists():
        return []
    manifest = json.loads(SKILL_MANIFEST.read_text())
    out = []
    for entry in manifest.get("entries", []):
        if entry.get("status") != "ok":
            continue
        repo_dir = SKILL_DIR / entry["repo"].replace("/", "__")
        for rel in entry.get("counted_skill_dirs", entry.get("skill_dirs", [])):
            target = repo_dir / rel
            if target.exists():
                out.append(("skill", f"{entry['repo']}:{rel}", target))
    return out


def all_targets() -> list[tuple[str, str, Path]]:
    return _benign_targets() + _recall_targets() + _skill_targets()


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
def _scan_one(item: tuple[str, str, str]) -> dict:
    """Worker. Import inside so each process initialises cleanly."""
    corpus, target_id, path = item
    from lucin.scanner import scan_target

    try:
        scan = scan_target(Path(path))
    except Exception as e:  # a crash is a real regression, recorded not swallowed
        return {"corpus": corpus, "target": target_id, "error": f"{type(e).__name__}: {e}",
                "findings": []}

    rows = sorted({
        (f.id,
         f.severity.value if hasattr(f.severity, "value") else str(f.severity),
         f.evidence_class.value if hasattr(f.evidence_class, "value") else str(f.evidence_class),
         bool(f.witness))
        for f in scan.findings
    })
    return {
        "corpus": corpus,
        "target": target_id,
        "findings": [
            {"id": i, "severity": s, "evidence_class": e, "has_witness": w}
            for i, s, e, w in rows
        ],
    }


def build_snapshot() -> dict:
    targets = all_targets()
    if not targets:
        print("ERROR: no corpus targets found. Build the corpora first:", file=sys.stderr)
        print("  python benchmarks/build_benign_corpus.py", file=sys.stderr)
        print("  python benchmarks/build_skill_corpus.py", file=sys.stderr)
        sys.exit(2)

    payload = [(c, t, str(p)) for c, t, p in targets]
    with ProcessPoolExecutor() as pool:
        results = list(pool.map(_scan_one, payload, chunksize=4))

    counts: dict[str, int] = {}
    for r in results:
        counts[r["corpus"]] = counts.get(r["corpus"], 0) + 1

    return {
        "schema_version": SCHEMA_VERSION,
        "target_counts": counts,
        "entries": sorted(results, key=lambda r: (r["corpus"], r["target"])),
    }


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_EVIDENCE_ORDER = {"posture": 0, "inferred": 1, "witnessed": 2}


def _index(snapshot: dict) -> dict[tuple[str, str], dict]:
    return {(e["corpus"], e["target"]): e for e in snapshot["entries"]}


def compare(base: dict, cur: dict, strict: bool = False) -> int:
    """Return a process exit code. 0 = no regression."""
    base_idx, cur_idx = _index(base), _index(cur)

    disappeared_targets, disappeared, sev_up, sev_down, ev_down, new, errors = (
        [], [], [], [], [], [], [])

    for key, base_entry in base_idx.items():
        cur_entry = cur_idx.get(key)
        if cur_entry is None:
            disappeared_targets.append(key)
            continue
        if cur_entry.get("error") and not base_entry.get("error"):
            errors.append((key, cur_entry["error"]))

        b = {f["id"]: f for f in base_entry["findings"]}
        c = {f["id"]: f for f in cur_entry["findings"]}

        for rid, bf in b.items():
            cf = c.get(rid)
            if cf is None:
                disappeared.append((key, rid, bf["severity"]))
                continue
            bs = _SEVERITY_ORDER.get(bf["severity"], -1)
            cs = _SEVERITY_ORDER.get(cf["severity"], -1)
            if cs > bs:
                sev_up.append((key, rid, bf["severity"], cf["severity"]))
            elif cs < bs:
                sev_down.append((key, rid, bf["severity"], cf["severity"]))
            be = _EVIDENCE_ORDER.get(bf["evidence_class"], -1)
            ce = _EVIDENCE_ORDER.get(cf["evidence_class"], -1)
            if ce < be:
                ev_down.append((key, rid, bf["evidence_class"], cf["evidence_class"]))

        for rid, cf in c.items():
            if rid not in b:
                new.append((key, rid, cf["severity"]))

    def _show(title, rows, fmt, limit=15):
        if not rows:
            return
        print(f"\n{title}  ({len(rows)})")
        for r in rows[:limit]:
            print("   " + fmt(r))
        if len(rows) > limit:
            print(f"   ... and {len(rows) - limit} more")

    print("=" * 78)
    print("REGRESSION SNAPSHOT COMPARISON")
    print("=" * 78)
    print(f"  baseline targets: {base['target_counts']}")
    print(f"  current  targets: {cur['target_counts']}")

    _show("[HARD FAIL] findings that DISAPPEARED (recall regression)", disappeared,
          lambda r: f"{r[0][0]}/{r[0][1]}: {r[1]} ({r[2]})")
    _show("[HARD FAIL] severity INCREASED (false-positive risk)", sev_up,
          lambda r: f"{r[0][0]}/{r[0][1]}: {r[1]} {r[2]} -> {r[3]}")
    _show("[HARD FAIL] evidence_class DOWNGRADED", ev_down,
          lambda r: f"{r[0][0]}/{r[0][1]}: {r[1]} {r[2]} -> {r[3]}")
    _show("[HARD FAIL] targets missing from current run", disappeared_targets,
          lambda r: f"{r[0]}/{r[1]}")
    _show("[HARD FAIL] new scan errors", errors, lambda r: f"{r[0][0]}/{r[0][1]}: {r[1]}")
    _show("[ok] severity DECREASED (the intended precision lever)", sev_down,
          lambda r: f"{r[0][0]}/{r[0][1]}: {r[1]} {r[2]} -> {r[3]}")
    _show("[review] NEW findings", new,
          lambda r: f"{r[0][0]}/{r[0][1]}: {r[1]} ({r[2]})")

    hard = (len(disappeared) + len(sev_up) + len(ev_down)
            + len(disappeared_targets) + len(errors))

    print("\n" + "-" * 78)
    print(f"  disappeared={len(disappeared)}  severity_up={len(sev_up)}  "
          f"evidence_down={len(ev_down)}  missing_targets={len(disappeared_targets)}  "
          f"new_errors={len(errors)}")
    print(f"  severity_down={len(sev_down)}  new={len(new)}")

    if hard:
        print(f"\n  RESULT: REGRESSION — {hard} hard failure(s).")
        print("  Per PHASE_6_PLAN.md §3: the deliverable is the failed number and a")
        print("  re-plan, never a change that makes the number pass.")
        return 1
    if strict and new:
        print(f"\n  RESULT: FAIL (--strict) — {len(new)} new finding(s).")
        return 1
    print("\n  RESULT: NO REGRESSION.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--write", metavar="PATH", help="capture a snapshot to PATH")
    ap.add_argument("--compare", metavar="PATH", help="compare current state against PATH")
    ap.add_argument("--strict", action="store_true", help="also fail on NEW findings")
    args = ap.parse_args()

    if not args.write and not args.compare:
        ap.error("pass --write PATH or --compare PATH")

    snapshot = build_snapshot()
    total = sum(len(e["findings"]) for e in snapshot["entries"])
    print(f"scanned {len(snapshot['entries'])} targets, {total} findings "
          f"({snapshot['target_counts']})")

    if args.write:
        Path(args.write).write_text(json.dumps(snapshot, indent=1, sort_keys=True))
        print(f"wrote {args.write}")

    if args.compare:
        base = json.loads(Path(args.compare).read_text())
        if base.get("schema_version") != SCHEMA_VERSION:
            print(f"ERROR: baseline schema v{base.get('schema_version')} != "
                  f"v{SCHEMA_VERSION}; recapture the baseline.", file=sys.stderr)
            return 2
        return compare(base, snapshot, strict=args.strict)
    return 0


if __name__ == "__main__":
    sys.exit(main())
