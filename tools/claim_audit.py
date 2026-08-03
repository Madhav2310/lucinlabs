#!/usr/bin/env python3
"""claim_audit.py — the launch-gate that keeps public claims honest.

Scans PUBLIC-FACING artifacts (README, docs/, plan/content/, the landing page)
for the specific dishonesty patterns our audits caught, and fails CI on any hit.
It deliberately does NOT scan internal planning/audit docs (plan/00..70,
DEFINITION_OF_DONE.md, PROGRESS.md, CORPUS_LEARNINGS.md) — those legitimately
discuss number *history* ("was 59%", "the fake 5/5") and would false-positive.

Rules (each maps to a real finding from the 5-component audit, 2026-07-29):
  R1  no self-claim of "sub-ms" latency        (measured ~5 ms/event; VIOLATED ~12x)
  R2  no "first/only/nobody-else" + info-flow   (the moat is CONTESTED — retire it)
  R3  no un-denominated "100% recall"           (n must be shown; blog had n=3 hidden)
  R4  no known-STALE figures in public copy     (59% / 296 tests / 26 detectors / 29-49 / 41% FN / "0% on SSRF/deser")
  R5  "0% false positive" must carry the reframe qualifier
        (it's "0 findings outside a documented per-repo known-capability allowlist",
         NOT a per-file zero-FP proof — audit-3 smoking gun)

Usage:  python tools/claim_audit.py         # exit 1 on any violation
        python tools/claim_audit.py --list  # show the files scanned and exit 0

NOTE: this gate is EXPECTED to fail until the Wave-2 doc sweep (H1/H2) runs — that
is its purpose: it defines "done" for the sweep. Every number it enforces is the
current reproducible value from DEFINITION_OF_DONE.md §1.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Public, launch-facing surfaces only.
PUBLIC_GLOBS = [
    "README.md",
    # LEARN.md quotes almost every number the project has and is pushed publicly, so it
    # is exactly the file the gate must police. It was omitted until 2026-07-30 and had
    # accumulated a stale test count, a stale finding count and an unqualified corpus claim.
    "LEARN.md",
    "HANDOFF.md",
    "docs/*.md",
    "site/content/*.md",
]

# ---- rules: (id, description, compiled regex, optional allow-if-line-contains) ----
Rule = tuple[str, str, re.Pattern, tuple[str, ...]]

RULES: list[Rule] = [
    ("R1", "self-claim of 'sub-ms' latency (measured ~5 ms/event)",
     re.compile(r"sub-?(?:ms|millisecond)", re.I),
     ("not sub-ms", "corrected", "microsoft", "agt", "~5 ms", "not sub")),
    ("R2", "contested-moat NOVELTY claim ('the only tool/vendor that does IFC') — the moat is contested",
     # Match genuine market/novelty claims only — NOT "only fires when taint…".
     # (a) first / no-one-else / no-other-vendor near info-flow;
     # (b) "the only <tool|scanner|vendor|product|platform|open-source ...>" near info-flow.
     re.compile(
         r"(\b(?:first|no one else|nobody else|no other (?:tool|vendor|scanner|product|platform))\b"
         r"[^.\n]{0,60}(?:information[- ]?flow|\bIFC\b|taint analysis|flow analysis))"
         r"|(\bthe only\b[^.\n]{0,20}(?:tool|scanner|vendor|product|platform|open[- ]?source)"
         r"[^.\n]{0,60}(?:information[- ]?flow|\bIFC\b|taint|flow analysis))", re.I),
     ()),
    ("R3", "un-denominated '100% recall' (show n / a fraction)",
     re.compile(r"100\s*%\s*recall|recall[^.\n]{0,15}\b100\s*%", re.I),
     ()),  # denominator check handled specially below
    ("R4", "known-STALE public figure (use current: 76% recall / 20.5-31.5% broad "
           "precision / 517 tests / 27 active detectors)",
     # 58% was the SECOND withdrawn broad-precision figure (59% was the first) — it
     # replaced 59% in some docs, was itself withdrawn as train-on-test, and survived
     # in HANDOFF.md/PROGRESS.md for days because this exact rule never learned about
     # it. That is the failure mode this rule exists to prevent; do not let it repeat
     # with whatever number replaces 20.5-31.5% next — update this list the same day.
     re.compile(r"\b59\s*%|\b58\s*%|\b296\s+test|\b26\s+detector"
                r"|\b29/49\b|\b41\s*%\s*FN|0\s*%\s*on\s*SSRF|\b25\s+active"
                r"|\b(?:433|445|473|507)\s+(?:passed|passing|tests?\b)"
                r"|test suite[^.\n]{0,25}\b(?:433|445|473|507)\b", re.I),
     # Historical/retrospective framing ("was 58%", "the original 58%", "not by N tests")
     # and unrelated numeric contexts (CSS percentages in mockups) are not live claims.
     # docs/methodology.md §1b is the one file whose actual job is narrating this
     # specific history ("neither 58% nor X% may be published", "the sin that produced
     # the 58%") — those lines are the correction, not a violation of it.
     ("withdrawn", "was ", "the original", "not by", "style=", "height:", "width:",
      "background", "train-on-test", "do not quote", "may be published",
      "the sin that produced", "hand-adjudicated sample")),
    ("R5", "'0 (%) false positive' without the honest adjudication/allowlist qualifier "
           "(the raw scan fires on test/example files; the number is post-adjudication)",
     # % is OPTIONAL — bare "0 FP" / "0 confirmed FP" must ALSO carry the qualifier.
     # The (?<![\d.]) lookbehind matters: without it this matched the trailing zero of
     # "150 false positives out of 330" — a figure we quote about ANOTHER tool — and
     # demanded we qualify someone else's number. Same defect existed in
     # site/check_site.py and is fixed identically there; it is the "no word boundary"
     # error class this project keeps finding in its own detectors.
     re.compile(r"(?<![\d.])0(?:\.0)?\s*%?\s*(?:confirmed |adjudicated )?(?:false[- ]?positive|FP)s?\b", re.I),
     ("allowlist", "known-capability", "known capability", "outside a",
      "per-repo", "documented", "adjudicated", "clean", "synthetic")),
    ("R6", "legacy placeholder ('AgentGuard'/'agentguard'/'<name>') — rename to Lucin incomplete",
     re.compile(r"agentguard|<name>", re.I),
     ()),
]

DENOM_NEAR = re.compile(r"\d+\s*/\s*\d+|\bn\s*=\s*\d+|out of \d+")


def _iter_files():
    for g in PUBLIC_GLOBS:
        yield from sorted(ROOT.glob(g))


def audit() -> list[tuple[str, int, str, str, str]]:
    hits: list[tuple[str, int, str, str, str]] = []
    for path in _iter_files():
        rel = str(path.relative_to(ROOT))
        for i, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            low = line.lower()
            for rid, desc, rx, allow in RULES:
                m = rx.search(line)
                if not m:
                    continue
                if any(a in low for a in allow):
                    continue
                # R3: only a violation if NO denominator is near on the same line.
                if rid == "R3" and DENOM_NEAR.search(line):
                    continue
                hits.append((rel, i, rid, desc, line.strip()[:140]))
    return hits


def main(argv: list[str]) -> int:
    if "--list" in argv:
        for p in _iter_files():
            print(p.relative_to(ROOT))
        return 0
    hits = audit()
    print("=" * 78)
    print("CLAIM AUDIT — public-facing honesty gate")
    print("=" * 78)
    if not hits:
        print("PASS — no banned patterns or stale figures in public artifacts.")
        return 0
    by_rule: dict[str, int] = {}
    for rel, ln, rid, desc, snip in hits:
        by_rule[rid] = by_rule.get(rid, 0) + 1
        print(f"  [{rid}] {rel}:{ln}\n      {desc}\n      > {snip}")
    print("-" * 78)
    summary = ", ".join(f"{k}={v}" for k, v in sorted(by_rule.items()))
    print(f"FAIL — {len(hits)} violation(s): {summary}")
    print("(Expected to fail until the Wave-2 doc sweep reconciles numbers — "
          "this gate defines 'done' for that sweep.)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
