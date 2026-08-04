#!/usr/bin/env python3
"""PHASE_6_PLAN.md §5.2.3 / COVERAGE_AND_BUILD_PLAN.md §8.5 falsification test.

"Take 50 corpus skills that genuinely need dangerous capabilities. Measure how many
declare them. If most legitimate dangerous skills declare nothing either, the
discriminator collapses and Phase 1 needs rethinking. This single measurement decides
whether Phase 1 works."

Deliberately does NOT reuse `skill_chain.py::_is_declared` as-is: that function's steps 2
and 3 (dependency/stdlib-import "implicit declaration") make an observed capability count
as "declared" merely because it was observed via a particular code path — which is
circular for exactly this test (it would make legitimate-but-undeclared skills look
falsely compliant). This script checks only the two channels a human author actually
fills in: `allowed-tools` (real, wired) and `compatibility` (mentioned in the detector's
own fix_suggestion text but, per this review, never actually checked by `_is_declared` —
a separate bug, noted below). Testing both gives the honest answer to "does declaration
exist as a signal at all," with and without fixing that bug.
"""
import json
import re
from pathlib import Path

DANGEROUS = {"remote_fetch", "decode", "deserialize", "exec", "egress", "credential_read"}

MANIFEST_PATH = Path("benchmarks/skill_corpus_manifest.json")
CORPUS_DIR = Path("benchmarks/skill_corpus")

_ALLOWED_TOOLS_KEYWORDS = {
    "remote_fetch": ["curl", "wget", "network", "http", "fetch", "axios", "request", "webfetch"],
    "exec": ["bash", "python", "exec", "shell", "node", "child_process"],
    "egress": ["curl", "network", "internet", "fetch", "upload", "aws", "gcp"],
    "credential_read": ["env", "secret", "credential", "dotenv", "token"],
    "decode": ["decode", "deserialize", "parse", "yaml", "pickle", "json"],
    "deserialize": ["decode", "deserialize", "parse", "yaml", "pickle", "json"],
}


def _iter_counted_skill_dirs():
    manifest = json.loads(MANIFEST_PATH.read_text())
    for entry in manifest["entries"]:
        if entry.get("status") != "ok":
            continue
        repo_dir = CORPUS_DIR / entry["repo"].replace("/", "__")
        for rel in entry.get("counted_skill_dirs", entry.get("skill_dirs", [])):
            yield entry["repo"], repo_dir / rel


def _declared_via_allowed_tools(cap: str, declared_capabilities: list[str]) -> bool:
    declared_str = " ".join(declared_capabilities).lower()
    return any(k in declared_str for k in _ALLOWED_TOOLS_KEYWORDS.get(cap, []))


def _declared_via_compatibility(cap: str, compatibility_text: str) -> bool:
    if not compatibility_text:
        return False
    text = compatibility_text.lower()
    return any(k in text for k in _ALLOWED_TOOLS_KEYWORDS.get(cap, []))


def main():
    from lucin.parsers.skill_parser import parse_skill

    dangerous_skills = []
    for repo, skill_dir in _iter_counted_skill_dirs():
        agents = parse_skill(skill_dir)
        if not agents or not agents[0].skill:
            continue
        skill = agents[0].skill
        observed_dangerous = {c.value for c in skill.observed_capabilities} & DANGEROUS
        if observed_dangerous:
            compat_text = str(skill.frontmatter.get("compatibility", ""))
            dangerous_skills.append((repo, skill_dir.name, skill, observed_dangerous, compat_text))

    sample = dangerous_skills[:50]
    print(f"Found {len(dangerous_skills)} skills with >=1 dangerous observed capability; testing first {len(sample)}.\n")

    declared_via_at_only = 0    # allowed-tools only (the channel that actually works today)
    declared_via_at_or_compat = 0  # allowed-tools OR compatibility (if the bug were fixed)
    fully_undeclared = 0

    per_skill_rows = []
    for repo, name, skill, observed_dangerous, compat_text in sample:
        at_hits = {cap for cap in observed_dangerous if _declared_via_allowed_tools(cap, skill.declared_capabilities)}
        compat_hits = {cap for cap in observed_dangerous if _declared_via_compatibility(cap, compat_text)}
        any_hits = at_hits | compat_hits

        if at_hits:
            declared_via_at_only += 1
        if any_hits:
            declared_via_at_or_compat += 1
        if not any_hits:
            fully_undeclared += 1

        per_skill_rows.append((repo, name, sorted(observed_dangerous), sorted(at_hits), sorted(compat_hits)))

    n = len(sample)
    print("=" * 70)
    print(f"RESULT — of {n} skills that genuinely use a dangerous capability:")
    print("=" * 70)
    print(f"  Declare it via allowed-tools (the channel that actually works today): "
          f"{declared_via_at_only}/{n} ({declared_via_at_only/n*100:.1f}%)" if n else "  (no dangerous skills found)")
    if n:
        print(f"  Declare it via allowed-tools OR compatibility (if that bug were fixed): "
              f"{declared_via_at_or_compat}/{n} ({declared_via_at_or_compat/n*100:.1f}%)")
        print(f"  Fully undeclared through EITHER channel: "
              f"{fully_undeclared}/{n} ({fully_undeclared/n*100:.1f}%)")

    print("\nPer-skill detail (first 20):")
    for repo, name, observed, at, compat in per_skill_rows[:20]:
        status = "DECLARED" if (at or compat) else "undeclared"
        print(f"  [{status:10s}] {name} ({repo}): observed={observed} allowed-tools-hit={at} compat-hit={compat}")

    print(f"\n{'='*70}")
    if n and fully_undeclared / n > 0.5:
        print("CONCLUSION: most legitimate dangerous skills declare NOTHING through either channel.")
        print("The undeclaredness discriminator does not separate malicious from legitimate-dangerous —")
        print("it fires on almost everything. This CONFIRMS §2.3/§8.5: undeclaredness is not a viable")
        print("standalone discriminator. PHASE_6_PLAN.md §5.3 option (b) (real flow analysis) or (c)")
        print("(kill the flagship, ship capability disclosure only) — not the current chain rule as-is.")
    elif n:
        print(f"CONCLUSION: {declared_via_at_or_compat/n*100:.1f}% of legitimate dangerous skills DO declare —")
        print("undeclaredness has some separating power, but re-examine whether it's precise enough")
        print("given the corpus's overall low declaration prevalence (see skill_corpus_report.py).")

    print("\nBUG NOTED (not fixed here): `skill_chain.py::_is_declared` never checks `compatibility` "
          "despite its own fix_suggestion text telling authors to use it. The gap between the two "
          "lines above is exactly what fixing that bug would buy.")
    print("\nReproduce: python benchmarks/build_skill_corpus.py && python benchmarks/skill_falsification_test.py")


if __name__ == "__main__":
    main()
