#!/usr/bin/env python3
"""PHASE_6_PLAN.md §5.2.4 / COVERAGE_AND_BUILD_PLAN.md §8.1 — actually differential.

The previous version of this script only ran Lucin over a single 18-skill corpus — not
differential at all (see PHASE_6_PLAN.md §2.1). Declaration prevalence and the benign-noise
metric now live in `build_skill_corpus.py` + `skill_corpus_report.py`, where they belong
(§5.2.2). This script does the one thing §8.1 actually asked for: run Lucin and a second,
independent scanner over the same third-party corpus and report where they disagree.

Second scanner: **NVIDIA/SkillSpector** (Apache-2.0, `--no-llm` mode — static-only, matches
this project's no-LLM-judge stance, never executes the scanned skill). Snyk Agent Scan was
evaluated and is NOT wired in here: its CLI is architected around live discovery of installed
MCP client configs (`snyk-agent-scan scan [CONFIG_FILE]`), not batch-scanning an arbitrary
third-party directory — pointing it directly at a cloned skill directory exits 1 with no
output. Wiring it would need either mimicking a client's on-disk skill-discovery convention
under a fake HOME, or a different invocation this review did not find in the time available.
Documented as a known gap, not silently dropped — see PHASE_6_PLAN.md §5.2.4.

Adjudication (§9.6's protocol — two independent raters, {TP, FP, unadjudicable} labels,
published inter-rater agreement) is NOT run here: that requires either two people or two
genuinely independent reviewers, and a single agent session cannot honestly produce an
"inter-rater agreement" number by adjudicating its own disagreement matrix. This script
produces the disagreement matrix only, and leaves adjudication as an explicit next step.
"""
import argparse
import json
import shutil
import subprocess
import time
from pathlib import Path

MANIFEST_PATH = Path("benchmarks/skill_corpus_manifest.json")
CORPUS_DIR = Path("benchmarks/skill_corpus")
OUT_PATH = Path("benchmarks/differential_scan_results.json")

DANGEROUS_CAPS = {"remote_fetch", "decode", "deserialize", "exec", "egress", "credential_read"}


def _iter_counted_skill_dirs():
    manifest = json.loads(MANIFEST_PATH.read_text())
    for entry in manifest["entries"]:
        if entry.get("status") != "ok":
            continue
        repo_dir = CORPUS_DIR / entry["repo"].replace("/", "__")
        for rel in entry.get("counted_skill_dirs", entry.get("skill_dirs", [])):
            yield entry["repo"], repo_dir / rel


def run_lucin(skill_dir: Path) -> list[dict]:
    from lucin.scanner import scan_target
    result = scan_target(skill_dir)
    return [{"id": f.id, "severity": f.severity.value, "title": f.title} for f in result.findings]


def run_skillspector(skill_dir: Path, timeout: int = 30) -> list[dict] | None:
    """Returns None on a scan error (recorded separately from '0 findings')."""
    skillspector = shutil.which("skillspector")
    if skillspector is None:
        return None
    try:
        r = subprocess.run(
            [skillspector, "scan", str(skill_dir), "--no-llm", "--format", "json"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None
    if r.returncode not in (0, 1):  # SkillSpector uses non-zero exit when issues are found
        return None
    try:
        data = json.loads(r.stdout)
    except Exception:
        return None
    return [
        {"id": i.get("id"), "category": i.get("category"), "severity": i.get("severity")}
        for i in data.get("issues", [])
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None, help="Cap the number of skills scanned (default: full corpus).")
    ap.add_argument("--skillspector-timeout", type=int, default=30)
    args = ap.parse_args()

    if shutil.which("skillspector") is None:
        print("⚠️  `skillspector` not on PATH — install with:")
        print("    uv tool install git+https://github.com/NVIDIA/SkillSpector.git")
        print("Proceeding with Lucin-only results (no differential comparison possible).\n")

    skills = list(_iter_counted_skill_dirs())
    if args.limit:
        skills = skills[: args.limit]
    print(f"Differential scan over {len(skills)} skills (Lucin vs SkillSpector, --no-llm)\n")

    both_flag = []            # both scanners raised >=1 finding
    lucin_only = []            # Lucin flagged, SkillSpector clean — candidate differentiator
    skillspector_only = []     # SkillSpector flagged, Lucin missed — candidate false-negative
    neither_flags = []         # both clean
    skillspector_errors = 0

    t_start = time.time()
    for i, (repo, skill_dir) in enumerate(skills):
        lucin_findings = run_lucin(skill_dir)
        ss_findings = run_skillspector(skill_dir, timeout=args.skillspector_timeout)

        lucin_has = len(lucin_findings) > 0
        if ss_findings is None:
            skillspector_errors += 1
            continue
        ss_has = len(ss_findings) > 0

        row = {"repo": repo, "skill": skill_dir.name, "lucin": lucin_findings, "skillspector": ss_findings}
        if lucin_has and ss_has:
            both_flag.append(row)
        elif lucin_has and not ss_has:
            lucin_only.append(row)
        elif ss_has and not lucin_has:
            skillspector_only.append(row)
        else:
            neither_flags.append(row)

        if (i + 1) % 25 == 0:
            print(f"  ...{i+1}/{len(skills)} scanned ({time.time()-t_start:.0f}s elapsed)")

    scanned = len(both_flag) + len(lucin_only) + len(skillspector_only) + len(neither_flags)
    print(f"\n{'='*70}\nDISAGREEMENT MATRIX  ({scanned} skills compared, {skillspector_errors} SkillSpector errors excluded)\n{'='*70}")
    print(f"  Both flag:              {len(both_flag)}")
    print(f"  Lucin-only (candidate differentiator): {len(lucin_only)}")
    print(f"  SkillSpector-only (candidate FN for Lucin): {len(skillspector_only)}")
    print(f"  Neither flags:          {len(neither_flags)}")

    if skillspector_only:
        print("\nSkillSpector caught, Lucin missed (first 15):")
        for row in skillspector_only[:15]:
            cats = sorted({i["category"] for i in row["skillspector"] if i.get("category")})
            sevs = sorted({i["severity"] for i in row["skillspector"] if i.get("severity")}, reverse=True)
            print(f"  {row['skill']} ({row['repo']}): {cats} [{', '.join(sevs)}]")

    if lucin_only:
        print("\nLucin caught, SkillSpector missed (first 15):")
        for row in lucin_only[:15]:
            ids = sorted({f["id"] for f in row["lucin"]})
            print(f"  {row['skill']} ({row['repo']}): {ids}")

    with open(OUT_PATH, "w") as f:
        json.dump({
            "scanned": scanned, "skillspector_errors": skillspector_errors,
            "both_flag": both_flag, "lucin_only": lucin_only,
            "skillspector_only": skillspector_only, "neither_flags": neither_flags,
        }, f, indent=2)
    print(f"\nFull results: {OUT_PATH}")
    print("Adjudication (§9.6 protocol — two independent raters, published agreement) is NOT run here.")
    print("Reproduce: python benchmarks/build_skill_corpus.py && python benchmarks/differential_scan.py")


if __name__ == "__main__":
    main()
