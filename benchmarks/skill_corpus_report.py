#!/usr/bin/env python3
"""PHASE_6_PLAN.md §5.2.2 — report the numbers that were never measured.

No detector changes happen here (§5.2's own rule). This only reads
`benchmarks/skill_corpus_manifest.json` (built by `build_skill_corpus.py`) and reports,
for every counted skill dir: declaration prevalence (`allowed-tools`/`compatibility`),
script language distribution, skills with executables outside `scripts/`, `references/`
depth, per-rule fire rate, the benign-noise metric (§5.2 of the build plan — median
findings at ANY severity + % zero-finding, which the old CRITICAL/HIGH-only FP metric
hides), and scan latency (p50/p95).

`anthropics/skills` gets its own CRITICAL/HIGH count reported separately: it is named in
COVERAGE_AND_BUILD_PLAN.md §9.2 as ground-truth benign, so any CRITICAL/HIGH finding there
is a false positive by definition.
"""
import json
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path

import yaml

MANIFEST_PATH = Path("benchmarks/skill_corpus_manifest.json")
CORPUS_DIR = Path("benchmarks/skill_corpus")


def _iter_counted_skill_dirs():
    manifest = json.loads(MANIFEST_PATH.read_text())
    for entry in manifest["entries"]:
        if entry.get("status") != "ok":
            continue
        repo_dir = CORPUS_DIR / entry["repo"].replace("/", "__")
        for rel in entry.get("counted_skill_dirs", entry.get("skill_dirs", [])):
            yield entry["repo"], repo_dir / rel


def _parse_frontmatter(skill_md: Path) -> dict:
    content = skill_md.read_text(errors="ignore")
    if not content.startswith("---"):
        return {}
    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}
    try:
        return yaml.safe_load(parts[1]) or {}
    except Exception:
        return {}


def _max_reference_depth(skill_dir: Path) -> int:
    """Depth of the deepest file under references/, regardless of what Lucin currently reads
    (Lucin today only reads depth 1 — this measures the real shape to size Stage 4's work)."""
    ref_dir = skill_dir / "references"
    if not ref_dir.is_dir():
        return -1
    max_depth = 0
    for p in ref_dir.rglob("*"):
        if p.is_file():
            depth = len(p.relative_to(ref_dir).parts)
            max_depth = max(max_depth, depth)
    return max_depth


def _script_extensions(skill_dir: Path) -> Counter:
    ext_counter = Counter()
    scripts_dir = skill_dir / "scripts"
    if scripts_dir.is_dir():
        for p in scripts_dir.rglob("*"):
            if p.is_file():
                ext_counter[p.suffix.lower() or "(no ext)"] += 1
    return ext_counter


def _executables_outside_scripts(skill_dir: Path) -> list[Path]:
    exec_exts = {".py", ".sh", ".bash", ".js", ".ts", ".cjs", ".mjs"}
    out = []
    for p in skill_dir.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in exec_exts:
            continue
        rel_parts = p.relative_to(skill_dir).parts
        if "scripts" in rel_parts[:-1] or (len(rel_parts) > 1 and rel_parts[0] == "scripts"):
            continue
        out.append(p)
    return out


def main():
    from lucin.models import Severity
    from lucin.scanner import scan_target

    skills = list(_iter_counted_skill_dirs())
    print(f"Reporting over {len(skills)} counted skill directories from {MANIFEST_PATH}\n")

    has_allowed_tools = 0
    has_compatibility = 0
    neither = 0
    script_ext_totals = Counter()
    skills_with_exec_outside_scripts = 0
    skills_with_references = 0
    reference_depths = []

    findings_per_skill = []          # total findings (any severity) per skill
    zero_finding_skills = 0
    rule_fire_counts = Counter()
    latencies_ms = []

    anthropics_crit_high = []  # (repo, skill_name, finding_id) for the ground-truth-benign check

    for repo, skill_dir in skills:
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            skill_md = skill_dir / "skill.md"
        fm = _parse_frontmatter(skill_md) if skill_md.exists() else {}
        a = "allowed-tools" in fm
        c = "compatibility" in fm
        has_allowed_tools += int(a)
        has_compatibility += int(c)
        neither += int(not a and not c)

        for ext, n in _script_extensions(skill_dir).items():
            script_ext_totals[ext] += n

        exec_outside = _executables_outside_scripts(skill_dir)
        if exec_outside:
            skills_with_exec_outside_scripts += 1

        ref_dir = skill_dir / "references"
        if ref_dir.is_dir():
            skills_with_references += 1
            reference_depths.append(_max_reference_depth(skill_dir))

        t0 = time.perf_counter()
        try:
            result = scan_target(skill_dir)
        except Exception as e:
            print(f"  [SCAN ERROR] {repo}/{skill_dir.name}: {e}")
            continue
        latencies_ms.append((time.perf_counter() - t0) * 1000)

        findings_per_skill.append(len(result.findings))
        if len(result.findings) == 0:
            zero_finding_skills += 1
        for f in result.findings:
            rule_fire_counts[f.id] += 1
            if repo == "anthropics/skills" and f.severity in (Severity.CRITICAL, Severity.HIGH):
                anthropics_crit_high.append((repo, skill_dir.name, f.id, f.title))

    total = len(skills)
    if total == 0:
        print("No skills found — run build_skill_corpus.py first.")
        return

    print("=" * 70)
    print("DECLARATION PREVALENCE (§8.4's gate)")
    print("=" * 70)
    print(f"  allowed-tools : {has_allowed_tools} ({has_allowed_tools/total*100:.1f}%)")
    print(f"  compatibility : {has_compatibility} ({has_compatibility/total*100:.1f}%)")
    print(f"  neither       : {neither} ({neither/total*100:.1f}%)")
    if has_allowed_tools / total < 0.20:
        print("  --> Below the ~20% threshold PHASE_6_PLAN.md §8.4 named as the flagship's go/no-go gate.")

    print("\n" + "=" * 70)
    print("SCRIPT LANGUAGE DISTRIBUTION (sizes §9.1's Bash/JS work)")
    print("=" * 70)
    for ext, n in script_ext_totals.most_common():
        print(f"  {ext:12s} {n}")

    print("\n" + "=" * 70)
    print("STRUCTURAL SHAPE")
    print("=" * 70)
    print(f"  Skills with executable files OUTSIDE scripts/: {skills_with_exec_outside_scripts} "
          f"({skills_with_exec_outside_scripts/total*100:.1f}%)  <- sizes the §2.9 bypass")
    print(f"  Skills with a references/ dir: {skills_with_references} ({skills_with_references/total*100:.1f}%)")
    if reference_depths:
        print(f"  Max reference depth observed: {max(reference_depths)} "
              f"(depths >1 violate the spec's 'one level deep' recommendation: "
              f"{sum(1 for d in reference_depths if d > 1)} skill(s))")

    print("\n" + "=" * 70)
    print("BENIGN NOISE METRIC (§5.2 of the build plan — the metric the old FP gate hides behind)")
    print("=" * 70)
    zero_pct = zero_finding_skills / total * 100
    median_findings = statistics.median(findings_per_skill) if findings_per_skill else 0
    print(f"  Median findings (any severity) per skill: {median_findings}")
    print(f"  Skills with ZERO findings: {zero_finding_skills}/{total} ({zero_pct:.1f}%)")
    print(f"  Target: >=80% zero-finding. Status: {'PASS' if zero_pct >= 80 else 'FAIL'}")

    print("\n" + "=" * 70)
    print("PER-RULE FIRE RATE")
    print("=" * 70)
    for rule_id, n in rule_fire_counts.most_common():
        print(f"  {rule_id:30s} {n:4d}  ({n/total*100:.1f}% of skills)")

    print("\n" + "=" * 70)
    print("GROUND-TRUTH-BENIGN CHECK: anthropics/skills (§9.2 — any finding here is an FP)")
    print("=" * 70)
    if anthropics_crit_high:
        print(f"  {len(anthropics_crit_high)} CRITICAL/HIGH finding(s) on ground-truth-benign skills:")
        for repo, name, rid, title in anthropics_crit_high:
            print(f"    [FP] {name}: {rid} — {title}")
    else:
        print("  0 CRITICAL/HIGH findings. Clean.")

    print("\n" + "=" * 70)
    print("SCAN LATENCY (§8.14 — previously unmeasured)")
    print("=" * 70)
    if latencies_ms:
        sorted_lat = sorted(latencies_ms)
        p50 = sorted_lat[len(sorted_lat) // 2]
        p95 = sorted_lat[int(len(sorted_lat) * 0.95)]
        print(f"  p50: {p50:.1f}ms   p95: {p95:.1f}ms   total: {sum(latencies_ms)/1000:.1f}s for {total} skills")

    print("\nReproduce: python benchmarks/build_skill_corpus.py && python benchmarks/skill_corpus_report.py")


if __name__ == "__main__":
    main()
