#!/usr/bin/env python3
"""Build a real, third-party Agent Skills corpus.

PHASE_6_PLAN.md §5.2.1. Method: no author-written fixtures — clone real third-party
repos, find every directory containing `SKILL.md`, record the exact commit SHA.

TWO MODES, AND THE DIFFERENCE MATTERS
-------------------------------------
`--from-manifest` (REPRODUCIBLE, use this to reproduce a published number)
    Reads `skill_corpus_manifest.json` and re-clones exactly the repos it names, at
    exactly the SHAs it records. Deterministic: same manifest -> same corpus, byte
    for byte, regardless of what upstream does afterwards.

default / discovery mode (NOT reproducible — it is how a NEW corpus is minted)
    Resolves candidates from a LIVE GitHub topic search sorted by stars, plus the
    named sources below, and clones each at whatever HEAD is today.

THE BUG THIS DOCSTRING USED TO CARRY
------------------------------------
It previously claimed the corpus was "SHA-pinned" and that "re-running this script
against the same manifest re-clones the same commits". **Both were false.** The
manifest was written and never read; `clone_repo` shallow-cloned HEAD and recorded
whatever SHA it got. Combined with a live star-ranked topic search, the corpus was
non-reproducible on two independent axes.

Demonstrated 2026-08-05: an identical re-run produced **256 skills / 10 repos**
where the manifest recorded **337 skills / 13 repos** — `K-Dense-AI/scientific-agent-skills`
(40), `github/awesome-copilot` (40) and `blader/humanizer` (1) vanished because the
live search returned different repos. Every number measured on the 337-skill corpus
was therefore unreproducible by anyone, including us. `--from-manifest` fixes that;
the three drifted repos are now named sources so they cannot silently disappear again.

**Commit the manifest.** It is the pinned definition of the corpus — without it in
version control, `--from-manifest` has nothing to pin to.

Uses the `gh` CLI for repo search (falls back to unauthenticated GitHub REST API if `gh`
is unavailable — much lower rate limit, so topic-search page count is capped either way).

Output: `benchmarks/skill_corpus/` (one directory per cloned repo) and
`benchmarks/skill_corpus_manifest.json` (source, repo, sha, and every SKILL.md path found).
"""
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

CORPUS_DIR = Path("benchmarks/skill_corpus")
MANIFEST_PATH = Path("benchmarks/skill_corpus_manifest.json")

# COVERAGE_AND_BUILD_PLAN.md §9.2 — named, curated sources beyond topic search.
NAMED_SOURCES = [
    "anthropics/skills",              # ground-truth benign — any finding here is an FP by definition
    "VoltAgent/awesome-agent-skills",
    "ComposioHQ/awesome-claude-skills",
    "agentregistry-dev/skills",
    "gmh5225/awesome-skills",
    "heilcheng/awesome-agent-skills",
    # Promoted from topic-search to named sources 2026-08-05. These three were
    # corpus members via the live star-ranked search and silently vanished on a
    # re-run (81 skills, ~24% of the corpus), which is what exposed the
    # reproducibility bug described in the module docstring. Naming them removes
    # them from the mercy of GitHub's ranking.
    "K-Dense-AI/scientific-agent-skills",
    "github/awesome-copilot",
    "blader/humanizer",
]

TOPIC_QUERY = "topic:agent-skills"


def _run(cmd: list[str], timeout: int = 60, cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)


def _gh_available() -> bool:
    return shutil.which("gh") is not None


def search_topic_repos(pages: int, per_page: int = 100) -> list[str]:
    """Return `owner/repo` full names for the topic search, sorted by stars desc."""
    names: list[str] = []
    if _gh_available():
        for page in range(1, pages + 1):
            try:
                r = _run([
                    "gh", "api",
                    f"search/repositories?q={TOPIC_QUERY}&sort=stars&order=desc&per_page={per_page}&page={page}",
                    "--jq", ".items[].full_name",
                ], timeout=30)
            except Exception as e:
                print(f"  [WARN] gh api search page {page} failed: {e}")
                break
            if r.returncode != 0:
                print(f"  [WARN] gh api search page {page} exit {r.returncode}: {r.stderr.strip()[:200]}")
                break
            names.extend(n for n in r.stdout.splitlines() if n.strip())
    else:
        print("  [WARN] `gh` CLI not found — topic search skipped (falls back to NAMED_SOURCES only)")
    return names


def _extract_repo_links(readme_text: str) -> list[str]:
    """Pull unique `owner/repo` names out of an awesome-list README's github.com links."""
    import re
    links = re.findall(r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", readme_text)
    seen: list[str] = []
    for full_name in links:
        full_name = full_name.rstrip("/").removesuffix(".git")
        if full_name not in seen:
            seen.append(full_name)
    return seen


def clone_repo(full_name: str, dest_root: Path, timeout: int = 45,
               pin_sha: str | None = None) -> tuple[Path, str] | None:
    """Clone `owner/repo`. Returns (path, sha) or None on failure.

    `pin_sha` makes this reproducible: instead of shallow-cloning HEAD (whatever
    upstream happens to be today), fetch that exact commit and check it out. A
    plain `git clone --depth 1` cannot target an arbitrary SHA, so this uses the
    init + fetch-by-SHA form, which GitHub supports
    (`uploadpack.allowReachableSHA1InWant`).

    A pinned fetch that fails is reported as a failure, never silently downgraded
    to HEAD — a corpus that quietly substitutes a different commit is worse than
    one that admits it could not be rebuilt.
    """
    dest = dest_root / full_name.replace("/", "__")
    url = f"https://github.com/{full_name}.git"

    if dest.exists():
        try:
            sha = _run(["git", "rev-parse", "HEAD"], cwd=str(dest)).stdout.strip()
        except Exception:
            return None
        if pin_sha and sha != pin_sha:
            print(f"  [WARN] {full_name}: on-disk {sha[:10]} != pinned {pin_sha[:10]}; re-cloning")
            shutil.rmtree(dest, ignore_errors=True)
        else:
            return dest, sha

    if pin_sha:
        try:
            dest.mkdir(parents=True, exist_ok=True)
            _run(["git", "init", "--quiet", str(dest)], timeout=timeout)
            _run(["git", "remote", "add", "origin", url], cwd=str(dest), timeout=timeout)
            r = _run(["git", "fetch", "--depth", "1", "--quiet", "origin", pin_sha],
                     cwd=str(dest), timeout=timeout)
            if r.returncode != 0:
                print(f"  [SKIP] {full_name}: cannot fetch pinned {pin_sha[:10]}: "
                      f"{r.stderr.strip()[:120]}")
                shutil.rmtree(dest, ignore_errors=True)
                return None
            c = _run(["git", "checkout", "--quiet", "FETCH_HEAD"], cwd=str(dest), timeout=timeout)
            if c.returncode != 0:
                print(f"  [SKIP] {full_name}: checkout {pin_sha[:10]} failed")
                shutil.rmtree(dest, ignore_errors=True)
                return None
        except subprocess.TimeoutExpired:
            print(f"  [SKIP] {full_name}: pinned fetch timed out")
            shutil.rmtree(dest, ignore_errors=True)
            return None
        return dest, pin_sha

    try:
        r = _run(["git", "clone", "--depth", "1", "--quiet", url, str(dest)], timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"  [SKIP] {full_name}: clone timed out")
        return None
    if r.returncode != 0:
        print(f"  [SKIP] {full_name}: {r.stderr.strip()[:150]}")
        return None
    try:
        sha = _run(["git", "rev-parse", "HEAD"], cwd=str(dest)).stdout.strip()
    except Exception:
        sha = ""
    return dest, sha


def find_skill_dirs(repo_path: Path) -> list[Path]:
    """Every directory under `repo_path` containing a SKILL.md (any case), `.git` pruned."""
    out = []
    for p in repo_path.rglob("SKILL.md"):
        if ".git" in p.parts:
            continue
        out.append(p.parent)
    if not out:
        for p in repo_path.rglob("skill.md"):
            if ".git" in p.parts:
                continue
            out.append(p.parent)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-skills", type=int, default=250,
                     help="Stop once this many (capped, diversity-counted) skills are found (floor per PHASE_6_PLAN.md §5.2.1 is 200).")
    ap.add_argument("--max-repos", type=int, default=220, help="Hard cap on repos cloned, regardless of target-skills.")
    ap.add_argument("--max-skills-per-repo", type=int, default=40,
                     help="Cap how many of a single repo's skill dirs count toward the corpus. Without this, one large "
                          "monorepo (e.g. a company's internal skill collection) can dominate composition and defeat "
                          "the point of a third-party, cloned-not-written corpus (COVERAGE_AND_BUILD_PLAN.md §9.2). "
                          "Every found skill dir is still recorded in the manifest with skill_count; only the corpus "
                          "sample used for measurement is capped per repo.")
    ap.add_argument("--topic-pages", type=int, default=3, help="Pages of topic-search results to pull (100/page).")
    ap.add_argument("--clone-timeout", type=int, default=45)
    ap.add_argument("--from-manifest", action="store_true",
                    help="REPRODUCIBLE MODE: rebuild exactly the repos in the existing "
                         "manifest, at exactly their recorded SHAs. No live search, no "
                         "HEAD clones. Use this to reproduce a published number.")
    args = ap.parse_args()

    CORPUS_DIR.mkdir(parents=True, exist_ok=True)

    pins: dict[str, str] = {}
    candidates: list[tuple[str, str]] = []  # (full_name, source_label)
    seen_names: set[str] = set()

    if args.from_manifest:
        if not MANIFEST_PATH.exists():
            print(f"ERROR: --from-manifest needs {MANIFEST_PATH}, which does not exist.")
            return 2
        prior = json.loads(MANIFEST_PATH.read_text())
        for entry in prior.get("entries", []):
            if entry.get("status") != "ok" or not entry.get("sha"):
                continue
            name = entry["repo"]
            if name in seen_names:
                continue
            pins[name] = entry["sha"]
            candidates.append((name, entry.get("source", "manifest")))
            seen_names.add(name)
        print(f"Reproducible rebuild from {MANIFEST_PATH}: "
              f"{len(candidates)} repo(s) pinned to recorded SHAs. No live search.")
    else:
        print(f"Resolving candidate repos: topic search ({TOPIC_QUERY}, {args.topic_pages} page(s)) "
              f"+ {len(NAMED_SOURCES)} named sources...")
        print("  [NOTE] Discovery mode uses a LIVE star-ranked GitHub search and clones HEAD, "
              "so the resulting corpus is NOT reproducible. Use --from-manifest to reproduce "
              "a published number.")
        for full_name in NAMED_SOURCES:
            if full_name not in seen_names:
                candidates.append((full_name, "named_source"))
                seen_names.add(full_name)

        for full_name in search_topic_repos(args.topic_pages):
            if full_name not in seen_names:
                candidates.append((full_name, "topic_search"))
                seen_names.add(full_name)

        print(f"  {len(candidates)} unique candidate repos before awesome-list expansion")

    manifest: list[dict] = []
    counted_skills = 0   # diversity-capped count that drives the stop condition
    raw_skills_found = 0  # true total across every repo, uncapped, for the record
    repos_with_skills = 0
    repos_cloned = 0
    i = 0

    # First pass: clone every direct candidate (topic search + named sources), collecting
    # skills AND, for repos that turn out to be curated link-lists (zero SKILL.md found but
    # a README full of github.com links), queue their linked repos as second-pass candidates.
    expansion_queue: list[str] = []

    # In --from-manifest mode the manifest IS the corpus definition, so the discovery
    # stop-conditions must not apply: honouring `--target-skills` there truncated a
    # 552-skill manifest to 257 and produced a *different* corpus from the one being
    # reproduced — reproducible mode that silently returns something else is worse
    # than no reproducible mode at all.
    def _keep_going() -> bool:
        if args.from_manifest:
            return i < len(candidates)
        return (i < len(candidates)
                and repos_cloned < args.max_repos
                and counted_skills < args.target_skills)

    while _keep_going():
        full_name, source = candidates[i]
        i += 1
        result = clone_repo(full_name, CORPUS_DIR, timeout=args.clone_timeout,
                            pin_sha=pins.get(full_name))
        if result is None:
            manifest.append({"repo": full_name, "source": source, "status": "clone_failed"})
            continue
        repo_path, sha = result
        repos_cloned += 1
        skill_dirs = find_skill_dirs(repo_path)

        if skill_dirs:
            rel_all = [str(d.relative_to(repo_path)) for d in skill_dirs]
            counted_rel = rel_all[: args.max_skills_per_repo]
            manifest.append({
                "repo": full_name, "source": source, "status": "ok",
                "sha": sha, "skill_count": len(skill_dirs),
                "counted_skill_count": len(counted_rel),
                "skill_dirs": rel_all, "counted_skill_dirs": counted_rel,
            })
            raw_skills_found += len(skill_dirs)
            counted_skills += len(counted_rel)
            repos_with_skills += 1
            cap_note = f" (capped from {len(skill_dirs)})" if len(skill_dirs) > len(counted_rel) else ""
            print(f"  [{counted_skills:4d} counted / {raw_skills_found:4d} raw] {full_name}: "
                  f"{len(counted_rel)} skill(s){cap_note} @ {sha[:10]}")
        else:
            readme = repo_path / "README.md"
            if readme.exists() and source in ("named_source", "topic_search", "awesome_list_expansion"):
                links = _extract_repo_links(readme.read_text(errors="ignore"))
                new_links = [n for n in links if n not in seen_names]
                if new_links:
                    print(f"  [LIST] {full_name}: 0 direct skills, {len(new_links)} linked repos queued")
                    for n in new_links:
                        seen_names.add(n)
                    expansion_queue.extend(new_links)
            manifest.append({"repo": full_name, "source": source, "status": "no_skills_found", "sha": sha})

        if i >= len(candidates) and expansion_queue and counted_skills < args.target_skills:
            candidates.extend((n, "awesome_list_expansion") for n in expansion_queue)
            print(f"  [EXPAND] adding {len(expansion_queue)} awesome-list-linked repos to the candidate queue")
            expansion_queue = []

    with open(MANIFEST_PATH, "w") as f:
        json.dump({
            "target_skills": args.target_skills, "max_repos": args.max_repos,
            "max_skills_per_repo": args.max_skills_per_repo,
            "counted_skills": counted_skills, "raw_skills_found": raw_skills_found,
            "repos_cloned": repos_cloned, "repos_with_skills": repos_with_skills,
            "repos_attempted": len(manifest), "entries": manifest,
        }, f, indent=2)

    print(f"\n{'='*70}")
    print(f"Repos attempted:      {len(manifest)}")
    print(f"Repos cloned OK:      {repos_cloned}")
    print(f"Repos with skills:    {repos_with_skills}")
    print(f"Counted skills (corpus): {counted_skills}  (diversity-capped at {args.max_skills_per_repo}/repo)")
    print(f"Raw skills found (uncapped): {raw_skills_found}")
    print(f"Manifest written: {MANIFEST_PATH}")
    if counted_skills < 200:
        print("\n⚠️  Below the 200-skill floor (PHASE_6_PLAN.md §5.2.1) — re-run with a higher --target-skills/--max-repos.")
    elif repos_with_skills < 10:
        print(f"\n⚠️  Meets the count floor but only {repos_with_skills} distinct repos contributed skills — "
              f"thin diversity for a 'third-party population' claim. Consider more topic-search pages.")
    else:
        print(f"\n✅ Meets the ≥200-skill floor with {repos_with_skills} distinct contributing repos.")


if __name__ == "__main__":
    sys.exit(main() or 0)
