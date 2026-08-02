#!/usr/bin/env python3
"""pin_corpus_shas.py — freeze the benign corpus to specific commit SHAs.

The benign corpus repos previously tracked `main` HEAD, so a later re-fetch could
silently shift the file count and the published "0 adjudicated FP / 52 repos /
2,732 files" precision result (a reproducibility drift risk flagged in the repo
hygiene notes). This resolves each repo's current default-branch HEAD to a commit
SHA and writes a lockfile; `download_repo` then fetches `/archive/<sha>.zip`
instead of `main`, so the number is frozen and re-derivable by a third party.

Run:  python benchmarks/pin_corpus_shas.py            # resolve + write lockfile
      python benchmarks/pin_corpus_shas.py --check    # verify lockfile covers CORPUS

Uses `GIT_CONFIG_GLOBAL=/dev/null git ls-remote` (bypasses any global
insteadOf HTTPS->SSH rewrite; SSH/port-22 is blocked in some build envs).
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_benign_corpus import CORPUS, SHAS_FILE  # noqa: E402


def _base_repo_url(archive_url: str) -> str:
    """https://github.com/o/r/archive/refs/heads/main.zip -> https://github.com/o/r"""
    return archive_url.split("/archive/")[0]


def resolve_sha(entry: dict) -> tuple[str, str | None, str]:
    """Return (name, sha_or_None, note). Uses ls-remote HEAD (default branch)."""
    base = _base_repo_url(entry["url"])
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
    try:
        out = subprocess.run(
            ["git", "ls-remote", base, "HEAD"],
            capture_output=True, text=True, timeout=60, env=env,
        )
        if out.returncode != 0 or not out.stdout.strip():
            return entry["name"], None, f"ls-remote failed: {out.stderr.strip()[:80]}"
        sha = out.stdout.split()[0].strip()
        if len(sha) != 40:
            return entry["name"], None, f"unexpected sha: {sha[:20]}"
        return entry["name"], sha, "ok"
    except Exception as e:  # noqa: BLE001
        return entry["name"], None, f"error: {type(e).__name__}: {e}"


def main(argv: list[str]) -> int:
    if "--check" in argv:
        if not SHAS_FILE.exists():
            print("no lockfile — run without --check to create it")
            return 1
        pins = json.loads(SHAS_FILE.read_text()).get("pins", {})
        missing = [e["name"] for e in CORPUS if e["name"] not in pins]
        print(f"lockfile pins {len(pins)} repos; CORPUS has {len(CORPUS)}; "
              f"missing: {missing or 'none'}")
        return 0 if not missing else 1

    print(f"Resolving HEAD SHAs for {len(CORPUS)} corpus repos (parallel)...")
    pins: dict[str, str] = {}
    failures: list[tuple[str, str]] = []
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        for name, sha, note in ex.map(resolve_sha, CORPUS):
            if sha:
                pins[name] = sha
                print(f"  [ok]   {name}  {sha[:12]}")
            else:
                failures.append((name, note))
                print(f"  [FAIL] {name}  {note}")

    payload = {
        "_comment": "Frozen corpus commit SHAs. download_repo fetches /archive/<sha>.zip. "
                    "Regenerate with: python benchmarks/pin_corpus_shas.py",
        "resolved_at": datetime.now(timezone.utc).isoformat(),
        "pins": pins,
    }
    SHAS_FILE.write_text(json.dumps(payload, indent=2))
    print(f"\nWrote {SHAS_FILE.name}: {len(pins)}/{len(CORPUS)} repos pinned"
          + (f", {len(failures)} failed" if failures else ""))
    if failures:
        print("Unpinned repos fall back to `main` HEAD (documented, not frozen):")
        for name, note in failures:
            print(f"  - {name}: {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
