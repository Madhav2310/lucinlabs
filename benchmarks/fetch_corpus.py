#!/usr/bin/env python3
"""fetch_corpus.py — re-download the benign benchmark corpus (~59 vendored repos).

WHY THIS EXISTS
    The benign corpus (~3.5 GB) is .gitignore'd and never committed or transferred.
    It is fully regenerable from the pinned URL list in build_benign_corpus.py, so
    the "0 confirmed FP / 52 repos / 2,732 files" result reproduces on a fresh
    checkout. Run this after cloning/reconstructing the repo:

        python benchmarks/fetch_corpus.py         # fetch all missing repos (skips present)
        python benchmarks/build_benign_corpus.py  # then run the FP measurement

REPRODUCIBILITY (SHA-pinned, 2026-07-30)
    Repos are now frozen to specific commit SHAs via `benchmarks/corpus_shas.json`
    (56/56 pinned); `download_repo` fetches `/archive/<sha>.zip`, so a re-fetch is
    byte-stable and the "0 adjudicated FP / 52 repos / 2,732 files" result does not
    drift with upstream. Regenerate the lockfile with:

        python benchmarks/pin_corpus_shas.py          # re-resolve HEAD -> SHA
        python benchmarks/pin_corpus_shas.py --check   # verify lockfile covers CORPUS

    A repo missing from the lockfile falls back to `main` HEAD (documented, not frozen).
"""
from __future__ import annotations

import concurrent.futures as cf
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_benign_corpus import CORPUS, CORPUS_DIR, download_repo  # noqa: E402


def main() -> int:
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Fetching {len(CORPUS)} repos into {CORPUS_DIR}")
    print("(existing repos are skipped; this is safe to re-run)\n")
    ok, failed = 0, []
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(download_repo, e, CORPUS_DIR / e["name"]): e for e in CORPUS}
        for fut in cf.as_completed(futs):
            entry = futs[fut]
            try:
                root = fut.result()
                if root:
                    ok += 1
                    print(f"  ✓ {entry['name']}")
                else:
                    failed.append(entry["name"])
                    print(f"  ✗ {entry['name']} (no extracted root)")
            except Exception as exc:  # noqa: BLE001
                failed.append(entry["name"])
                print(f"  ✗ {entry['name']} — {exc}")
    print(f"\nDone: {ok}/{len(CORPUS)} present.  Failed: {failed or 'none'}")
    print("Next: python benchmarks/build_benign_corpus.py  (runs the 0%-FP analysis)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
