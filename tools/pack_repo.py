#!/usr/bin/env python3
"""pack_repo.py — pack the whole Lucin repo into ONE text file for migration.

You migrate this repo by concatenating it into a single file, pasting that into an
assistant, and having it recreate the tree. A naive concat is impossible because
`benchmarks/corpus/` (~3.5 GB of vendored repos) and `venv/` (~1.7 GB) dwarf the
actual source. This packer EXCLUDES everything regenerable and emits ONLY the
source of truth: code, tests, docs, plan, fixtures, configs.

OUTPUT
    lucin_bundle.txt  (gitignored)

RECONSTRUCT ON THE TARGET MACHINE
    1. For each block, write its contents to the path in its
       "===== FILE: <path> =====" header (creating parent dirs).
    2. python -m venv venv && ./venv/bin/pip install -e ".[dev]"
    3. python benchmarks/fetch_corpus.py       # re-download the ~3.5 GB corpus
    4. ./venv/bin/python -m pytest tests/ -q    # expect all green

USAGE
    python tools/pack_repo.py [--max-kb 300] [--out lucin_bundle.txt]
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Directories never descended into (regenerable / huge / opaque).
EXCLUDE_DIRS = {
    "venv", ".venv", "env", ".git", "node_modules", "__pycache__",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", "dist", "build", "htmlcov",
    ".egg-info",
}
# Relative path prefixes to skip entirely (the huge regenerable corpus).
EXCLUDE_PREFIXES = ("benchmarks/corpus", "benchmarks/corpus_cache")
EXCLUDE_NAMES = {".DS_Store", "lucin_bundle.txt"}
BINARY_EXT = {
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".zip", ".gz", ".tar", ".whl",
    ".safetensors", ".bin", ".pt", ".pth", ".onnx", ".npy", ".npz", ".parquet",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf",
    ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".mov", ".zip",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-kb", type=int, default=300,
                    help="skip files larger than this many KB (default 300)")
    ap.add_argument("--out", default=str(ROOT / "lucin_bundle.txt"))
    args = ap.parse_args()
    max_bytes = args.max_kb * 1024

    included: list[Path] = []
    skipped_large: list[tuple[str, int]] = []
    skipped_binary: list[str] = []

    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel_dir = Path(dirpath).relative_to(ROOT)
        # prune excluded dirs IN PLACE so we never descend into venv/corpus/.git
        dirnames[:] = [
            d for d in dirnames
            if d not in EXCLUDE_DIRS
            and not any(str((rel_dir / d)).startswith(p) for p in EXCLUDE_PREFIXES)
        ]
        for fn in sorted(filenames):
            if fn in EXCLUDE_NAMES:
                continue
            p = Path(dirpath) / fn
            rel = p.relative_to(ROOT)
            rels = str(rel)
            if any(rels.startswith(p2) for p2 in EXCLUDE_PREFIXES):
                continue
            if p.suffix.lower() in BINARY_EXT:
                skipped_binary.append(rels)
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size > max_bytes:
                skipped_large.append((rels, size))
                continue
            try:
                p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                skipped_binary.append(rels)
                continue
            included.append(rel)

    included.sort()
    out = Path(args.out)
    with out.open("w", encoding="utf-8") as f:
        f.write("LUCIN REPO BUNDLE — single-file migration package\n")
        f.write("=" * 72 + "\n")
        f.write(
            "RECONSTRUCT:\n"
            "  1. For each block below, write its contents to the path in its\n"
            "     '===== FILE: <path> =====' header (create parent dirs).\n"
            '  2. python -m venv venv && ./venv/bin/pip install -e ".[dev]"\n'
            "  3. python benchmarks/fetch_corpus.py     # re-download the ~3.5 GB corpus\n"
            "  4. ./venv/bin/python -m pytest tests/ -q  # expect all green\n"
        )
        f.write("=" * 72 + "\n")
        f.write(f"INCLUDED FILES ({len(included)}):\n")
        for rel in included:
            f.write(f"  {rel}\n")
        if skipped_large:
            f.write(f"\nSKIPPED — larger than {args.max_kb} KB (transfer/regenerate separately):\n")
            for rels, size in skipped_large:
                f.write(f"  {rels}  ({size // 1024} KB)\n")
        if skipped_binary:
            f.write("\nSKIPPED — binary/opaque (cannot be recreated from text):\n")
            for rels in skipped_binary:
                f.write(f"  {rels}\n")
        f.write("\nNOTE: benchmarks/corpus/ (~3.5 GB, 59 vendored repos) and venv/ are\n")
        f.write("intentionally omitted — regenerate with fetch_corpus.py + pip install.\n")
        f.write("=" * 72 + "\n\n")
        for rel in included:
            f.write(f"===== FILE: {rel} =====\n")
            f.write((ROOT / rel).read_text(encoding="utf-8"))
            f.write("\n\n")

    total = out.stat().st_size
    print(f"Wrote {out} — {len(included)} files, {total // 1024} KB")
    print(f"  skipped large: {len(skipped_large)}   skipped binary: {len(skipped_binary)}")
    if skipped_large:
        print("  (large files listed in the bundle header; move them out-of-band if needed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
