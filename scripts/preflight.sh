#!/usr/bin/env bash
# scripts/preflight.sh — run before every deploy.
set -euo pipefail
python -m pytest tests/ -q
ruff check src/
python site/build.py && python site/build_blog.py && python site/build_rules.py
python site/check_site.py
git diff --exit-code site/ || { echo "site/ changed — commit the rebuild"; exit 1; }
bash scripts/p0_gate.sh
echo "preflight OK"
