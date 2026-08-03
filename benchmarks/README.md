# Lucin Benchmark Dataset

Labeled agent configurations for measuring detection accuracy.

## Structure

- `vulnerable/` — Agents with known vulnerabilities (expected: findings)
- `safe/` — Agents with no security issues (expected: no critical/high findings)

## Usage

```bash
# Run benchmark
python benchmarks/run_benchmark.py

# Expected output:
# True Positive Rate: >95%
# False Positive Rate: <5%
```

## Adding Examples

Each file should contain:
1. A complete agent definition (parseable by Lucin)
2. A comment header documenting expected findings
