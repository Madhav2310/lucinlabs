"""Lucin Benchmark Runner — measure detection accuracy.

Scans all examples in vulnerable/ and safe/ directories,
computes true positive rate, false positive rate, and overall accuracy.

Run: python benchmarks/run_benchmark.py
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from lucin.scanner import scan_target


def run_benchmark():
    """Run the full benchmark suite."""
    benchmark_dir = Path(__file__).parent
    vulnerable_dir = benchmark_dir / "vulnerable"
    safe_dir = benchmark_dir / "safe"

    print("=" * 60)
    print(" Lucin Accuracy Benchmark")
    print("=" * 60)
    print()

    # Test vulnerable examples (should find issues)
    print("VULNERABLE AGENTS (expected: findings)")
    print("-" * 40)
    true_positives = 0
    false_negatives = 0

    if vulnerable_dir.exists():
        for agent_file in sorted(vulnerable_dir.iterdir()):
            if agent_file.suffix in (".py", ".json", ".yaml", ".yml"):
                result = scan_target(agent_file)
                has_findings = len(result.findings) > 0
                status = "✅ TP" if has_findings else "❌ FN"
                print(f"  {status} {agent_file.name}: {len(result.findings)} findings")
                if has_findings:
                    true_positives += 1
                else:
                    false_negatives += 1

    # Test safe examples (should NOT find critical/high issues)
    print()
    print("SAFE AGENTS (expected: no critical/high findings)")
    print("-" * 40)
    true_negatives = 0
    false_positives = 0

    if safe_dir.exists():
        for agent_file in sorted(safe_dir.iterdir()):
            if agent_file.suffix in (".py", ".json", ".yaml", ".yml"):
                result = scan_target(agent_file)
                critical_high = [f for f in result.findings if f.severity.value in ("critical", "high")]
                is_clean = len(critical_high) == 0
                status = "✅ TN" if is_clean else "❌ FP"
                print(f"  {status} {agent_file.name}: {len(critical_high)} critical/high")
                if is_clean:
                    true_negatives += 1
                else:
                    false_positives += 1

    # Compute metrics
    print()
    print("=" * 60)
    print(" RESULTS")
    print("=" * 60)

    total_vuln = true_positives + false_negatives
    total_safe = true_negatives + false_positives

    tp_rate = (true_positives / total_vuln * 100) if total_vuln > 0 else 0
    fp_rate = (false_positives / total_safe * 100) if total_safe > 0 else 0

    print(f"  True Positives:  {true_positives}/{total_vuln}")
    print(f"  False Negatives: {false_negatives}/{total_vuln}")
    print(f"  True Negatives:  {true_negatives}/{total_safe}")
    print(f"  False Positives: {false_positives}/{total_safe}")
    print()
    print(f"  TP Rate (Recall):     {tp_rate:.1f}% (target: >95%)")
    print(f"  FP Rate:              {fp_rate:.1f}% (target: <5%)")
    print()

    if tp_rate >= 95 and fp_rate <= 5:
        print("  ✅ BENCHMARK PASSES")
    elif tp_rate >= 90:
        print("  ⚠️  CLOSE — minor accuracy gap")
    else:
        print("  ❌ BENCHMARK FAILS — accuracy below target")

    return tp_rate >= 95 and fp_rate <= 5


if __name__ == "__main__":
    success = run_benchmark()
    sys.exit(0 if success else 1)
