from unittest.mock import MagicMock

from rich.console import Console

from lucin.reporter import _print_summary


def test_print_summary_bar_scaling():
    """Verify that the risk summary bars scale proportionally to the highest severity count."""

    # Create a mock ScanResult with 1 critical, 5 high, 10 medium, 20 low
    result = MagicMock()
    result.critical_count = 1
    result.high_count = 5
    result.medium_count = 10
    result.low_count = 20

    # Capture the output
    console = Console(width=100, record=True)
    _print_summary(console, result)

    output = console.export_text()

    # Max count is 20. The bar max width is 24 characters.
    # Therefore, 20 findings = 24 blocks.
    # 1 finding = max(1, round(1/20 * 24)) = max(1, round(1.2)) = 1 block
    # 5 findings = max(1, round(5/20 * 24)) = max(1, round(6)) = 6 blocks
    # 10 findings = max(1, round(10/20 * 24)) = max(1, round(12)) = 12 blocks
    # 20 findings = max(1, round(20/20 * 24)) = max(1, round(24)) = 24 blocks

    assert "CRITICAL  █  1" in output
    assert "HIGH      ██████  5" in output
    assert "MEDIUM    ████████████  10" in output
    assert "LOW       ████████████████████████  20" in output
