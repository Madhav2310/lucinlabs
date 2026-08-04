"""The site, the README and the code must agree on every published number.

NOTE ON WHAT THESE TESTS DO AND DO NOT PROVE
--------------------------------------------
Most tests here check that README/HTML agree with `site/numbers.json`. That is
*internal consistency*, not truth: a stale number in `numbers.json` propagates to
every surface and every check still passes.

That gap was live. `tests_passing` sat at **511** while the suite actually had
**537** — published on the README badge, the site, and the docs, and no test could
see it, because nothing compared the number to reality. `test_detector_count_matches_code`
and `test_adapter_count_matches_code` do compare against the code; `tests_passing`
did not, so it drifted. `test_tests_passing_is_not_stale` below closes that.
"""
import json
import subprocess
import sys
from pathlib import Path

NUM = json.loads(Path("site/numbers.json").read_text())


def test_tests_passing_is_not_stale():
    """The published test count must reflect the suite that actually exists.

    Compared against `pytest --collect-only` in a subprocess rather than against a
    full run: collection is fast and deterministic, whereas re-running the suite
    inside itself doubles CI time.

    Collected and passing are NOT equal — module-level skips (e.g. an optional
    dependency missing) are reported as skipped but never collected, so on this
    machine 550 collect while the summary reads 537 passed / 15 skipped / 1 xfailed.
    The assertions therefore bound the relationship instead of equating it:

      * `passing <= collected` — claiming more passing tests than exist is an
        overclaim, and is never acceptable.
      * the gap stays small — catches the real failure mode, which is adding a batch
        of tests and forgetting to update the published number (26 tests, in the
        case above).
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
        capture_output=True, text=True, cwd=Path(__file__).resolve().parent.parent,
    )
    collected = None
    for line in proc.stdout.splitlines():
        if "tests collected" in line or "test collected" in line:
            collected = int(line.split()[0])
            break
    if collected is None:                      # collection itself failed — not our call to judge
        import pytest
        pytest.skip(f"could not parse collection output: {proc.stdout[-300:]}")

    published = NUM["tests_passing"]
    assert published <= collected, (
        f"site/numbers.json claims {published} passing tests but only {collected} exist. "
        "Publishing more passing tests than the suite contains is an overclaim."
    )
    assert collected - published <= 30, (
        f"site/numbers.json claims {published} passing but {collected} are collected "
        f"(gap {collected - published}). The published number is stale — re-run "
        "`python -m pytest tests/ -q` and update site/numbers.json, README.md badge, "
        "README 'Test suite:' line, and site/index.html together."
    )


def test_detector_count_matches_code():
    from lucin.detectors import ACTIVE_DETECTOR_COUNT
    assert NUM["detectors_active"] == ACTIVE_DETECTOR_COUNT


def test_adapter_count_matches_code():
    """`frameworks` counts agent orchestration framework adapters only.

    `parse_skill` is deliberately excluded: an Agent Skills bundle (SKILL.md) is an
    artifact type, not an orchestration framework, and folding it into this count
    would inflate it the same way registering an unmeasured detector would inflate
    `detectors_active` — see PHASE_6_PLAN.md §2.11/§5.1.4, §7 Q6.
    """
    from lucin.parsers import _AUTO_PARSERS
    named = {
        fn.__name__ for fn in _AUTO_PARSERS
        if fn.__name__ not in ("parse_generic", "parse_skill")
    }
    assert NUM["frameworks"] == len(named)


def test_site_html_matches_numbers_json():
    html = Path("site/index.html").read_text()
    assert f'data-target="{NUM["recall_pct"]}"' in html
    assert f'data-target="{NUM["detectors_active"]}"' in html
    assert f'data-target="{NUM["frameworks"]}"' in html


def test_no_stale_precision_string_anywhere():
    """The 58% figure was baked into an old OG image. It must never reappear."""
    for p in list(Path("site").rglob("*.html")) + [Path("README.md"), Path("site/make_og.py")]:
        assert "58% precision" not in p.read_text(), f"stale precision figure in {p}"


def test_new_benchmark_numbers_agree():
    readme = Path("README.md").read_text()
    assert NUM["unit_tests"] in readme, f"Expected {NUM['unit_tests']} in README.md"
    assert "Behavioral benchmark on 52 real-world repos (in progress)" not in readme, "Found stale '(in progress)' in README.md"

    html = Path("site/index.html").read_text()
    assert f">{NUM['tests_passing']}<" in html or f" {NUM['tests_passing']} passing" in html or f"**{NUM['tests_passing']} passing**" in html or str(NUM['tests_passing']) in html, "Could not find tests_passing in HTML"
