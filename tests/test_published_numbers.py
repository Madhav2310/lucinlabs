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
    # fp_count was NOT checked here, which is how the landing page kept claiming
    # "0 false positives" and "100% precision" long after the measured values were
    # 11 and 20.5-31.5%. Commit 1d5837f corrected the OG image and missed the page
    # body, because site/index.html is hand-written rather than generated from this
    # JSON — so a fix to the JSON never propagated and no test noticed.
    assert f'data-target="{NUM["fp_count"]}"' in html, (
        f'site/index.html does not carry fp_count={NUM["fp_count"]} from numbers.json'
    )


def test_site_precision_and_corpus_claims_match_numbers_json():
    """The benchmarks block must state the measured precision, not an aspiration.

    This is the one defect that cannot coexist with the positioning: the audience
    most worth reaching is exactly the audience that opens the methodology page,
    sees a different number, and concludes the honesty stance is decorative.
    """
    html = Path("site/index.html").read_text()
    assert NUM["precision_range"] in html, (
        f'Landing page does not state the measured precision range '
        f'{NUM["precision_range"]} from numbers.json'
    )
    assert f'{NUM["repos"]} real repositories' in html, "stale repo count on landing page"
    assert f'{NUM["files"]:,} files' in html, "stale file count on landing page"


def test_no_unearned_precision_or_fp_claims():
    """Absolute claims we have measured to be false must never reappear anywhere.

    `0 false positives` and `100% precision` were both live on lucin.pages.dev while
    `build_benign_corpus.py` printed 11 and the methodology page said 20.5-31.5%.

    Deliberately NOT banned: "100% recall (4/4 labeled trifecta cases)". That is true
    and denominated — `recall_corpus.py` reports secret_exfil_trifecta 4/4. Banning a
    figure that is accurate and carries its n would be theatre, and `claim_audit.py`
    R3 already enforces the real rule (no UN-denominated 100% recall).

    Word-boundary matched: "150 false positives out of 330 detections" is a cited
    figure about Meta's Pysa in the Semgrep comparison, not a claim about Lucin, and
    a naive substring match flags it.
    """
    import re

    banned = (r"58% precision", r"100% precision",
              r"\b0 false positives", r"\bzero false positives",
              r"\b0 adjudicated false positives", r"\b0 confirmed FP")
    targets = (list(Path("site").rglob("*.html"))
               + list(Path("site/content").rglob("*.md"))
               + list(Path("docs").rglob("*.md"))
               + [Path("README.md"), Path("site/make_og.py")])
    for p in targets:
        if not p.exists():
            continue
        text = p.read_text()
        for phrase in banned:
            hit = re.search(phrase, text, re.IGNORECASE)
            assert hit is None, (
                f"unearned claim {hit.group(0)!r} in {p} — measured values are "
                f'fp_count={NUM["fp_count"]}, precision={NUM["precision_range"]}'
            )


def test_claim_audit_gate_passes():
    """Run tools/claim_audit.py — the honesty gate that was wired to nothing.

    It exists specifically to fail CI on dishonest public copy, and `grep -rln
    claim_audit tests/ .github/` returned NOTHING: it had never been connected to the
    test suite or to CI, which is why "0 false positives" and "100% precision" stayed
    live on the landing page long after the measured values were 11 and 20.5-31.5%.
    A launch gate nobody runs is not a gate.
    """
    root = Path(__file__).resolve().parent.parent
    proc = subprocess.run([sys.executable, "tools/claim_audit.py"],
                          capture_output=True, text=True, cwd=root)
    assert proc.returncode == 0, (
        f"claim_audit.py failed:\n{proc.stdout[-2000:]}\n{proc.stderr[-500:]}"
    )


def test_new_benchmark_numbers_agree():
    readme = Path("README.md").read_text()
    assert NUM["unit_tests"] in readme, f"Expected {NUM['unit_tests']} in README.md"
    assert "Behavioral benchmark on 52 real-world repos (in progress)" not in readme, "Found stale '(in progress)' in README.md"

    html = Path("site/index.html").read_text()
    assert f">{NUM['tests_passing']}<" in html or f" {NUM['tests_passing']} passing" in html or f"**{NUM['tests_passing']} passing**" in html or str(NUM['tests_passing']) in html, "Could not find tests_passing in HTML"
