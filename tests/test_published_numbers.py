"""The site, the README and the code must agree on every published number."""
import json
from pathlib import Path

NUM = json.loads(Path("site/numbers.json").read_text())


def test_detector_count_matches_code():
    from lucin.detectors import ACTIVE_DETECTOR_COUNT
    assert NUM["detectors_active"] == ACTIVE_DETECTOR_COUNT


def test_adapter_count_matches_code():
    from lucin.parsers import _AUTO_PARSERS
    named = {fn.__name__ for fn in _AUTO_PARSERS if fn.__name__ != "parse_generic"}
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
