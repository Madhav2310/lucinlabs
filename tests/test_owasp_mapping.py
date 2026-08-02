"""Every rule that fires must cite a real OWASP Agentic 2026 category."""
import re
import glob

from lucin.owasp import ASI, RULE_TO_ASI, owasp_ref

VALID = set(ASI)


def test_no_stray_owasp_literals():
    """No detector may hardcode an OWASP string; they must all go through owasp.py."""
    offenders = []
    for path in glob.glob("src/lucin/detectors/*.py"):
        for m in re.finditer(r'owasp_ref\s*=\s*"([^"]*)"', open(path).read()):
            offenders.append(f"{path}: {m.group(1)}")
    assert not offenders, "hardcoded owasp_ref found:\n" + "\n".join(offenders)


def test_every_mapped_code_exists():
    for rule, codes in RULE_TO_ASI.items():
        for c in codes:
            assert c in VALID, f"{rule} cites unknown category {c}"


def test_every_shipped_rule_is_mapped():
    ids = set()
    for path in glob.glob("src/lucin/detectors/*.py"):
        text = open(path).read()
        ids |= set(re.findall(r'id="(AG-[A-Za-z0-9-]+)"', text))
        ids |= set(re.findall(r'"id"\s*:\s*"(AG-[A-Za-z0-9-]+)"', text))
    missing = ids - set(RULE_TO_ASI)
    assert not missing, f"rules with no OWASP mapping: {sorted(missing)}"


def test_no_web_top10_language_leaks():
    """Guard against the exact regression: Web Top 10 wording in an agentic tool."""
    banned = ["Cryptographic Failures", "Broken Access Control", "Security Misconfiguration",
              "Identification and Authentication Failures", "Excessive Agency",
              "Resource Overload", "Cascading Hallucination"]
    rendered = " ".join(owasp_ref(r) for r in RULE_TO_ASI)
    for b in banned:
        assert b not in rendered, f"stale taxonomy leaked: {b}"
