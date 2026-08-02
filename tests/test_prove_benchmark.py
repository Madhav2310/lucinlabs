"""Smoke + contract tests for the extended PROVE layer.

Covers:
  - attack_library.EXTRA_GENERATORS (AG-001, AG-002, AG-CORS, AG-NOAUTH, AG-011)
  - benchmark.to_agentdojo_case export shape
  - benchmark.AttackHarness end-to-end on the MOCK agent (ASR in [0,1])

These tests assert structure and honesty guarantees, NOT any real-world ASR.
"""

import pytest

from lucin.models import Finding, Severity
from lucin.prove.attack_library import EXTRA_GENERATORS
from lucin.prove.payload_generator import AdversarialPayload
from lucin.prove import benchmark as B


NEW_FINDING_IDS = ["AG-001", "AG-002", "AG-CORS", "AG-NOAUTH", "AG-011"]


def _finding(fid: str) -> Finding:
    return Finding(
        id=fid,
        title=f"Test finding {fid}",
        severity=Severity.HIGH,
        description="synthetic finding for payload generation",
        agent_name="test_agent",
        tool_name="do_thing",
        witness=["capability reached in 'do_thing' at line 10"],
    )


def test_import_smoke():
    assert callable(B.to_agentdojo_case)
    assert callable(B.default_defense_fn)
    assert callable(B.mock_agent_fn)
    assert set(NEW_FINDING_IDS).issubset(EXTRA_GENERATORS.keys())


@pytest.mark.parametrize("fid", NEW_FINDING_IDS)
def test_each_generator_returns_valid_payloads(fid):
    gen = EXTRA_GENERATORS[fid]
    payloads = gen(_finding(fid))
    assert isinstance(payloads, list)
    assert len(payloads) >= 1, f"{fid} produced no payloads"
    for p in payloads:
        assert isinstance(p, AdversarialPayload)
        assert p.finding_id == fid
        assert p.payload.strip(), f"{fid} has an empty payload"
        assert p.explanation.strip(), f"{fid} has an empty explanation"
        assert p.mitigation.strip(), f"{fid} has an empty mitigation"


def test_to_agentdojo_case_shape():
    payload = EXTRA_GENERATORS["AG-002"](_finding("AG-002"))[0]
    case = B.to_agentdojo_case(payload)
    assert isinstance(case, dict)
    for key in ("suite", "user_task", "injection", "injection_task",
                "attack_type", "expected_blocked", "security_target",
                "finding_id"):
        assert key in case, f"missing key {key}"
    assert case["expected_blocked"] is True
    assert case["finding_id"] == "AG-002"
    assert isinstance(case["injection"], dict)


def test_harness_runs_on_mock_and_reports_asr_in_range():
    payloads = []
    for fid in NEW_FINDING_IDS:
        payloads.extend(EXTRA_GENERATORS[fid](_finding(fid)))
    assert len(payloads) >= 5

    harness = B.AttackHarness()  # defaults: rule defense + mock agent
    results = harness.run(payloads)
    assert len(results) == len(payloads)

    benign = harness.run_benign(B.DEFAULT_BENIGN_PROBES)
    rep = B.report(results, benign_refusals=benign)

    assert 0.0 <= rep["asr"] <= 1.0
    assert rep["n_attacks"] == len(payloads)
    assert 0 <= rep["n_blocked"] <= rep["n_attacks"]
    assert rep["is_mock"] is True
    assert "MOCK" in rep["disclaimer"]
    assert 0.0 <= rep["false_refusal_rate"] <= 1.0


def test_encoding_bypass_slips_past_byte_level_defense():
    """Honesty check: homoglyph payloads should evade the byte-level rule defense
    while the mock agent (which folds homoglyphs like an LLM) still complies."""
    payloads = EXTRA_GENERATORS["AG-001"](_finding("AG-001"))
    enc = [p for p in payloads if p.variant.value == "encoding"]
    assert enc, "expected an encoding-bypass variant"
    r = B.AttackHarness().run_one(enc[0])
    assert r.blocked is False
    assert r.succeeded is True
