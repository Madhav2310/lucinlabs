"""Tests for the behavioral trace generator and statistical calibration."""

import pytest

pytest.importorskip("numpy", reason="behavioral extra not installed")

from lucin.behavioral.trace_gen import (
    build_corpus, benign_session, attack_session, ROLE_NAMES, ATTACKS, EVASIVE_ATTACKS,
)
from lucin.behavioral.score_calibration import (
    IsotonicCalibrator, MondrianConformal, brier_score,
)


# ---------------------------------------------------------------------------
# Trace generator
# ---------------------------------------------------------------------------

def test_corpus_is_deterministic():
    a = build_corpus(seed=1, benign_per_role=3, attack_per_type=2)
    b = build_corpus(seed=1, benign_per_role=3, attack_per_type=2)
    # same seed → identical corpus (reproducible numbers)
    assert a["test_attacks"] == b["test_attacks"]
    assert a["train"] == b["train"]


def test_different_seeds_differ():
    a = build_corpus(seed=1, benign_per_role=3, attack_per_type=2)
    b = build_corpus(seed=2, benign_per_role=3, attack_per_type=2)
    assert a["test_attacks"] != b["test_attacks"]


def test_benign_contains_attack_ingredients():
    """The corpus is only meaningful if benign traffic contains the ingredients
    of attacks (secret reads + external egress) — otherwise PR-AUC is a lie."""
    c = build_corpus(seed=0, benign_per_role=4, attack_per_type=1)
    tools = [e["tool"] for r in c["test_benign"] for s in c["test_benign"][r] for e in s]
    assert "read_secret_env" in tools          # benign roles legitimately read secrets
    assert any(t in tools for t in ("send_email", "send_report", "http_get", "read_url"))


def test_attack_sessions_are_labelled():
    c = build_corpus(seed=0, benign_per_role=2, attack_per_type=1)
    for item in c["test_attacks"]:
        labels = [e["label"] for e in item["events"]]
        assert 1 in labels                     # has an attack span
        assert 0 in labels                     # has a benign prefix
        # attack span is contiguous at the end
        assert labels[-1] == 1


def test_benign_sessions_all_label_zero():
    c = build_corpus(seed=0, benign_per_role=3, attack_per_type=1)
    for r, sessions in c["test_benign"].items():
        for s in sessions:
            assert all(e["label"] == 0 for e in s)


def test_all_attacks_present_and_evasive_marked():
    assert EVASIVE_ATTACKS <= set(ATTACKS)
    assert "slow_low" in EVASIVE_ATTACKS and "mimicry" in EVASIVE_ATTACKS
    assert "exfil_rapid" in ATTACKS and "exfil_rapid" not in EVASIVE_ATTACKS


def test_events_have_timestamps_and_args():
    evs = attack_session("data_analyst", "exfil_rapid", __import__("random").Random(0))
    for e in evs:
        assert "t" in e and isinstance(e["t"], float)
        assert "args" in e and isinstance(e["args"], dict)


# ---------------------------------------------------------------------------
# Isotonic calibration
# ---------------------------------------------------------------------------

def test_isotonic_improves_brier_on_miscalibrated_scores():
    # Construct scores that separate classes but are NOT probabilities:
    # benign scores ~0.3, attack scores ~0.6 (both far from 0/1 → high Brier raw).
    import random
    rng = random.Random(0)
    scores, labels = [], []
    for _ in range(200):
        scores.append(0.3 + rng.uniform(-0.05, 0.05)); labels.append(0)
    for _ in range(200):
        scores.append(0.6 + rng.uniform(-0.05, 0.05)); labels.append(1)
    iso = IsotonicCalibrator().fit(scores, labels)
    imp = iso.brier_improvement(scores, labels)
    assert imp["brier_calibrated"] <= imp["brier_raw"]
    assert imp["improvement"] >= 0


def test_isotonic_predict_is_monotonic():
    iso = IsotonicCalibrator().fit([0.1, 0.2, 0.5, 0.8, 0.9], [0, 0, 1, 1, 1])
    preds = iso.predict([0.0, 0.3, 0.6, 1.0])
    assert all(preds[i] <= preds[i + 1] + 1e-9 for i in range(len(preds) - 1))


def test_isotonic_requires_fit():
    with pytest.raises(RuntimeError):
        IsotonicCalibrator().predict([0.5])


# ---------------------------------------------------------------------------
# Mondrian conformal
# ---------------------------------------------------------------------------

def test_mondrian_controls_per_group_false_alarm():
    """Per-group benign false-alarm rate should be ≈ alpha (the coverage guarantee)."""
    import random
    rng = random.Random(0)
    # Two groups with different benign score distributions.
    cal = {
        "roleA": [rng.gauss(0.2, 0.05) for _ in range(500)],
        "roleB": [rng.gauss(0.5, 0.05) for _ in range(500)],
    }
    conf = MondrianConformal(alpha=0.05).fit(cal)
    # Held-out benign from the same distributions.
    test = {
        "roleA": [rng.gauss(0.2, 0.05) for _ in range(500)],
        "roleB": [rng.gauss(0.5, 0.05) for _ in range(500)],
    }
    far = conf.group_false_alarm_rates(test)
    # Each group's benign flag rate should be close to alpha (0.05), well under 0.12.
    for g, rate in far.items():
        assert rate <= 0.12, f"{g} false-alarm {rate} exceeds tolerance"


def test_mondrian_flags_clear_anomaly():
    conf = MondrianConformal(alpha=0.05).fit({"r": [0.1, 0.15, 0.2, 0.12, 0.18] * 20})
    # A score far above the benign calibration set is anomalous.
    assert conf.is_anomalous("r", 0.95)
    # A score inside the benign range is not.
    assert not conf.is_anomalous("r", 0.15)


def test_mondrian_unknown_group_never_flags():
    conf = MondrianConformal(alpha=0.05).fit({"r": [0.1, 0.2]})
    assert conf.p_value("unknown", 0.99) == 1.0
    assert not conf.is_anomalous("unknown", 0.99)


def test_brier_score_basic():
    assert brier_score([1.0, 0.0], [1, 0]) == 0.0
    assert brier_score([0.0, 1.0], [1, 0]) == 1.0


# ---------------------------------------------------------------------------
# Session-level scoring (the redesign)
# ---------------------------------------------------------------------------

def test_scan_statistic_rewards_contiguity_over_isolated_spike():
    from lucin.behavioral.session_scoring import scan_statistic
    # one isolated spike in an otherwise-quiet session
    isolated = [0.1] * 20 + [0.95] + [0.1] * 20
    # a contiguous span of the same peak height
    contiguous = [0.1] * 20 + [0.95, 0.95, 0.95] + [0.1] * 18
    assert scan_statistic(contiguous, window=3) > scan_statistic(isolated, window=3)
    # the isolated spike is diluted well below its peak
    assert scan_statistic(isolated, window=3) < 0.5


def test_session_conformal_controls_session_fp():
    import random
    from lucin.behavioral.session_scoring import SessionConformalThreshold
    rng = random.Random(0)
    # benign sessions: mostly low with the occasional isolated spike (a legit
    # report-send). Two-scale conformal must keep session FP ≈ alpha even so.
    def benign_session():
        s = [rng.uniform(0.0, 0.2) for _ in range(30)]
        if rng.random() < 0.5:
            s[rng.randrange(30)] = rng.uniform(0.85, 0.95)
        return s
    calib = {"r": [benign_session() for _ in range(200)]}
    conf = SessionConformalThreshold(alpha=0.05, windows=(1, 5)).fit(calib)
    test = [benign_session() for _ in range(300)]
    fp = sum(1 for s in test if conf.flag("r", s)) / len(test)
    assert fp <= 0.12, f"session FP {fp} exceeds tolerance"


def test_session_conformal_flags_sustained_attack():
    import random
    from lucin.behavioral.session_scoring import SessionConformalThreshold
    rng = random.Random(1)
    calib = {"r": [[rng.uniform(0.0, 0.2) for _ in range(30)] for _ in range(200)]}
    conf = SessionConformalThreshold(alpha=0.05, windows=(1, 5)).fit(calib)
    # a sustained anomalous span → caught by the w=5 scale
    attack = [rng.uniform(0.0, 0.2) for _ in range(20)] + [0.9] * 6 + [rng.uniform(0.0, 0.2) for _ in range(10)]
    assert conf.flag("r", attack)


def test_session_conformal_catches_single_decisive_spike_on_quiet_role():
    import random
    from lucin.behavioral.session_scoring import SessionConformalThreshold
    rng = random.Random(2)
    # a role whose benign sessions are ALWAYS quiet (never spike)
    calib = {"quiet": [[rng.uniform(0.0, 0.2) for _ in range(30)] for _ in range(200)]}
    conf = SessionConformalThreshold(alpha=0.05, windows=(1, 5)).fit(calib)
    # a single decisive event (a Layer-0 secret→egress spike) — caught by w=1
    attack = [rng.uniform(0.0, 0.2) for _ in range(25)] + [0.95] + [rng.uniform(0.0, 0.2) for _ in range(5)]
    assert conf.flag("quiet", attack)


def test_session_conformal_unknown_role_never_flags():
    from lucin.behavioral.session_scoring import SessionConformalThreshold
    conf = SessionConformalThreshold().fit({"r": [[0.1, 0.2, 0.1]]})
    assert not conf.flag("unknown", [0.99, 0.99, 0.99])
