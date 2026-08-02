"""Unit tests for the behavioral baseline layer (baselines.py, layered_monitor.py).

MATURITY NOTE: these exercise author-constructed synthetic input only. They do NOT
validate detection quality on real agent traces.
"""

from __future__ import annotations

import math

import pytest

from lucin.behavioral.baselines import (
    RolePriorStore,
    RoleBaselineManager,
    empirical_bayes_shrink,
    DEFAULT_PRIOR_STD,
)
from lucin.behavioral.monitor import FEATURE_NAMES
from lucin.behavioral.trajectory import EventFeatureVector


# --------------------------------------------------------------------------- #
# import smoke                                                                 #
# --------------------------------------------------------------------------- #

def test_imports_smoke():
    assert callable(empirical_bayes_shrink)
    assert RolePriorStore is not None
    assert RoleBaselineManager is not None


def test_layered_monitor_imports():
    from lucin.behavioral.layered_monitor import LayeredMonitor  # noqa: F401
    assert LayeredMonitor is not None


# --------------------------------------------------------------------------- #
# empirical-Bayes shrinkage direction                                          #
# --------------------------------------------------------------------------- #

def test_shrinkage_small_n_moves_toward_prior():
    # A confident (small-variance) prior with a tiny sample: result hugs the prior.
    prior_mean, prior_var = 0.0, 0.25
    sample_mean, sample_var = 10.0, 1.0
    m, _ = empirical_bayes_shrink(sample_mean, sample_var, sample_n=1,
                                  prior_mean=prior_mean, prior_var=prior_var)
    assert abs(m - prior_mean) < abs(m - sample_mean)


def test_shrinkage_large_n_moves_toward_sample():
    prior_mean, prior_var = 0.0, 1.0
    sample_mean, sample_var = 10.0, 1.0
    m, _ = empirical_bayes_shrink(sample_mean, sample_var, sample_n=10_000,
                                  prior_mean=prior_mean, prior_var=prior_var)
    assert abs(m - sample_mean) < abs(m - prior_mean)
    assert m == pytest.approx(sample_mean, abs=0.05)


def test_shrinkage_monotonic_in_n():
    # As n grows, the shrunk mean moves monotonically from prior toward sample.
    prior_mean, sample_mean = 0.0, 5.0
    prev = prior_mean
    for n in (1, 2, 5, 20, 100, 1000):
        m, _ = empirical_bayes_shrink(sample_mean, 1.0, n, prior_mean, 1.0)
        assert m >= prev - 1e-9
        prev = m
    assert prev == pytest.approx(sample_mean, abs=0.05)


def test_shrinkage_zero_n_returns_prior():
    m, v = empirical_bayes_shrink(9.0, 2.0, 0, prior_mean=1.0, prior_var=3.0)
    assert m == 1.0 and v == 3.0


# --------------------------------------------------------------------------- #
# RolePriorStore save/load round-trip                                          #
# --------------------------------------------------------------------------- #

def test_store_get_update():
    store = RolePriorStore()
    assert store.get("support") is None
    stats = {f: (float(i), 1.0 + i) for i, f in enumerate(FEATURE_NAMES)}
    store.update("support", stats)
    got = store.get("support")
    assert got is not None
    for f in FEATURE_NAMES:
        assert got[f] == pytest.approx(stats[f])


def test_store_save_load_roundtrip(tmp_path):
    path = tmp_path / "priors.json"
    store = RolePriorStore()
    stats = {f: (float(i) * 0.5, 2.0 + i) for i, f in enumerate(FEATURE_NAMES)}
    store.update("analyst", stats)
    store.save(path)
    assert path.exists()

    reloaded = RolePriorStore().load(path)
    got = reloaded.get("analyst")
    assert got is not None
    for f in FEATURE_NAMES:
        assert got[f][0] == pytest.approx(stats[f][0])
        assert got[f][1] == pytest.approx(stats[f][1])


def test_store_load_missing_file_is_noop(tmp_path):
    store = RolePriorStore().load(tmp_path / "does_not_exist.json")
    assert store.roles() == []


# --------------------------------------------------------------------------- #
# RoleBaselineManager dict shape + behaviour                                   #
# --------------------------------------------------------------------------- #

def _make_fv(egress: float) -> EventFeatureVector:
    return EventFeatureVector(
        event_key="http_post:external",
        egress_ratio=egress,
        secret_read_velocity=0.0,
        total_velocity=1.0,
        transition_surprisal=0.5,
        is_sensitive_tool=False,
        role_egress_ratio_z=0.0,
    )


def test_manager_returns_correct_dict_shape():
    mgr = RoleBaselineManager()
    fvs = [_make_fv(0.1 * i) for i in range(20)]
    prior = mgr.observe_session("support", fvs)
    # keys == feature names, values == (mean, std) tuples of floats
    assert set(prior.keys()) == set(FEATURE_NAMES)
    for f, val in prior.items():
        assert isinstance(val, tuple) and len(val) == 2
        assert all(isinstance(x, float) for x in val)
        assert val[1] > 0.0  # std strictly positive


def test_manager_prior_for_unseen_role_is_none():
    mgr = RoleBaselineManager()
    assert mgr.prior_for("never-seen") is None


def test_manager_accepts_raw_vectors():
    mgr = RoleBaselineManager()
    vectors = [_make_fv(0.2).to_vector() for _ in range(10)]
    prior = mgr.observe_session("raw", vectors)
    assert set(prior.keys()) == set(FEATURE_NAMES)


def test_manager_persists_and_reloads(tmp_path):
    path = tmp_path / "role_priors.json"
    mgr = RoleBaselineManager(store_path=path)
    mgr.observe_session("support", [_make_fv(0.3) for _ in range(15)])
    assert path.exists()

    mgr2 = RoleBaselineManager(store_path=path)
    prior = mgr2.prior_for("support")
    assert prior is not None
    assert set(prior.keys()) == set(FEATURE_NAMES)


def test_manager_shrinks_across_sessions():
    # First session establishes a prior; a second, larger, consistent session
    # should keep the egress mean near the observed value.
    mgr = RoleBaselineManager()
    mgr.observe_session("support", [_make_fv(0.5) for _ in range(50)])
    prior = mgr.observe_session("support", [_make_fv(0.5) for _ in range(200)])
    assert prior["egress_ratio"][0] == pytest.approx(0.5, abs=0.1)


# --------------------------------------------------------------------------- #
# LayeredMonitor synthetic stream                                              #
# --------------------------------------------------------------------------- #

def test_layered_monitor_runs_synthetic_stream():
    from lucin.behavioral.layered_monitor import LayeredMonitor

    lm = LayeredMonitor(role="support", drift_burn_in=10)
    t = 0.0
    for i in range(120):
        # benign-looking internal reads, then a burst of external posts
        if i < 80:
            lm.observe("read_config", args={"host": "db.internal"}, timestamp=t)
        else:
            lm.observe("http_post", args={"url": "https://evil.example.com"}, timestamp=t)
        t += 1.0

    assert isinstance(lm.drift_detected, bool)
    assert isinstance(lm.drift_points, list)
    assert all(isinstance(p, int) for p in lm.drift_points)
    # session actually recorded every event
    assert len(lm.session.events) == 120
