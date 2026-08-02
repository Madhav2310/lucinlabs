"""Behavioral-layer SMOKE TEST on a labelled synthetic corpus.

    python benchmarks/behavioral_eval.py [--benign N] [--attacks M]

*** THIS IS A SMOKE TEST, NOT DETECTION EVIDENCE. ***
Every number here (the ~3.75% benign session false-positive rate, the per-attack
detection rates, PR-AUC) is CIRCULAR: the benign traffic, the calibration set,
and the test set are all produced by the SAME synthetic generator
(behavioral/trace_gen.py). Train / calibrate / test on one generator measures
only that the pipeline is internally consistent and runs end-to-end — it does
NOT measure real-world false-positive or recall performance. Per Anti-Slop rules
2 and 3 (external truth over internal polish), these figures MUST NOT be cited as
a validated detection claim. They become evidence only when re-run on third-party
agent traces we do not generate. Until then: "smoke test passed", not "3.75% FP".

Reports (all on SYNTHETIC, self-generated data — reproducible, but circular as
above; the corpus is adversarial to naive detection: benign roles legitimately
read secrets and egress externally, so a naive detector WILL false-positive here):

  1. PR-AUC + precision@k over all post-warmup events
  2. Benign false-positive rate at the operating threshold  <-- the number that
     matters most for a security tool
  3. Per-attack-type detection rate, EVASIVE (L4) vs non-evasive, stated separately
  4. Train-serve parity (same trace twice → bit-identical scores)
  5. Calibration: isotonic Brier improvement + Mondrian per-role false-alarm rate
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

import random as _random
from lucin.behavioral.trace_gen import build_corpus, benign_session, EVASIVE_ATTACKS, ROLE_NAMES
from lucin.behavioral.monitor import AgentMonitor
from lucin.behavioral.baselines import RoleBaselineManager
from lucin.behavioral.score_calibration import IsotonicCalibrator, MondrianConformal

WARMUP = 15
HST_WINDOW = 40
THRESHOLD = 0.7


def _train_role_monitor(role: str, train_sessions: list[list[dict]]) -> AgentMonitor:
    mgr = RoleBaselineManager()
    mon = AgentMonitor(role=role, warmup_events=WARMUP, threshold=THRESHOLD,
                       hst_window=HST_WINDOW, baseline_manager=mgr, role_deviation=True)
    for evs in train_sessions:
        s = mon.new_session()
        for e in evs:
            s.observe(e["tool"], e["args"], timestamp=e["t"])
        mon.learn_from(s)
    return mon


def _score_session(mon: AgentMonitor, events: list[dict]):
    """Return list of (score, label, is_alert) for post-warmup events."""
    s = mon.new_session()
    out = []
    for i, e in enumerate(events):
        ev = s.observe(e["tool"], e["args"], timestamp=e["t"])
        if i >= WARMUP:
            out.append((ev.score.score, e["label"], ev.alert))
    return out


def _eval_one_role(task: tuple) -> dict:
    """Worker: train + score all sessions for ONE role. Fully independent →
    run in a separate PROCESS (river HST is CPU-bound pure Python; the GIL makes
    threads useless here, but processes give near-linear speedup across cores)."""
    role, train_sessions, test_benign, attack_items, calib_n, calib_seed = task
    # 10 benign sessions are plenty to learn a role baseline; more just slows
    # scoring without improving the baseline.
    mon = _train_role_monitor(role, train_sessions[:10])

    # Calibration: score a FRESH held-out benign set (NOT the baseline-training
    # sessions — scoring those is contaminated: the baseline adapted to them, so
    # they score artificially low and the threshold comes out too low). These are
    # generated here, unseen by the baseline, exactly like the test set → the
    # conformal coverage guarantee is valid. calib_n must be >= ~19 for α=0.05.
    crng = _random.Random(calib_seed)
    calib_events = [benign_session(role, crng) for _ in range(calib_n)]
    calib_sessions = [[sc for sc, _, _ in _score_session(mon, evs)] for evs in calib_events]

    scores, labels = [], []
    benign_scores: list[float] = []
    benign_test_score_lists: list[list[float]] = []
    for evs in test_benign:
        row_scores = []
        for sc, lab, alert in _score_session(mon, evs):
            scores.append(sc); labels.append(lab); row_scores.append(sc)
            if lab == 0:
                benign_scores.append(sc)
        benign_test_score_lists.append(row_scores)

    benign_mean = sum(benign_scores) / len(benign_scores) if benign_scores else 0.0
    attack_sep: dict[str, list[float]] = {}
    attack_session_scores: list[tuple[str, list[float]]] = []
    for it in attack_items:
        a, evs = it["attack"], it["events"]
        rows = _score_session(mon, evs)
        span = [sc for sc, lab, _ in rows if lab == 1]
        row_scores = []
        for sc, lab, al in rows:
            scores.append(sc); labels.append(lab); row_scores.append(sc)
        attack_session_scores.append((a, row_scores))
        if span:
            attack_sep.setdefault(a, []).append(sum(span) / len(span) - benign_mean)

    return {"role": role, "scores": scores, "labels": labels,
            "benign_scores": benign_scores, "attack_sep": attack_sep,
            "calib_sessions": calib_sessions,
            "benign_test_score_lists": benign_test_score_lists,
            "attack_session_scores": attack_session_scores}


SCORE_CACHE = str(Path(__file__).parent / "behavioral_scores_cache.json")


def _produce_per_role(benign_per_role: int, attack_per_type: int, seed: int,
                      workers: int | None) -> list[dict]:
    """SLOW step: score the whole corpus (river HST). Parallel, one proc/role."""
    from multiprocessing import Pool
    corpus = build_corpus(seed=seed, benign_per_role=benign_per_role,
                          attack_per_type=attack_per_type)
    roles = list(corpus["train"].keys())
    calib_n = 120  # need >= 1/(α/2) ≈ 80 for a real (1-α/2) quantile (not clamped max)
    tasks = [(r, corpus["train"][r], corpus["test_benign"][r],
              [it for it in corpus["test_attacks"] if it["role"] == r],
              calib_n, 9000 + i) for i, r in enumerate(roles)]
    workers = workers or min(len(tasks), (os.cpu_count() or 2))
    per_role = []
    with Pool(processes=workers) as pool:
        for res in pool.imap_unordered(_eval_one_role, tasks):
            per_role.append(res)
            print(f"    [role done] {res['role']:14s} events={len(res['scores'])} "
                  f"benign_test_sessions={len(res['benign_test_score_lists'])}", flush=True)
    return per_role


def evaluate(benign_per_role: int = 8, attack_per_type: int = 3, seed: int = 0,
             workers: int | None = None, cache: str | None = None,
             from_cache: bool = False) -> dict:
    """Score (slow) then compute session metrics (fast).

    OPTIMIZATION: per-event scores are a fixed function of (corpus, monitor
    config); the session-level aggregation is milliseconds. So we dump the
    expensive scores to `cache` and can re-derive all session-level metrics
    instantly with from_cache=True — no need to re-score to tune windows/alpha.
    """
    import json
    from sklearn.metrics import average_precision_score

    cache = cache or SCORE_CACHE
    if from_cache and os.path.exists(cache):
        with open(cache) as f:
            per_role = json.load(f)
        print(f"    [loaded cached scores from {cache}]", flush=True)
    else:
        per_role = _produce_per_role(benign_per_role, attack_per_type, seed, workers)
        with open(cache, "w") as f:
            json.dump(per_role, f)
        print(f"    [dumped scores to {cache} — re-tune session logic with --from-cache]",
              flush=True)

    # --- aggregate across roles ---
    scores = [s for r in per_role for s in r["scores"]]
    labels = [l for r in per_role for l in r["labels"]]
    benign_scores_by_role = {r["role"]: r["benign_scores"] for r in per_role}
    attack_sep: dict[str, list[float]] = {}
    for r in per_role:
        for a, v in r["attack_sep"].items():
            attack_sep.setdefault(a, []).extend(v)

    # ===== SESSION-LEVEL scoring (the redesign) =====
    from lucin.behavioral.session_scoring import SessionConformalThreshold
    ALPHA = 0.05
    calib = {r["role"]: r["calib_sessions"] for r in per_role}
    sess = SessionConformalThreshold(alpha=ALPHA, windows=(1, 5)).fit(calib)

    # benign SESSION false-alarm rate (test-benign, disjoint from calibration)
    benign_sessions = benign_flagged_sessions = 0
    for r in per_role:
        for sc_list in r["benign_test_score_lists"]:
            benign_sessions += 1
            if sess.flag(r["role"], sc_list):
                benign_flagged_sessions += 1
    session_fp = benign_flagged_sessions / benign_sessions if benign_sessions else 0.0

    # attack SESSION detection per type (session-level flag)
    sess_detect: dict[str, list[bool]] = {}
    for r in per_role:
        for a, sc_list in r["attack_session_scores"]:
            sess_detect.setdefault(a, []).append(sess.flag(r["role"], sc_list))
    sess_det_rate = {a: round(sum(v) / len(v), 3) for a, v in sess_detect.items()}

    # ===== per-EVENT metrics (kept for comparison / diagnosis) =====
    pr_auc = average_precision_score(labels, scores) if any(labels) else 0.0
    k = sum(labels)
    top = sorted(range(len(scores)), key=lambda i: -scores[i])[:k]
    precision_at_k = sum(labels[i] for i in top) / k if k else 0.0
    benign_total = sum(1 for l in labels if l == 0)
    ev_fp = sum(1 for sc, l in zip(scores, labels) if l == 0 and sc > THRESHOLD)
    benign_event_fp = ev_fp / benign_total if benign_total else 0.0

    sep_rate = {a: round(sum(v) / len(v), 3) for a, v in attack_sep.items()}
    non_evasive = [a for a in sess_det_rate if a not in EVASIVE_ATTACKS]
    evasive = [a for a in sess_det_rate if a in EVASIVE_ATTACKS]

    iso = IsotonicCalibrator().fit(scores, labels)
    brier = iso.brier_improvement(scores, labels)

    return {
        "n_events": len(scores),
        "n_attack_events": k,
        # session-level (the operating mode)
        "benign_SESSION_fp_rate": round(session_fp, 4),
        "session_alpha_target": ALPHA,
        "session_detection_non_evasive": {a: sess_det_rate[a] for a in non_evasive},
        "session_detection_evasive_L4": {a: sess_det_rate[a] for a in evasive},
        # per-event (diagnosis)
        "pr_auc": round(pr_auc, 3),
        "precision_at_k": round(precision_at_k, 3),
        "benign_event_fp_rate": round(benign_event_fp, 4),
        "span_separation": sep_rate,
        "brier": brier,
    }


def parity_test(seed: int = 0) -> dict:
    """Train-serve parity: scoring the same trace twice yields identical scores.

    This guards against wall-clock leakage / nondeterminism (training-serving
    skew). If the featurizer is a pure function of (events, timestamps), the two
    score sequences must be bit-identical.
    """
    corpus = build_corpus(seed=seed, benign_per_role=4, attack_per_type=1)
    role = ROLE_NAMES[0]
    mon = _train_role_monitor(role, corpus["train"][role])
    evs = corpus["test_benign"][role][0]
    r1 = [sc for sc, _, _ in _score_session(mon, evs)]
    # fresh monitor, identical training + trace
    mon2 = _train_role_monitor(role, corpus["train"][role])
    r2 = [sc for sc, _, _ in _score_session(mon2, evs)]
    identical = (r1 == r2)
    max_diff = max((abs(a - b) for a, b in zip(r1, r2)), default=0.0)
    return {"identical": identical, "max_abs_diff": max_diff, "n": len(r1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", type=int, default=8)
    ap.add_argument("--attacks", type=int, default=3)
    ap.add_argument("--from-cache", action="store_true",
                    help="skip re-scoring; recompute session metrics from cached scores (instant)")
    args = ap.parse_args()

    print("=" * 70)
    print("BEHAVIORAL LAYER — SMOKE TEST (SYNTHETIC, self-generated, CIRCULAR)")
    print("  NOT detection evidence: train/calibrate/test share one generator.")
    print("  Numbers below verify the pipeline runs; they do NOT validate FP/recall.")
    print("=" * 70)

    if not args.from_cache:
        par = parity_test()
        print(f"\nTrain-serve parity: identical={par['identical']} "
              f"max_abs_diff={par['max_abs_diff']:.2e} over {par['n']} events "
              f"({'PASS' if par['identical'] else 'FAIL — nondeterminism/skew'})")

    r = evaluate(benign_per_role=args.benign, attack_per_type=args.attacks,
                 from_cache=args.from_cache)
    print(f"\nEvents scored: {r['n_events']}  (attack events: {r['n_attack_events']})")
    print("\n--- SESSION-LEVEL (the operating mode) ---")
    print(f"benign SESSION FP rate:  {r['benign_SESSION_fp_rate']}  (target α={r['session_alpha_target']}) "
          f"<-- SMOKE-TEST number (circular, self-generated — NOT a validated FP claim)")
    print(f"attack SESSION detection:")
    print(f"  non-evasive:")
    for a, d in r["session_detection_non_evasive"].items():
        print(f"    {a:16s} {d}   (span_separation={r['span_separation'].get(a)})")
    print(f"  EVASIVE (L4) — expect low; honest limit:")
    for a, d in r["session_detection_evasive_L4"].items():
        print(f"    {a:16s} {d}   (span_separation={r['span_separation'].get(a)})")
    print("\n--- per-EVENT (diagnosis, NOT the operating mode) ---")
    print(f"PR-AUC {r['pr_auc']}  precision@k {r['precision_at_k']}  "
          f"benign event FP {r['benign_event_fp_rate']}")
    print(f"isotonic calibration: {r['brier']}")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
