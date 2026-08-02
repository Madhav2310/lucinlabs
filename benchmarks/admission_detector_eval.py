"""Train + evaluate the embedding admission detector on a REAL injection corpus.

    python benchmarks/admission_detector_eval.py            # train, eval, persist
    python benchmarks/admission_detector_eval.py --no-save  # eval only

Compares three admission classifiers on a HELD-OUT test split of
`deepset/prompt-injections` (the same corpus on which the regex gate measured
8.4% recall / 0% benign FP):
  1. regex-only        (RuleBasedInjectionClassifier — the current baseline)
  2. embedding-only    (local MiniLM ONNX -> sklearn head, threshold calibrated
                        on TRAIN to a fixed benign-FP budget)
  3. ensemble (OR)     (regex OR embedding — the shipped behavior)

Cost note: the MiniLM embedder is LOCAL onnxruntime (no API tokens, ~$0). The
corpus is fetched once and CACHED to disk, so reruns are offline and instant.
Precision-first: the threshold is chosen for a target benign FP, not max recall.
No tuning on the test split — threshold is fixed from TRAIN only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from lucin.guard.admission import RuleBasedInjectionClassifier  # noqa: E402
from lucin.guard.injection_detector import (  # noqa: E402
    InjectionDetector,
    MiniLMEmbedder,
)

_CACHE = Path(__file__).parent / "corpus_cache" / "deepset_prompt_injections.json"
TARGET_BENIGN_FP = 0.01   # spend at most ~1% benign FP; take whatever recall it buys
SEED = 0
TEST_FRAC = 0.30


def load_corpus() -> list[tuple[str, int]]:
    """Cached fetch: disk first, else HF datasets-server (then cache)."""
    if _CACHE.exists():
        rows = json.loads(_CACHE.read_text())
        return [(r["text"], int(r["label"])) for r in rows]
    from admission_real_corpus import fetch_corpus  # reuse the proven fetch + CA

    corpus = fetch_corpus("train")
    _CACHE.parent.mkdir(parents=True, exist_ok=True)
    _CACHE.write_text(json.dumps([{"text": t, "label": l} for t, l in corpus]))
    return corpus


def _metrics(pred: np.ndarray, y: np.ndarray) -> tuple[float, float, int, int]:
    inj = y == 1
    ben = y == 0
    recall = float(pred[inj].mean()) if inj.any() else 0.0
    benign_fp = float(pred[ben].mean()) if ben.any() else 0.0
    return recall, benign_fp, int(pred[inj].sum()), int(pred[ben].sum())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args()

    print("=" * 72)
    print("ADMISSION DETECTOR — embedding vs regex vs ensemble (deepset, held-out)")
    print("=" * 72)

    # Prefer the semantic MiniLM backbone if its onnx assets are materialized;
    # otherwise use the always-available TF-IDF backbone (sklearn-only, offline).
    embedder = MiniLMEmbedder()
    backbone = "minilm" if embedder.available else "tfidf"
    if not embedder.available:
        print(f"MiniLM unavailable ({embedder._reason}) -> using TF-IDF backbone.")
    else:
        print("MiniLM onnx assets present -> using semantic embedding backbone.")

    corpus = load_corpus()
    texts = [t for t, _ in corpus]
    y = np.array([l for _, l in corpus], dtype=int)
    print(f"corpus: {len(texts)} rows  |  injections={int(y.sum())}  "
          f"benign={int((y == 0).sum())}  (cached={_CACHE.exists()})")

    # Honest 3-way split (fixed seed): FIT the model on `fit`, choose the
    # threshold on a SEPARATE `calib` split, report on untouched `test`. The
    # threshold must never see the data the model trained on, or it won't
    # generalize (that was the 14.6%-test-FP failure with a train-derived one).
    from sklearn.model_selection import train_test_split

    tr_i, te_i = train_test_split(
        np.arange(len(texts)), test_size=TEST_FRAC, random_state=SEED, stratify=y
    )
    fit_i, ca_i = train_test_split(
        tr_i, test_size=0.30, random_state=SEED, stratify=y[tr_i]
    )
    fit_txt, fit_y = [texts[i] for i in fit_i], y[fit_i]
    ca_txt, ca_y = [texts[i] for i in ca_i], y[ca_i]
    te_txt, te_y = [texts[i] for i in te_i], y[te_i]
    print(f"split: fit={len(fit_txt)}  calib={len(ca_txt)}  test={len(te_txt)}  seed={SEED}")

    det = InjectionDetector(backbone=backbone,
                            featurizer=embedder if backbone == "minilm" else None)
    det.fit(fit_txt, fit_y)
    thr = det.calibrate_threshold(ca_txt, ca_y, target_benign_fp=TARGET_BENIGN_FP)
    ca_r, ca_fp, _, _ = _metrics(det.scores(ca_txt) >= det.threshold, ca_y)
    print(f"head trained ({backbone}); threshold={thr:.4f} "
          f"(chosen on calib for benign FP<={TARGET_BENIGN_FP:.0%}; "
          f"calib recall={ca_r:.1%} calib FP={ca_fp:.1%})")

    # --- evaluate on TEST ---
    rule = RuleBasedInjectionClassifier()
    regex_pred = np.array([rule.classify(t)[0] for t in te_txt], dtype=bool)
    embed_scores = det.scores(te_txt)
    embed_pred = embed_scores >= det.threshold
    ensemble_pred = regex_pred | embed_pred

    rows = [
        ("regex-only (baseline)", regex_pred),
        ("embedding-only", embed_pred),
        ("ensemble (regex OR embed)", ensemble_pred),
    ]
    print(f"\n{'classifier':30s} {'recall':>8s} {'benign-FP':>10s}  (inj hit / benign flagged)")
    print("-" * 72)
    results = {}
    for name, pred in rows:
        r, fp, hit, flg = _metrics(pred, te_y)
        results[name] = {"recall": r, "benign_fp": fp}
        print(f"{name:30s} {r:>7.1%} {fp:>10.1%}   ({hit}/{int((te_y==1).sum())} inj, "
              f"{flg}/{int((te_y==0).sum())} benign)")

    base = results["regex-only (baseline)"]["recall"]
    ens = results["ensemble (regex OR embed)"]["recall"]
    ens_fp = results["ensemble (regex OR embed)"]["benign_fp"]
    print("-" * 72)
    print(f"Ensemble lifts recall {base:.1%} -> {ens:.1%} "
          f"({ens - base:+.1%}) at {ens_fp:.1%} benign FP on held-out test.")

    if not args.no_save:
        path = det.save()
        print(f"persisted embedding head -> {path}")

    print("\nHonest limits: single corpus (deepset, English, ~546 rows); recall is")
    print("on THIS distribution — cross-dataset generalization not yet measured.")
    print("Threshold chosen on a separate calib split (no test-set tuning).")
    print("Backbone is local + offline (sklearn TF-IDF here; MiniLM onnx if")
    print("materialized) — 0 API tokens, $0. Precision-first: 1% benign-FP budget.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
