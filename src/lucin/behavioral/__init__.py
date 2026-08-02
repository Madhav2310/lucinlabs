"""Lucin behavioral analysis — statistical deviation scoring (NOT trained ML).

HONEST LABEL (corrected in Phase 0). This is a per-agent statistical baseline +
hand-weighted deviation scorer, borrowing the *framing* of payment-fraud detection
(per-entity baselines, contextual scoring, explainable risk score). It is NOT a
trained model and must not be marketed as machine learning. See `scoring.py` for
the full honest description.

What is real here:
1. Per-agent behavioral baselines (running statistics).
2. Contextual deviation scoring (frequency / temporal / parameter / structural /
   sequence), combined by fixed hand-set weights.
3. A 0-99 heuristic risk score with human-readable contributing factors.

What is NOT here (future work, gated on labeled data — see THE_BLUEPRINT §6.2):
the trained HST/LODA/DeepLog→XGBoost pipeline, calibration against a labeled
corpus, and any learned model. This module is the Blueprint's day-one
"unsupervised deviation-from-normal" layer, nothing more.
"""
