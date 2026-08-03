"""Trained prompt-injection detector — the real (non-regex) admission layer.

The regex admission classifier is precise but nearly blind on real, diverse
social-engineering injections (MEASURED: 8.4% recall on `deepset/prompt-injections`,
0% benign FP). This module adds a trained layer that catches the injections the
regex families miss (persona/roleplay/authority/context-confusion), while keeping
the precision-first brand.

Two pluggable backbones behind one interface:
  * TfidfFeaturizer  (DEFAULT) — char_wb + word n-gram TF-IDF. sklearn-only, no
    torch, no network, no model files, trains in <1s, fully picklable. This is a
    legitimate real detector (what many production injection filters actually
    are), not a placeholder. Lexical, so cross-corpus generalization is a stated
    limit — retrain/expand on more corpora to improve it.
  * MiniLMEmbedder   (OPT-IN, `backbone="minilm"`) — a local all-MiniLM-L6-v2
    ONNX export run via onnxruntime + tokenizers (offline, no torch). Semantic,
    stronger, but requires the onnx assets to be MATERIALIZED (in this repo they
    are git-LFS pointer stubs, so it is unavailable and we fall back to TF-IDF).

Design invariants (deliberate):
  * GRACEFUL DEGRADATION. If a backbone or the trained head is absent, the
    admission gate falls back to pure regex with NO crash (see
    `default_injection_detector` / `build_admission_gate`).
  * RAISE-ONLY. Wired as an extra OR judge (or `predict_fn`), the detector can
    only *raise* suspicion, never suppress a regex hit.
  * PRECISION-FIRST. The decision threshold is calibrated on TRAINING data to a
    target benign false-positive budget — never tuned on the test split.

Train / evaluate with `benchmarks/admission_detector_eval.py`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Sequence

import numpy as np

# Local MiniLM model dir (repo-root, outside the package). Override with
# LUCIN_MINILM_PATH. Kept out of the wheel; detector degrades without it.
_DEFAULT_MODEL_DIR = Path(__file__).resolve().parents[3].parent / "all-MiniLM-L6-v2"
_MODEL_DIR = Path(os.environ.get("LUCIN_MINILM_PATH", str(_DEFAULT_MODEL_DIR)))

# Where the trained head is persisted.
_HEAD_PATH = Path(__file__).resolve().parent / "models" / "injection_head.joblib"


# ---------------------------------------------------------------------------
# Backbones
# ---------------------------------------------------------------------------
class TfidfFeaturizer:
    """Char_wb (3-5) + word (1-2) n-gram TF-IDF. sklearn-only, picklable, offline."""

    def __init__(self):
        self.vec = None
        self.available = True
        self._reason = ""

    def fit(self, texts: Sequence[str]) -> "TfidfFeaturizer":
        from scipy.sparse import hstack
        from sklearn.feature_extraction.text import TfidfVectorizer

        # Regularized to generalize on small corpora: higher min_df + capped
        # features fight the 40k-features-vs-few-hundred-samples overfit that
        # otherwise makes a train-derived threshold collapse out-of-sample.
        self._char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                                     min_df=5, max_features=8000, sublinear_tf=True)
        self._word = TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                     min_df=3, max_features=8000, sublinear_tf=True,
                                     lowercase=True)
        texts = [t or "" for t in texts]
        self._char.fit(texts)
        self._word.fit(texts)
        self._hstack = hstack
        self.vec = True
        return self

    def transform(self, texts: Sequence[str]):
        if self.vec is None:
            raise RuntimeError("TfidfFeaturizer not fitted")
        texts = [t or "" for t in texts]
        return self._hstack([self._char.transform(texts),
                             self._word.transform(texts)]).tocsr()

    # pickled via joblib directly (TfidfVectorizer is picklable)


class MiniLMEmbedder:
    """Offline MiniLM sentence embeddings from a local ONNX export (no torch).

    encode(texts) -> (n, 384) float32, attention-masked mean-pool + L2 normalize
    (identical semantics to sentence-transformers). `available` is False when the
    onnx/tokenizer assets are missing or are git-LFS pointer stubs.
    """

    def __init__(self, model_dir: Path | str | None = None, max_length: int = 256):
        self.model_dir = Path(model_dir) if model_dir else _MODEL_DIR
        self.max_length = max_length
        self._tok = None
        self._sess = None
        self._input_names: set[str] = set()
        self.available = False
        self._reason = ""
        self._load()

    def _load(self) -> None:
        onnx_path = self.model_dir / "onnx" / "model.onnx"
        tok_path = self.model_dir / "tokenizer.json"
        if not onnx_path.exists() or not tok_path.exists():
            self._reason = f"assets missing under {self.model_dir}"
            return
        # Guard against git-LFS pointer stubs (a few hundred bytes, not a model).
        if onnx_path.stat().st_size < 100_000:
            self._reason = f"{onnx_path.name} is a git-LFS pointer stub (not materialized)"
            return
        try:
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except Exception as e:  # noqa: BLE001
            self._reason = f"runtime import failed: {e}"
            return
        try:
            tok = Tokenizer.from_file(str(tok_path))
            tok.enable_truncation(max_length=self.max_length)
            tok.enable_padding(pad_id=0, pad_token="[PAD]")
            sess = ort.InferenceSession(str(onnx_path),
                                        providers=["CPUExecutionProvider"])
            self._tok, self._sess = tok, sess
            self._input_names = {i.name for i in sess.get_inputs()}
            self.available = True
        except Exception as e:  # noqa: BLE001
            self._reason = f"load failed: {e}"

    def fit(self, texts: Sequence[str]) -> "MiniLMEmbedder":
        return self  # nothing to fit

    def transform(self, texts: Sequence[str]) -> np.ndarray:
        return self.encode(texts)

    def encode(self, texts: Sequence[str], batch_size: int = 32) -> np.ndarray:
        if not self.available:
            raise RuntimeError(f"MiniLMEmbedder unavailable: {self._reason}")
        out: list[np.ndarray] = []
        texts = [t if isinstance(t, str) else "" for t in texts]
        for start in range(0, len(texts), batch_size):
            batch = texts[start : start + batch_size]
            encs = self._tok.encode_batch(batch)
            mask = np.array([e.attention_mask for e in encs], dtype=np.int64)
            feed = {}
            if "input_ids" in self._input_names:
                feed["input_ids"] = np.array([e.ids for e in encs], dtype=np.int64)
            if "attention_mask" in self._input_names:
                feed["attention_mask"] = mask
            if "token_type_ids" in self._input_names:
                feed["token_type_ids"] = np.array([e.type_ids for e in encs],
                                                  dtype=np.int64)
            token_emb = self._sess.run(None, feed)[0]
            m = mask.astype(np.float32)[:, :, None]
            mean = (token_emb * m).sum(axis=1) / np.clip(m.sum(axis=1), 1e-9, None)
            norm = np.clip(np.linalg.norm(mean, axis=1, keepdims=True), 1e-12, None)
            out.append((mean / norm).astype(np.float32))
        return np.vstack(out) if out else np.zeros((0, 384), dtype=np.float32)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------
class InjectionDetector:
    """Trained text-injection classifier. Conforms to the InjectionClassifier Protocol.

    Backbone: TF-IDF (default) or MiniLM (opt-in, if assets materialized). Use
    `.classify(text)` as a judge, or `.proba(text)` as a `predict_fn`.
    """

    def __init__(self, backbone: str = "tfidf", featurizer=None, clf=None,
                 threshold: float = 0.5):
        if featurizer is not None:
            self.featurizer = featurizer
        elif backbone == "minilm":
            self.featurizer = MiniLMEmbedder()
        else:
            self.featurizer = TfidfFeaturizer()
        self.backbone = backbone
        self.clf = clf
        self.threshold = threshold

    @property
    def available(self) -> bool:
        return getattr(self.featurizer, "available", False) and self.clf is not None

    def _feat(self, texts: Sequence[str]):
        return self.featurizer.transform(texts)

    # --- training -----------------------------------------------------------
    def fit(self, texts: Sequence[str], labels: Sequence[int], *, C: float = 1.0):
        from sklearn.linear_model import LogisticRegression

        if hasattr(self.featurizer, "fit"):
            self.featurizer.fit(texts)
        X = self._feat(texts)
        y = np.asarray(labels, dtype=int)
        self.clf = LogisticRegression(C=C, class_weight="balanced", max_iter=3000)
        self.clf.fit(X, y)
        return self

    def scores(self, texts: Sequence[str]) -> np.ndarray:
        if not self.available:
            return np.zeros(len(texts), dtype=np.float32)
        return self.clf.predict_proba(self._feat(texts))[:, 1].astype(np.float32)

    def calibrate_threshold(self, texts: Sequence[str], labels: Sequence[int],
                            target_benign_fp: float = 0.01) -> float:
        """Lowest threshold whose benign FP on this set <= target (precision-first)."""
        s = self.scores(texts)
        y = np.asarray(labels, dtype=int)
        benign = s[y == 0]
        if len(benign) == 0:
            self.threshold = 0.5
            return self.threshold
        q = float(np.quantile(benign, 1.0 - target_benign_fp))
        self.threshold = min(1.0, q + 1e-6)
        return self.threshold

    # --- inference ----------------------------------------------------------
    def proba(self, text: str) -> float:
        if not self.available or not text:
            return 0.0
        try:
            return float(self.clf.predict_proba(self._feat([text]))[0, 1])
        except Exception:  # noqa: BLE001
            return 0.0

    def classify(self, text: str) -> tuple[bool, float, list[str]]:
        p = self.proba(text)
        matched = [f"{self.backbone}-injection:{p:.2f}"] if p >= self.threshold else []
        return (p >= self.threshold, round(p, 4), matched)

    # --- persistence --------------------------------------------------------
    def save(self, path: Path | str | None = None) -> Path:
        import joblib

        path = Path(path) if path else _HEAD_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        # MiniLM embedder holds an onnx session (not picklable) → store clf only
        # and recreate the embedder from assets on load. TF-IDF is picklable.
        feat = None if self.backbone == "minilm" else self.featurizer
        joblib.dump({"backbone": self.backbone, "featurizer": feat,
                     "clf": self.clf, "threshold": self.threshold}, path)
        return path

    @classmethod
    def load(cls, path: Path | str | None = None) -> "InjectionDetector":
        import joblib

        blob = joblib.load(Path(path) if path else _HEAD_PATH)
        backbone = blob.get("backbone", "tfidf")
        feat = blob.get("featurizer")
        if feat is None and backbone == "minilm":
            feat = MiniLMEmbedder()
        return cls(backbone=backbone, featurizer=feat, clf=blob["clf"],
                   threshold=blob.get("threshold", 0.5))


# Back-compat alias (earlier name).
EmbeddingInjectionDetector = InjectionDetector


def default_injection_detector() -> "InjectionDetector | None":
    """Load the persisted detector if the head exists and its backbone is available."""
    if not _HEAD_PATH.exists():
        return None
    try:
        det = InjectionDetector.load()
    except Exception:  # noqa: BLE001
        return None
    return det if det.available else None


def build_admission_gate(detector: "InjectionDetector | None" = None, **gate_kwargs):
    """AdmissionGate whose committee is regex(raw) + regex(NFKC) + trained detector, OR'd.

    aggregate="any": each detector keeps its OWN calibrated threshold and a flag
    from any one blocks — regex catches overt families, the trained detector
    catches the semantic/social-engineering ones regex misses. Falls back to the
    pure-regex committee when no trained detector is available.
    """
    import unicodedata

    from .admission import AdmissionGate, EnsembleJudge, RuleBasedInjectionClassifier

    det = detector if detector is not None else default_injection_detector()
    rule = RuleBasedInjectionClassifier()
    judges = [
        lambda t: rule.classify(t),
        lambda t: rule.classify(unicodedata.normalize("NFKC", t)),
    ]
    if det is not None and det.available:
        judges.append(lambda t: det.classify(t))
        # The detector emits CALIBRATED probabilities: its threshold already
        # encodes the target-FP operating point. Collapse the abstention band to
        # that threshold so we block iff score>=threshold and don't re-add FPs
        # from a regex-tuned band on a different score scale. (The band is kept
        # for the pure-regex gate, where uncalibrated scores are what it's for.)
        gate_kwargs.setdefault("abstain_low", det.threshold)
        gate_kwargs.setdefault("abstain_high", det.threshold)
    return AdmissionGate(judge=EnsembleJudge(judges=judges, aggregate="any"),
                         **gate_kwargs)
