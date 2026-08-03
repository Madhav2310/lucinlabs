"""GUARD Layer-1 admission gate — spotlighting + classifier + ensemble judge.

MATURITY: L2 (scaffolded + unit-tested on author input; NOT validated against a
live LLM/framework).

Blueprint §6.2, "Layer 1 — admission gate (not inline; 3-10s LLM latency
budget)." This is the *prompt-defense* tier the blueprint labels "table-stakes
only" — empirical and SEP-bypassable, and therefore layered UNDER the
deterministic IFC gate in ifc_runtime.py, never a substitute for it.

Components (all pure-Python, no torch/transformers):
  - spotlight():        prompt-isolation of untrusted content
                        [datamarking / delimiting / base64] per arXiv:2403.14720
                        (reported >50% -> <2% injection ASR).
  - InjectionClassifier: rule-based default reusing the tool_poisoning regexes;
                        pluggable predict_fn for a fine-tuned DeBERTa/ModernBERT
                        model later (Blueprint §6.2). No model shipped here.
  - EnsembleJudge:      committee of N judge callables, majority vote
                        (arXiv:2504.18333 — a committee cuts judge-injection ASR
                        to 10-19% vs 73.8% single-model).
  - AdmissionGate:      spotlight -> classify -> judge, with a conformal-style
                        abstention band for uncertain scores.

Honest limits (hostile-reader test):
  - The default classifier is REGEX, not a trained model. It will miss novel /
    paraphrased injections and can over-fire on benign trigger-words (NotInject).
    The abstention band exists precisely because the score is not calibrated.
  - No metric in this docstring is measured on Lucin's own corpus; the
    percentages above are cited from the referenced papers, not reproduced here.
  - Spotlighting is a mitigation, not a proof. The provable control is the IFC
    gate, which runs regardless of what this layer decides.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable

from lucin.detectors.tool_poisoning import (
    INJECTION_INDICATORS,
    JAILBREAK_INDICATORS,
    MULTILANG_INJECTION_INDICATORS,
    PROMPT_EXTRACTION_INDICATORS,
    _deobfuscate,
)

# ---------------------------------------------------------------------------
# 1. Spotlighting / datamarking  (arXiv:2403.14720)
# ---------------------------------------------------------------------------

# A private, high-entropy marker token. In a real deployment this should be
# rotated per session so an attacker cannot predict and forge it. The point of
# spotlighting is to make the *boundary* between trusted instructions and
# untrusted data explicit and hard to spoof from inside the data.
_DEFAULT_MARKER = "⁢"          # INVISIBLE TIMES — unlikely in real prose
_DEFAULT_DELIMS = ("<<UNTRUSTED_DATA>>", "<</UNTRUSTED_DATA>>")


def spotlight(content: str, method: str = "datamarking", *,
              marker: str = _DEFAULT_MARKER,
              delims: tuple[str, str] = _DEFAULT_DELIMS) -> str:
    """Isolate untrusted `content` so a downstream LLM can tell data from
    instructions. Implements the three variants from arXiv:2403.14720.

    method:
      - "datamarking": interleave `marker` between every whitespace-split token,
        so the model sees a continuous signal that "this is data." The marker is
        stripped of semantic meaning but present throughout, which the paper
        shows the model learns to treat as a hard boundary.
      - "delimiting":  wrap the content in explicit begin/end delimiters.
      - "base64":      encode the content so any embedded imperative text is no
        longer directly readable as instructions by the model surface.

    Returns a transformed string. Always changes non-empty input.
    """
    if method == "datamarking":
        # Interleave the marker across word boundaries.
        parts = content.split(" ")
        marked = marker.join(parts)
        return f"{delims[0]}{marker}{marked}{marker}{delims[1]}"

    if method == "delimiting":
        return f"{delims[0]}\n{content}\n{delims[1]}"

    if method == "base64":
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        return (f"{delims[0]} (base64) {encoded} {delims[1]}")

    raise ValueError(
        f"unknown spotlight method {method!r}; "
        "expected 'datamarking', 'delimiting', or 'base64'"
    )


# ---------------------------------------------------------------------------
# 2. Injection classifier — rule-based default, model-pluggable
# ---------------------------------------------------------------------------

# Compile once. We combine the four indicator families from the tool-poisoning
# detector; each carries a per-family weight reflecting severity.
_RULE_FAMILIES: list[tuple[str, list[str], float]] = [
    ("injection",  INJECTION_INDICATORS,          0.34),
    ("jailbreak",  JAILBREAK_INDICATORS,          0.40),
    ("extraction", PROMPT_EXTRACTION_INDICATORS,  0.30),
    ("multilang",  MULTILANG_INJECTION_INDICATORS, 0.34),
]

_COMPILED_FAMILIES: list[tuple[str, list[tuple[str, re.Pattern]], float]] = [
    (name, [(p, re.compile(p, re.IGNORECASE)) for p in pats], w)
    for name, pats, w in _RULE_FAMILIES
]


@runtime_checkable
class InjectionClassifier(Protocol):
    """Interface for a prompt-injection classifier.

    A conforming classifier maps text to (is_injection, score, matched), where
    score in [0, 1] is a confidence and `matched` lists human-readable evidence.
    """

    def classify(self, text: str) -> tuple[bool, float, list[str]]:
        ...


@dataclass
class RuleBasedInjectionClassifier:
    """Default InjectionClassifier: regex families from tool_poisoning.py.

    Designed so a fine-tuned model (DeBERTa/ModernBERT per Blueprint §6.2) can be
    dropped in later WITHOUT importing torch here: pass `predict_fn`, a callable
    `str -> float in [0, 1]`. When provided, the score becomes
    max(rule_score, predict_fn(text)) so the model can only *raise* suspicion,
    never silently suppress a rule hit. Default is pure regex.
    """

    threshold: float = 0.30
    predict_fn: Callable[[str], float] | None = None
    deobfuscate: bool = True

    def classify(self, text: str) -> tuple[bool, float, list[str]]:
        if not text:
            return (False, 0.0, [])

        probe = _deobfuscate(text) if self.deobfuscate else text
        matched: list[str] = []
        score = 0.0

        for family, patterns, weight in _COMPILED_FAMILIES:
            # multilang family is matched on ORIGINAL text: _deobfuscate maps
            # homoglyphs to Latin and would break non-Latin patterns
            # (same rationale as detectors/tool_poisoning.py).
            target = text if family == "multilang" else probe
            for raw, rx in patterns:
                if rx.search(target):
                    matched.append(f"{family}:{raw}")
                    # Diminishing-returns accumulation: each additional hit
                    # adds `weight` of the remaining headroom toward 1.0.
                    score = score + weight * (1.0 - score)

        if self.predict_fn is not None:
            try:
                model_score = float(self.predict_fn(text))
            except Exception:
                model_score = 0.0
            score = max(score, min(max(model_score, 0.0), 1.0))

        return (score >= self.threshold, round(score, 4), matched)


# ---------------------------------------------------------------------------
# 3. Ensemble judge  (arXiv:2504.18333 — committee cuts judge-injection ASR)
# ---------------------------------------------------------------------------

# A single "judge" here is a callable str -> (is_injection, score, matched).
Judge = Callable[[str], tuple[bool, float, list[str]]]


@dataclass
class EnsembleVerdict:
    is_injection: bool
    score: float                       # mean score across judges
    votes: int                         # number of judges that flagged
    total: int                         # number of judges
    per_judge: list[tuple[bool, float, list[str]]] = field(default_factory=list)


class EnsembleJudge:
    """Majority-vote committee of judge callables.

    Rationale (arXiv:2504.18333): a single LLM judge is itself injectable
    (73.8% ASR); an anonymized committee that must agree drops that to 10-19%.
    We approximate the committee cheaply by applying the SAME rule-based
    classifier to DIFFERENT spotlightings of the input, so an attack tuned to
    slip past one presentation still faces the others. This is a structural
    diversity, not a claim of independence between the judges.

    Default committee (when `judges` is None): the rule-based classifier over
    raw / datamarked / base64 views of the content.
    """

    def __init__(self, judges: list[Judge] | None = None,
                 classifier: InjectionClassifier | None = None,
                 aggregate: str = "auto"):
        """aggregate:
          - "any": flag if ANY judge flags (correct for deterministic classifiers —
            a regex cannot be "injected", so OR-over-normalization-views maximizes
            recall without hurting precision).
          - "majority": strict majority (correct for INJECTABLE LLM judges, per
            arXiv:2504.18333 — a committee that must agree resists judge-injection).
          - "auto": "any" for the default rule-based committee, else "majority".

        NOTE: the default committee applies the classifier to NORMALIZATION views
        (raw + NFKC-normalized), NOT spotlighting views. Spotlighting obfuscates
        text, which defeats a regex — it is only sound as diversity for an LLM
        judge. Measured: spotlighting-committee scored 55% recall vs 65% for the
        raw classifier; normalization + OR restores/raises it without new FPs.
        """
        clf = classifier or RuleBasedInjectionClassifier()
        default_committee = judges is None
        if judges is None:
            import unicodedata
            judges = [
                lambda t: clf.classify(t),
                lambda t: clf.classify(unicodedata.normalize("NFKC", t)),
            ]
        self.judges = judges
        if aggregate == "auto":
            aggregate = "any" if default_committee else "majority"
        if aggregate not in ("any", "majority"):
            raise ValueError("aggregate must be 'any', 'majority', or 'auto'")
        self.aggregate = aggregate

    def judge(self, content: str) -> EnsembleVerdict:
        per_judge = [j(content) for j in self.judges]
        votes = sum(1 for is_inj, _, _ in per_judge if is_inj)
        total = len(per_judge)
        # Score = MAX across views for "any" (a hit in any normalization is real),
        # mean for majority (committee agreement strength).
        if self.aggregate == "any":
            agg_score = max((s for _, s, _ in per_judge), default=0.0)
            is_inj = votes >= 1
        else:
            agg_score = (sum(s for _, s, _ in per_judge) / total) if total else 0.0
            is_inj = votes * 2 > total
        return EnsembleVerdict(
            is_injection=is_inj,
            score=round(agg_score, 4),
            votes=votes,
            total=total,
            per_judge=per_judge,
        )


# ---------------------------------------------------------------------------
# 4. Admission gate — spotlight -> classify -> judge, with abstention
# ---------------------------------------------------------------------------

@dataclass
class AdmissionDecision:
    allow: bool
    score: float
    reasons: list[str] = field(default_factory=list)
    abstain: bool = False               # score fell in the uncertain band
    spotlighted: str = ""               # the isolated content that was judged


class AdmissionGate:
    """Composes spotlighting, classification, and the ensemble judge.

    admit(content, context) -> AdmissionDecision

    Decision logic:
      - Spotlight the untrusted content (default datamarking).
      - Run the ensemble judge on the RAW content (the judges spotlight
        internally as their diversity axis).
      - If the ensemble score lands inside [abstain_low, abstain_high],
        return abstain=True (conformal-style: refuse to auto-decide; escalate
        to a human / stronger judge). Outside the band, allow/deny by threshold.

    The abstention band is the honest substitute for calibrated probabilities:
    the regex score is NOT a true posterior, so we decline to make a hard call
    in the region where it is least trustworthy rather than guess.
    """

    def __init__(self, judge: EnsembleJudge | None = None, *,
                 abstain_low: float = 0.30,
                 abstain_high: float = 0.60,
                 spotlight_method: str = "datamarking"):
        if not (0.0 <= abstain_low <= abstain_high <= 1.0):
            raise ValueError("require 0 <= abstain_low <= abstain_high <= 1")
        self.judge = judge or EnsembleJudge()
        self.abstain_low = abstain_low
        self.abstain_high = abstain_high
        self.spotlight_method = spotlight_method

    def admit(self, content: str, context: dict | None = None) -> AdmissionDecision:
        context = context or {}
        spotlighted = spotlight(content, self.spotlight_method) if content else ""
        verdict = self.judge.judge(content)

        reasons: list[str] = [
            f"ensemble: {verdict.votes}/{verdict.total} judges flagged",
            f"score={verdict.score}",
        ]
        for is_inj, s, matched in verdict.per_judge:
            if matched:
                reasons.append(f"matched={matched[:3]}")
                break

        # Conformal-style abstention band.
        if self.abstain_low <= verdict.score < self.abstain_high:
            reasons.append(
                f"score in abstention band "
                f"[{self.abstain_low}, {self.abstain_high}) — escalate"
            )
            return AdmissionDecision(
                allow=False, score=verdict.score, reasons=reasons,
                abstain=True, spotlighted=spotlighted,
            )

        allow = not (verdict.is_injection or verdict.score >= self.abstain_high)
        if not allow:
            reasons.append("blocked: injection indicators above threshold")
        else:
            reasons.append("admitted: below injection threshold")

        return AdmissionDecision(
            allow=allow, score=verdict.score, reasons=reasons,
            abstain=False, spotlighted=spotlighted,
        )
