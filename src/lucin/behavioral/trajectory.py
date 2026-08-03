"""Event templating and trajectory feature engineering.

Blueprint §6.2, Codex §4.

This module implements the "craft that is the actual edge" per ICSE 2022
(arXiv:2202.04301): F1 swings 0.73→0.10 purely from the event parser. [VERIFIED]

How a raw tool call becomes a stable, low-cardinality symbol — and how to
extract the velocity and ratio features that make behavioral baselining work.

Three classes:
  EventTemplater    — raw tool call → canonical symbol (the parser)
  DecayingCounter   — exponentially-decayed velocity counter, the standard
                      primitive in streaming fraud and abuse detection
  TransitionSurprisal — k-order Markov surprisal on event-key sequences
  TrajectoryFeaturizer — combines the above into a feature vector per event

Designed to have identical logic offline (training) and online (inference)
so training-serving skew is structurally impossible. [HIGH-CONF]

Pure Python + stdlib only.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# 1. Event Templater — the parser
# ---------------------------------------------------------------------------

# Internal-destination suffixes: calls to these stay within the trust boundary
_INTERNAL_SUFFIXES = (
    ".internal", ".svc.cluster.local", ".svc", ".local",
    "localhost", "127.0.0.1", "::1",
)

# Tool-name prefixes that indicate high-privilege operations
_SENSITIVE_PREFIXES = (
    "read_secret", "get_secret", "read_env", "get_env", "read_cred",
    "read_key", "fetch_key", "query_db", "query_database", "db_query",
    "list_users", "get_users", "read_file", "read_config",
)


def _extract_host(url: str) -> str:
    """Extract the hostname from a URL string, or return '' if none."""
    if "://" in url:
        rest = url.split("://", 1)[1]
        host = rest.split("/")[0].split("?")[0].split("#")[0]
        return host
    return url


def _target_class(tool_name: str, args: dict) -> str:
    """Classify the target of a tool call: 'external', 'internal', or 'none'.

    This single decision is the most important in the event template —
    an http_post to an external domain is categorically different from one
    to an internal service, even though both are NETWORK_ACCESS.
    """
    for key in ("url", "endpoint", "host", "destination", "target"):
        val = args.get(key, "")
        if isinstance(val, str) and val:
            host = _extract_host(val)
            if host:
                return "internal" if host.endswith(_INTERNAL_SUFFIXES) else "external"
    return "none"


def event_key(tool_name: str, args: dict | None = None) -> str:
    """Canonical event key: `tool_name:target_class`.

    This is the stable, low-cardinality symbol fed to the transition
    model and n-gram surprisal. Two calls with the same key are
    considered the same event type for behavioral baselining purposes.

    Examples:
      http_post + url=external  → "http_post:external"
      http_post + url=internal  → "http_post:internal"
      read_file + no url        → "read_file:none"
    """
    tc = _target_class(tool_name, args or {})
    return f"{tool_name}:{tc}"


def is_sensitive_tool(tool_name: str) -> bool:
    """Return True if the tool name suggests access to sensitive data."""
    low = tool_name.lower()
    return any(low.startswith(p) for p in _SENSITIVE_PREFIXES)


# ---------------------------------------------------------------------------
# 2. DecayingCounter — exponentially-decayed velocity (streaming-fraud style)
# ---------------------------------------------------------------------------

@dataclass
class DecayingCounter:
    """Exponentially-decayed event velocity counter.

    Equivalent to a leaky integrator with half-life `half_life_s`.
    Increments by `amount` on each bump; decays continuously with time.

    The same formula is used offline (on historical timestamps) and online
    (on wall-clock time), so there is no training-serving skew. [HIGH-CONF]

    Example: secret_reads per 60 seconds, decayed.
        c = DecayingCounter(half_life_s=60)
        c.bump(t1)
        c.bump(t2)
        rate = c.read(t3)   # events per half-life window
    """
    half_life_s: float
    _value: float = field(default=0.0, init=False)
    _last_t: float = field(default=0.0, init=False)

    def _decay(self, now: float) -> float:
        if self._last_t == 0.0:
            return self._value
        elapsed = max(0.0, now - self._last_t)
        # Cap exponent to avoid overflow on very long gaps (> ~1100 half-lives → 0)
        exponent = min(elapsed / self.half_life_s, 1100.0)
        return self._value * (0.5 ** exponent)

    def bump(self, now: float, amount: float = 1.0) -> None:
        self._value = self._decay(now) + amount
        self._last_t = now

    def read(self, now: float) -> float:
        return self._decay(now)

    def reset(self) -> None:
        self._value = 0.0
        self._last_t = 0.0


# ---------------------------------------------------------------------------
# 3. TransitionSurprisal — k-order Markov surprisal
# ---------------------------------------------------------------------------

class TransitionSurprisal:
    """k-order Markov transition surprisal over event key sequences.

    Surprisal = −log P(next_key | ctx_k) under a Laplace-smoothed model.

    High surprisal = the agent just took a step it has never (or rarely)
    taken from this context before. A single near-zero-probability
    transition (e.g. read_secrets:none → http_post:external) is often
    THE signal in an exfiltration attack. [VERIFIED: Blueprint §6.2]

    Usage (prequential — surprisal before learning):
        ts = TransitionSurprisal(k=1)
        for key in event_stream:
            s = ts.surprisal(ctx, key)    # high = surprising
            ts.learn(ctx, key)
            ctx = (*ctx[1:], key)         # advance context
    """

    def __init__(self, k: int = 1, alpha: float = 0.5):
        self.k = k
        self.alpha = alpha                         # Laplace smoothing
        self._ctx_counts:   dict[tuple, int] = defaultdict(int)
        self._trans_counts: dict[tuple, int] = defaultdict(int)
        self._vocab:        set[str]          = set()

    def surprisal(self, ctx: tuple[str, ...], nxt: str) -> float:
        """−log P(nxt | ctx) under Laplace smoothing. Higher = more surprising."""
        self._vocab.add(nxt)
        v = max(len(self._vocab), 1)
        num = self._trans_counts[(ctx, nxt)] + self.alpha
        den = self._ctx_counts[ctx] + self.alpha * v
        return -math.log(num / den)

    def learn(self, ctx: tuple[str, ...], nxt: str) -> None:
        """Update the model with the observed (ctx → nxt) transition."""
        self._vocab.add(nxt)
        self._ctx_counts[ctx] += 1
        self._trans_counts[(ctx, nxt)] += 1

    def reset(self) -> None:
        self._ctx_counts.clear()
        self._trans_counts.clear()
        self._vocab.clear()


# ---------------------------------------------------------------------------
# 4. TrajectoryFeaturizer — the complete feature vector per event
# ---------------------------------------------------------------------------

@dataclass
class EventFeatureVector:
    """Feature vector for one observed tool-call event.

    Consumed by the streaming anomaly detector (HST + LODA) and
    later by the XGBoost stacker when labels arrive.
    """
    event_key: str                # canonical symbol (e.g. "http_post:external")
    egress_ratio: float           # external-egress calls / total calls (window)
    secret_read_velocity: float   # decayed count of sensitive reads
    total_velocity: float         # decayed total event rate
    transition_surprisal: float   # −log P(this key | last key)
    is_sensitive_tool: bool       # tool name suggests sensitive data access
    role_egress_ratio_z: float    # z-score vs role prior (0 until priors exist)

    def to_vector(self) -> list[float]:
        """Numeric feature vector for the streaming detector."""
        return [
            self.egress_ratio,
            self.secret_read_velocity,
            self.total_velocity,
            self.transition_surprisal,
            1.0 if self.is_sensitive_tool else 0.0,
            self.role_egress_ratio_z,
        ]

    @property
    def feature_names(self) -> list[str]:
        return [
            "egress_ratio",
            "secret_read_velocity",
            "total_velocity",
            "transition_surprisal",
            "is_sensitive_tool",
            "role_egress_ratio_z",
        ]


class TrajectoryFeaturizer:
    """Converts raw tool-call events into EventFeatureVector instances.

    One instance per agent-role (shares the transition model and counters).
    Uses prequential scoring: compute features BEFORE updating state, so
    the same logic applies in training and inference (no skew).

    role_prior: optional dict {feature_name: (mean, std)} for z-scoring
    against the role's learned baseline.
    """

    def __init__(self, role_prior: dict[str, tuple[float, float]] | None = None,
                 egress_half_life_s: float = 60.0,
                 secret_half_life_s: float = 60.0,
                 total_half_life_s:  float = 30.0,
                 ctx_k: int = 1):
        self._prior = role_prior or {}
        self._egress_ctr  = DecayingCounter(half_life_s=egress_half_life_s)
        self._secret_ctr  = DecayingCounter(half_life_s=secret_half_life_s)
        self._total_ctr   = DecayingCounter(half_life_s=total_half_life_s)
        self._ts = TransitionSurprisal(k=ctx_k)
        self._ctx: tuple[str, ...] = ("<start>",) * ctx_k

    def observe(self, tool_name: str, args: dict | None = None,
                now: float | None = None) -> EventFeatureVector:
        """Compute features for the event, THEN update state (prequential)."""
        now = now or time.time()
        args = args or {}
        key = event_key(tool_name, args)
        tc  = _target_class(tool_name, args)

        # --- score BEFORE learning (prequential) ---
        surp = self._ts.surprisal(self._ctx, key)
        egress  = self._egress_ctr.read(now)
        secret  = self._secret_ctr.read(now)
        total   = self._total_ctr.read(now)
        ratio   = egress / max(total, 1e-9)
        sensitive = is_sensitive_tool(tool_name)

        # z-score vs role prior (0 if no prior yet).
        # Variance floor: a homogeneous baseline drives std → 0, which makes the
        # z-score explode on tiny natural fluctuations (the classic zero-variance
        # false-positive trap). egress_ratio ∈ [0,1], so we never claim to know
        # it to better than ±0.05 — the floor caps z at a sane magnitude.
        z_ratio = 0.0
        if "egress_ratio" in self._prior:
            mean, std = self._prior["egress_ratio"]
            z_ratio = (ratio - mean) / max(std, 0.05)

        fv = EventFeatureVector(
            event_key=key,
            egress_ratio=ratio,
            secret_read_velocity=secret,
            total_velocity=total,
            transition_surprisal=surp,
            is_sensitive_tool=sensitive,
            role_egress_ratio_z=z_ratio,
        )

        # --- update state AFTER scoring ---
        self._ts.learn(self._ctx, key)
        self._ctx = (*self._ctx[1:], key)
        self._total_ctr.bump(now)
        if tc == "external":
            self._egress_ctr.bump(now)
        if sensitive:
            self._secret_ctr.bump(now)

        return fv

    def reset(self) -> None:
        self._egress_ctr.reset()
        self._secret_ctr.reset()
        self._total_ctr.reset()
        self._ts.reset()
        self._ctx = ("<start>",) * self._ts.k
