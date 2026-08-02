"""MATURITY: L2 (scaffolded + unit-tested on author input; NOT validated on real agent traces).

Role-baseline persistence + empirical-Bayes cold-start for the behavioral layer.

AgentMonitor (monitor.py) already maintains an in-memory role prior and z-scores
new sessions against it. That prior is (a) not persisted across process restarts and
(b) naive on cold start — a role with 2 observed sessions is trusted as much as a
role with 2000. This module fixes both:

  RolePriorStore        — persist/load per-role feature priors to JSON on disk.
  empirical_bayes_shrink — James-Stein / Normal-Normal shrinkage toward the role
                           prior: few samples -> trust the prior; many -> trust the
                           sample. Solves the cold-start over-confidence problem.
  RoleBaselineManager   — glue: observe a session's feature vectors, shrink the
                           stored prior toward what was seen, and hand AgentMonitor
                           a prior in exactly the {feature_name: (mean, std)} shape
                           its `role_prior` argument expects.

The prior format is identical to what monitor.AgentMonitor / TrajectoryFeaturizer
consume: dict {feature_name: (mean, std)}. std is the spread of the feature
distribution (used for z-scoring), NOT the standard error of the mean.

Pure Python + stdlib. numpy is used only for the per-feature sample statistics.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from lucin.behavioral.monitor import FEATURE_NAMES

# When a role has never been seen, we start from a deliberately weak prior:
# mean 0, large std. A large prior variance makes the shrinkage weight climb to
# ~1 quickly, so the very first sessions are trusted (there is nothing better).
DEFAULT_PRIOR_MEAN = 0.0
DEFAULT_PRIOR_STD = 1.0e3
_MIN_STD = 1e-9


# ---------------------------------------------------------------------------
# 1. Empirical-Bayes / James-Stein shrinkage
# ---------------------------------------------------------------------------

def empirical_bayes_shrink(
    sample_mean: float,
    sample_var: float,
    sample_n: int,
    prior_mean: float,
    prior_var: float,
) -> tuple[float, float]:
    """Shrink a per-feature sample estimate toward the role prior.

    Normal-Normal conjugate / empirical-Bayes shrinkage. Treat the prior as if it
    were `kappa = sample_var / prior_var` pseudo-observations located at
    prior_mean. The posterior-mean weight on the observed sample is then the
    classic shrinkage weight:

        w = n / (n + sample_var / prior_var)          (VERIFIED closed form)

    which is the Normal-Normal posterior-mean weight
        w = (n / sigma^2) / (1 / tau^2 + n / sigma^2)
    with sigma^2 = sample_var (per-observation variance) and tau^2 = prior_var.

    Behaviour of w (the cold-start fix):
      * n small           -> w -> 0  -> trust the PRIOR
      * n large           -> w -> 1  -> trust the SAMPLE
      * prior_var large    (weak prior) -> w -> 1 quickly
      * prior_var small    (strong prior) -> needs many samples to move

    Reference: Efron & Morris (1975), "Data Analysis Using Stein's Estimator and
    Its Generalizations", JASA 70(350); Normal-Normal conjugacy, Gelman et al.,
    Bayesian Data Analysis, 3rd ed., ch. 2.

    Returns (shrunk_mean, shrunk_var). shrunk_var blends the sample and prior
    spread by the same weight so the returned std stays a usable z-score scale.
    """
    n = max(int(sample_n), 0)
    prior_var = max(float(prior_var), _MIN_STD**2)
    sample_var = max(float(sample_var), 0.0)

    if n == 0:
        return float(prior_mean), float(prior_var)

    # kappa = effective prior sample size. If the sample has zero variance we
    # still want the prior to count for something, so floor sample_var.
    kappa = max(sample_var, _MIN_STD**2) / prior_var
    w = n / (n + kappa)

    shrunk_mean = w * sample_mean + (1.0 - w) * prior_mean
    shrunk_var = w * sample_var + (1.0 - w) * prior_var
    return float(shrunk_mean), float(shrunk_var)


# ---------------------------------------------------------------------------
# 2. RolePriorStore — persistence
# ---------------------------------------------------------------------------

class RolePriorStore:
    """Persist/load per-role feature priors to JSON on disk.

    Internal shape: {role: {feature_name: [mean, std]}}. Exposed via get() as
    {feature_name: (mean, std)} — the tuple shape AgentMonitor.role_prior wants.
    """

    def __init__(self) -> None:
        self._priors: dict[str, dict[str, tuple[float, float]]] = {}

    def get(self, role: str) -> dict[str, tuple[float, float]] | None:
        """Return the stored prior for `role`, or None if unknown."""
        stats = self._priors.get(role)
        if stats is None:
            return None
        # Return a defensive copy with tuple values.
        return {f: (float(m), float(s)) for f, (m, s) in stats.items()}

    def update(self, role: str, stats: dict[str, tuple[float, float]]) -> None:
        """Set/replace the stored prior for `role`.

        stats: {feature_name: (mean, std)}. std is floored to avoid /0 downstream.
        """
        self._priors[role] = {
            f: (float(m), max(float(s), _MIN_STD)) for f, (m, s) in stats.items()
        }

    def roles(self) -> list[str]:
        return list(self._priors.keys())

    def save(self, path: str | Path) -> None:
        """Serialize all role priors to JSON at `path` (parents created)."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        serializable = {
            role: {f: [float(m), float(s)] for f, (m, s) in stats.items()}
            for role, stats in self._priors.items()
        }
        path.write_text(json.dumps(serializable, indent=2))

    def load(self, path: str | Path) -> "RolePriorStore":
        """Load role priors from JSON at `path`. No-op if the file is missing.

        Returns self so callers can chain: store = RolePriorStore().load(p).
        """
        path = Path(path)
        if not path.exists():
            return self
        data = json.loads(path.read_text())
        self._priors = {
            role: {f: (float(v[0]), max(float(v[1]), _MIN_STD)) for f, v in stats.items()}
            for role, stats in data.items()
        }
        return self


# ---------------------------------------------------------------------------
# 3. RoleBaselineManager — shrinkage over the store
# ---------------------------------------------------------------------------

def _vectors_from(feature_vectors) -> np.ndarray:
    """Coerce input into an (n_events, n_features) float array.

    Accepts a list of EventFeatureVector (anything with .to_vector()) or a list
    of already-numeric vectors.
    """
    rows: list[list[float]] = []
    for fv in feature_vectors:
        if hasattr(fv, "to_vector"):
            rows.append([float(x) for x in fv.to_vector()])
        else:
            rows.append([float(x) for x in fv])
    if not rows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=float)
    return np.asarray(rows, dtype=float)


class RoleBaselineManager:
    """Wraps RolePriorStore + empirical_bayes_shrink.

    observe_session(role, feature_vectors) folds a session's observations into the
    stored prior via shrinkage. prior_for(role) returns the current shrunk prior in
    the {feature_name: (mean, std)} shape AgentMonitor.role_prior expects.

    Usage:
        mgr = RoleBaselineManager(store_path=".lucin/role_priors.json")
        monitor = AgentMonitor(role="support")
        session = monitor.new_session()
        ...                              # session.observe(...) per tool call
        mgr.observe_session("support", [e.features for e in session.events])
        # next AgentMonitor for this role can be seeded:
        prior = mgr.prior_for("support")
    """

    def __init__(
        self,
        store: RolePriorStore | None = None,
        store_path: str | Path | None = None,
        feature_names: list[str] | None = None,
    ) -> None:
        self.feature_names = feature_names or list(FEATURE_NAMES)
        self._store_path = Path(store_path) if store_path else None
        if store is not None:
            self._store = store
        else:
            self._store = RolePriorStore()
            if self._store_path is not None:
                self._store.load(self._store_path)

    @property
    def store(self) -> RolePriorStore:
        return self._store

    def prior_for(self, role: str) -> dict[str, tuple[float, float]] | None:
        """Current shrunk prior for `role`, or None if the role is unseen."""
        return self._store.get(role)

    def observe_session(self, role: str, feature_vectors) -> dict[str, tuple[float, float]]:
        """Fold a session's feature vectors into the stored prior via shrinkage.

        For each feature: compute the session's sample mean/var/n, pull the existing
        stored prior (or the weak default), shrink the sample toward it, and store the
        result back. Returns the updated prior. Persists to disk if store_path was set.
        """
        arr = _vectors_from(feature_vectors)
        existing = self._store.get(role) or {}

        if arr.shape[0] == 0:
            # Nothing observed: keep whatever we had (or nothing).
            return existing

        n = arr.shape[0]
        sample_means = arr.mean(axis=0)
        # ddof=1 sample variance; with n==1 numpy yields nan, so guard.
        sample_vars = arr.var(axis=0, ddof=1) if n > 1 else np.zeros(arr.shape[1])

        updated: dict[str, tuple[float, float]] = {}
        for i, feat in enumerate(self.feature_names):
            if i >= arr.shape[1]:
                break
            prior_mean, prior_std = existing.get(
                feat, (DEFAULT_PRIOR_MEAN, DEFAULT_PRIOR_STD)
            )
            prior_var = max(prior_std, _MIN_STD) ** 2
            s_mean, s_var = empirical_bayes_shrink(
                sample_mean=float(sample_means[i]),
                sample_var=float(sample_vars[i]),
                sample_n=n,
                prior_mean=float(prior_mean),
                prior_var=float(prior_var),
            )
            updated[feat] = (s_mean, max(s_var, _MIN_STD**2) ** 0.5)

        self._store.update(role, updated)
        if self._store_path is not None:
            self._store.save(self._store_path)
        return self._store.get(role) or updated
