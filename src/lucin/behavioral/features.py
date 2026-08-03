"""Feature extraction from agent telemetry — the signal engineering layer.

Just as transaction-fraud systems extract hundreds of features from a single
payment event (amount, merchant category, time since last transaction, distance
from last location, velocity of spending, etc.), we extract features from each
agent action:

- What tool was called?
- What parameters were passed?
- How long since the last tool call?
- Is this tool-call sequence common for this agent?
- What's the data sensitivity of the resources accessed?
- Is this action consistent with the agent's declared purpose?
- How does this compare to the agent's peer group?

These features feed into the scoring models.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


def stable_tool_encoding(tool_name: str, buckets: int = 10000) -> int:
    """Deterministic, process-independent encoding of a tool name.

    Python's builtin hash() is salted per-process (PYTHONHASHSEED), so
    hash(name) % N gives a DIFFERENT integer on every interpreter run. That
    silently poisons any persisted baseline (a serialized transition graph keyed
    by the encoding no longer matches after restart) and breaks train-serve
    parity. We hash the UTF-8 bytes with a fixed digest instead so the same tool
    name always maps to the same bucket.
    """
    digest = hashlib.blake2b(tool_name.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % buckets


@dataclass
class AgentAction:
    """A single observed agent action (analogous to a single transaction)."""
    timestamp: datetime
    agent_id: str
    session_id: str
    action_type: str  # tool_call, inference, data_access
    tool_name: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    result_size_bytes: int = 0
    latency_ms: float = 0
    user_id: str = ""  # The human who initiated the session
    task_context: str = ""  # What the agent is supposed to be doing


@dataclass
class ActionFeatures:
    """Extracted features for a single action — input to scoring models."""

    # === Identity features ===
    agent_id: str = ""
    session_id: str = ""
    user_id: str = ""

    # === Temporal features (like transaction timing) ===
    hour_of_day: int = 0  # 0-23
    day_of_week: int = 0  # 0-6
    seconds_since_last_action: float = 0.0
    actions_in_last_minute: int = 0
    actions_in_last_hour: int = 0
    session_duration_seconds: float = 0.0
    session_action_count: int = 0

    # === Tool usage features (like merchant category) ===
    tool_name_encoded: int = 0  # Encoded tool ID
    tool_category: str = ""  # read_data, write_data, execute_code, network_access
    tool_is_high_risk: bool = False  # exec/network/write
    tool_frequency_for_agent: float = 0.0  # How often THIS agent calls THIS tool (0-1)
    tool_is_new_for_agent: bool = False  # First time this agent uses this tool?
    tool_call_in_normal_sequence: bool = True  # Does this fit the agent's usual call patterns?

    # === Parameter features (like transaction amount) ===
    param_count: int = 0
    param_total_length: int = 0
    params_contain_url: bool = False
    params_contain_file_path: bool = False
    params_contain_code: bool = False
    params_contain_sensitive_keywords: bool = False
    param_entropy: float = 0.0  # High entropy might indicate encoded/encrypted data

    # === Data access features (like spending velocity) ===
    accesses_new_resource: bool = False  # Resource never accessed by this agent before
    resource_sensitivity: str = "unknown"  # public, internal, confidential, restricted
    data_volume_bytes: int = 0
    data_volume_anomaly_z: float = 0.0  # Z-score vs agent's typical data volume

    # === Contextual features ===
    action_matches_task_context: bool = True  # Is this action relevant to the declared task?
    action_after_user_message: bool = True  # Was this triggered by user or autonomous?
    delegation_depth: int = 0  # How many agents deep (sub-agent depth)

    # === Peer comparison features ===
    tool_usage_percentile_in_cohort: float = 0.5  # How common is this tool in similar agents?
    sequence_similarity_to_peers: float = 1.0  # How similar is this sequence to peer agents?

    # NOTE: a `to_vector()` method was removed in Phase 0 — it produced a numeric
    # feature vector "for ML model input", but no model consumed it (dead code /
    # theater). The trained HST/LODA→XGBoost pipeline (THE_BLUEPRINT §6.2) will
    # define its own vectorizer against the model's actual expected features.


SENSITIVE_KEYWORDS = [
    "password", "secret", "token", "key", "credential", "auth",
    "ssn", "social security", "credit card", "bank account",
    "private", "confidential", "internal", "restricted",
]


def extract_features(
    action: AgentAction,
    agent_history: list[AgentAction] | None = None,
    peer_stats: dict | None = None,
) -> ActionFeatures:
    """Extract features from a single agent action.

    This is the feature engineering step — the most important part of
    any ML system. The quality of features determines model accuracy.
    """
    features = ActionFeatures(
        agent_id=action.agent_id,
        session_id=action.session_id,
        user_id=action.user_id,
        hour_of_day=action.timestamp.hour,
        day_of_week=action.timestamp.weekday(),
    )

    # Tool features — STABLE across processes (see stable_tool_encoding).
    features.tool_name_encoded = stable_tool_encoding(action.tool_name)
    features.tool_is_high_risk = _is_high_risk_tool(action.tool_name)

    # Parameter features
    params_str = str(action.parameters)
    features.param_count = len(action.parameters)
    features.param_total_length = len(params_str)
    features.params_contain_url = "http" in params_str.lower()
    features.params_contain_file_path = "/" in params_str or "\\" in params_str
    features.params_contain_code = any(kw in params_str.lower() for kw in ["import ", "def ", "class ", "exec(", "eval("])
    features.params_contain_sensitive_keywords = any(kw in params_str.lower() for kw in SENSITIVE_KEYWORDS)
    features.param_entropy = _calculate_entropy(params_str)

    # Data volume
    features.data_volume_bytes = action.result_size_bytes

    # History-based features (if available)
    if agent_history:
        features = _enrich_with_history(features, action, agent_history)

    # Peer comparison (if available)
    if peer_stats:
        features = _enrich_with_peers(features, action, peer_stats)

    return features


def _is_high_risk_tool(tool_name: str) -> bool:
    """Check if a tool name indicates high-risk capability."""
    high_risk = ["shell", "exec", "bash", "http", "fetch", "request", "write", "delete", "send"]
    return any(hr in tool_name.lower() for hr in high_risk)


def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (high entropy = possibly encoded/encrypted)."""
    if not text:
        return 0.0
    import math
    from collections import Counter
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _enrich_with_history(
    features: ActionFeatures,
    action: AgentAction,
    history: list[AgentAction],
) -> ActionFeatures:
    """Add history-based features (temporal patterns, tool frequency)."""
    if not history:
        return features

    # Time since last action
    if history:
        last_action = history[-1]
        delta = (action.timestamp - last_action.timestamp).total_seconds()
        features.seconds_since_last_action = max(0, delta)

    # Actions in time windows
    one_min_ago = action.timestamp.timestamp() - 60
    one_hour_ago = action.timestamp.timestamp() - 3600
    features.actions_in_last_minute = sum(
        1 for h in history if h.timestamp.timestamp() > one_min_ago
    )
    features.actions_in_last_hour = sum(
        1 for h in history if h.timestamp.timestamp() > one_hour_ago
    )

    # Tool frequency for this agent
    total_actions = len(history)
    tool_count = sum(1 for h in history if h.tool_name == action.tool_name)
    features.tool_frequency_for_agent = tool_count / max(total_actions, 1)

    # Is this a new tool for this agent?
    seen_tools = {h.tool_name for h in history}
    features.tool_is_new_for_agent = action.tool_name not in seen_tools

    # Is this a new resource?
    # (simplified — in production, would track resource identifiers)
    features.accesses_new_resource = features.tool_is_new_for_agent

    return features


def _enrich_with_peers(
    features: ActionFeatures,
    action: AgentAction,
    peer_stats: dict,
) -> ActionFeatures:
    """Add peer-comparison features (how does this agent compare to similar ones?)."""
    # peer_stats would contain aggregated stats from similar agents
    # This is where the data flywheel creates value — more customers = better peer models
    tool_usage_rates = peer_stats.get("tool_usage_rates", {})
    if action.tool_name in tool_usage_rates:
        features.tool_usage_percentile_in_cohort = tool_usage_rates[action.tool_name]

    return features
