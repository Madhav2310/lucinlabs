"""Lucin Monitor — Live behavioral anomaly detection on agent traces.

This is the CORE DIFFERENTIATOR. Not rules. Not patterns. ML.

Feed it a stream of agent actions (tool calls with context), and it:
1. Learns what "normal" looks like per agent (first N actions = baseline)
2. Scores every subsequent action for anomaly (0-99)
3. Explains WHY something was flagged
4. Detects behavioral drift over time

This applies the standard transaction-fraud detection architecture to agent
actions:
- Per-entity models (per-agent baselines, the streaming-fraud pattern)
- Real-time scoring (<50ms per action)
- Online learning (no batch retraining)
- Contextual conditioning (same action can be normal or anomalous)
- Explainable scores (which features contributed)

Input format (JSONL — one JSON object per line):
    {"timestamp": "2026-07-26T10:30:00Z", "agent_id": "support-agent", "tool": "sql_query", "params": {"query": "SELECT * FROM customers WHERE id = 123"}}
    {"timestamp": "2026-07-26T10:30:01Z", "agent_id": "support-agent", "tool": "send_email", "params": {"to": "customer@example.com"}}
    ...

Output: Real-time risk scores with explanations.
"""

import json
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from lucin.behavioral.features import AgentAction, extract_features
from lucin.behavioral.scoring import BehavioralScorer, RiskScore

console = Console()


class TraceMonitor:
    """Process a stream of agent actions and produce real-time anomaly scores."""

    def __init__(self, baseline_actions: int = 50):
        """Initialize monitor.

        Args:
            baseline_actions: Number of actions to observe before scoring.
                During baseline period, all actions are LEARNED (not scored).
                After baseline, actions are scored AND learned.
        """
        self.scorer = BehavioralScorer()
        self.baseline_actions = baseline_actions
        self.action_counts: dict[str, int] = defaultdict(int)
        self.history: dict[str, list[AgentAction]] = defaultdict(list)
        self.scores: list[tuple[AgentAction, RiskScore]] = []
        self.alerts: list[tuple[AgentAction, RiskScore]] = []

    def process_action(self, raw_action: dict) -> RiskScore | None:
        """Process a single agent action from the trace.

        Returns:
            RiskScore if past baseline period, None if still learning.
        """
        # Parse the action
        action = self._parse_action(raw_action)
        if action is None:
            return None

        agent_id = action.agent_id
        self.action_counts[agent_id] += 1
        self.history[agent_id].append(action)

        # Keep history bounded (last 1000 actions per agent)
        if len(self.history[agent_id]) > 1000:
            self.history[agent_id] = self.history[agent_id][-500:]

        # Extract features
        features = extract_features(
            action,
            agent_history=self.history[agent_id][:-1],  # Exclude current
        )

        # If still in baseline period: learn only
        if self.action_counts[agent_id] <= self.baseline_actions:
            self.scorer.learn(features)
            return None

        # Past baseline: score AND learn
        score = self.scorer.score(features)
        self.scorer.learn(features)  # Continue adapting

        # Track
        self.scores.append((action, score))
        if score.score >= 60:
            self.alerts.append((action, score))

        return score

    def _parse_action(self, raw: dict) -> AgentAction | None:
        """Parse a raw JSON action into an AgentAction."""
        try:
            # Handle various timestamp formats
            ts_str = raw.get("timestamp", "")
            if ts_str:
                # Try ISO format
                if "T" in ts_str:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                else:
                    ts = datetime.now()
            else:
                ts = datetime.now()

            return AgentAction(
                timestamp=ts,
                agent_id=raw.get("agent_id", raw.get("agent", "unknown")),
                session_id=raw.get("session_id", raw.get("session", "default")),
                action_type=raw.get("action_type", "tool_call"),
                tool_name=raw.get("tool", raw.get("tool_name", "")),
                parameters=raw.get("params", raw.get("parameters", {})),
                result_size_bytes=raw.get("result_size", 0),
                latency_ms=raw.get("latency_ms", 0),
                user_id=raw.get("user_id", raw.get("user", "")),
                task_context=raw.get("task", raw.get("context", "")),
            )
        except Exception:
            return None

    @property
    def total_processed(self) -> int:
        return sum(self.action_counts.values())

    @property
    def agents_baselined(self) -> int:
        return sum(1 for count in self.action_counts.values() if count > self.baseline_actions)


def run_monitor_from_file(
    trace_file: Path,
    baseline_actions: int = 50,
    alert_threshold: int = 60,
    speed: float = 0.0,  # Delay between actions (0 = full speed)
):
    """Run the monitor against a trace file and display live results.

    Args:
        trace_file: Path to JSONL file with agent actions
        baseline_actions: Actions to observe before scoring
        alert_threshold: Score threshold for alerts (0-99)
        speed: Delay between processing actions (seconds). 0 = instant.
    """
    monitor = TraceMonitor(baseline_actions=baseline_actions)

    # Read all actions
    try:
        lines = trace_file.read_text().strip().split("\n")
        actions = [json.loads(line) for line in lines if line.strip()]
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        console.print(f"[red]Error reading trace file:[/red] {e}")
        return monitor

    console.print(Panel(
        f"[bold]Monitoring {len(actions)} agent actions[/bold]\n"
        f"[dim]Baseline period: first {baseline_actions} actions per agent (learning only)\n"
        f"Alert threshold: score >= {alert_threshold}[/dim]",
        title="Lucin Behavioral Monitor",
        border_style="blue",
    ))
    console.print()

    # Process actions with live display
    recent_scores = []

    for i, raw_action in enumerate(actions):
        score = monitor.process_action(raw_action)

        if score is not None:
            agent_id = raw_action.get("agent_id", raw_action.get("agent", "?"))
            tool = raw_action.get("tool", raw_action.get("tool_name", "?"))

            # Color based on score
            if score.score >= 85:
                color = "bold red"
                status = "BLOCK"
            elif score.score >= 60:
                color = "yellow"
                status = "ALERT"
            elif score.score >= 30:
                color = "dim yellow"
                status = "WATCH"
            else:
                color = "green"
                status = "OK"

            # Print live score
            factors_str = "; ".join(score.contributing_factors[:2]) if score.contributing_factors else ""
            console.print(
                f"  [{color}]{status:5s}[/{color}] "
                f"[dim]#{i+1:4d}[/dim] "
                f"[bold]{agent_id}[/bold] → {tool} "
                f"[{color}]score:{score.score}[/{color}] "
                f"[dim]{factors_str}[/dim]"
            )

            recent_scores.append((agent_id, tool, score.score, status))
        else:
            # Still in baseline
            agent_id = raw_action.get("agent_id", raw_action.get("agent", "?"))
            tool = raw_action.get("tool", raw_action.get("tool_name", "?"))
            count = monitor.action_counts.get(agent_id, 0)
            pct = min(100, int(count / baseline_actions * 100))
            console.print(
                f"  [dim]LEARN #{i+1:4d} {agent_id} → {tool} "
                f"(baseline: {pct}%)[/dim]"
            )

        if speed > 0:
            time.sleep(speed)

    # Summary
    console.print()
    console.print("─" * 70)
    console.print()
    console.print(f"  [bold]Processed:[/bold] {monitor.total_processed} actions")
    console.print(f"  [bold]Agents baselined:[/bold] {monitor.agents_baselined}")
    console.print(f"  [bold]Alerts:[/bold] {len(monitor.alerts)}")

    if monitor.alerts:
        console.print()
        console.print(Panel("[bold red]ALERTS (score >= 60)[/bold red]", border_style="red"))
        for action, score in monitor.alerts:
            factors = "; ".join(score.contributing_factors[:3])
            console.print(
                f"  [red]●[/red] {action.agent_id} → {action.tool_name} "
                f"[bold red]score:{score.score}[/bold red] "
                f"({factors})"
            )

    return monitor
