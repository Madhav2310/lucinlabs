"""Tests for integrations, config, behavioral, and red team components."""

import json
import tempfile
from pathlib import Path

import pytest

from lucin.scanner import scan_target
from lucin.scoring import calculate_security_score


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


# === Config File ===

class TestConfig:
    def test_loads_default_when_no_file(self):
        from lucin.config import load_config
        config = load_config(Path("/nonexistent"))
        assert config.scan.fail_on == "high"
        assert config.monitor.baseline_actions == 50
        assert config.webhooks.slack_url == ""

    def test_parses_yaml_config(self, tmp_dir):
        from lucin.config import load_config
        config_content = """
scan:
  fail_on: critical
  exclude_rules: [AG-010, AG-009]
monitor:
  baseline_actions: 30
  alert_threshold: 70
webhooks:
  slack_url: https://hooks.slack.com/test
"""
        (tmp_dir / ".lucin.yml").write_text(config_content)
        config = load_config(tmp_dir)
        assert config.scan.fail_on == "critical"
        assert config.scan.exclude_rules == ["AG-010", "AG-009"]
        assert config.monitor.baseline_actions == 30
        assert config.monitor.alert_threshold == 70
        assert config.webhooks.slack_url == "https://hooks.slack.com/test"


# === Badge Generation ===

class TestBadge:
    def test_generates_passing_badge(self, tmp_dir):
        from lucin.badge import generate_badge_svg
        from lucin.models import ScanResult
        result = ScanResult(target="test", agents=[], findings=[])
        svg = generate_badge_svg(result)
        assert "passing" in svg
        assert "<svg" in svg

    def test_generates_failing_badge(self, tmp_dir):
        from lucin.badge import generate_badge_svg
        from lucin.models import ScanResult, Finding, Severity
        result = ScanResult(target="test", agents=[], findings=[
            Finding(id="AG-001", title="Test", severity=Severity.CRITICAL,
                    description="test", agent_name="test")
        ])
        svg = generate_badge_svg(result)
        assert "failing" in svg

    def test_generates_score_badge(self, tmp_dir):
        from lucin.badge import generate_badge_svg
        from lucin.models import ScanResult
        result = ScanResult(target="test", agents=[], findings=[])
        svg = generate_badge_svg(result, style="score")
        assert "score: 100" in svg


# === SIEM Output ===

class TestSIEM:
    def test_generates_ocsf_events(self, tmp_dir):
        from lucin.integrations.siem import findings_to_ocsf
        from lucin.models import ScanResult, Finding, Severity
        result = ScanResult(target="test", agents=[], findings=[
            Finding(id="AG-001", title="Shell Access", severity=Severity.CRITICAL,
                    description="Unrestricted", agent_name="agent1",
                    owasp_ref="A02")
        ])
        events = findings_to_ocsf(result)
        assert len(events) == 1
        assert events[0]["class_uid"] == 2001  # Security Finding
        assert events[0]["severity_id"] == 5  # Critical
        assert events[0]["finding_info"]["uid"] == "AG-001"

    def test_ocsf_ndjson_format(self, tmp_dir):
        from lucin.integrations.siem import findings_to_ocsf_ndjson
        from lucin.models import ScanResult, Finding, Severity
        result = ScanResult(target="test", agents=[], findings=[
            Finding(id="AG-001", title="Test", severity=Severity.HIGH,
                    description="test", agent_name="a"),
            Finding(id="AG-002", title="Test2", severity=Severity.MEDIUM,
                    description="test2", agent_name="b"),
        ])
        ndjson = findings_to_ocsf_ndjson(result)
        lines = ndjson.strip().split("\n")
        assert len(lines) == 2
        # Each line should be valid JSON
        for line in lines:
            parsed = json.loads(line)
            assert "class_uid" in parsed


# === Behavioral Persistence ===

class TestPersistence:
    def test_save_and_load_baseline(self, tmp_dir):
        from lucin.behavioral.scoring import BehavioralScorer
        from lucin.behavioral.features import ActionFeatures
        from lucin.behavioral.persistence import BaselinePersistence

        # Create scorer and learn some data
        scorer = BehavioralScorer()
        for i in range(10):
            features = ActionFeatures(agent_id="test-agent", tool_name_encoded=i % 3)
            scorer.learn(features)

        # Save
        persistence = BaselinePersistence(storage_dir=tmp_dir / "baselines")
        save_path = persistence.save(scorer, reason="test")
        assert save_path.exists()

        # Load into new scorer
        new_scorer = BehavioralScorer()
        meta = persistence.load(new_scorer, save_path)
        assert meta.get("reason") == "test"
        assert new_scorer.baseline_count == 1  # One agent baselined


# === Tool Mock ===

class TestToolMock:
    def test_returns_normal_response(self):
        from lucin.redteam.tool_mock import ToolMock
        mock = ToolMock()
        mock.register("search", normal="Normal result", poisoned="EVIL result")
        assert mock.get_response("search") == "Normal result"

    def test_returns_poisoned_response_when_activated(self):
        from lucin.redteam.tool_mock import ToolMock
        mock = ToolMock()
        mock.register("search", normal="Normal", poisoned="Poisoned!")
        mock.activate_poison("search")
        assert mock.get_response("search") == "Poisoned!"

    def test_tracks_call_log(self):
        from lucin.redteam.tool_mock import ToolMock
        mock = ToolMock()
        mock.register("tool1", normal="ok", poisoned="bad")
        mock.get_response("tool1", {"key": "value"})
        mock.get_response("tool1")
        assert len(mock.call_log) == 2
        assert mock.call_log[0]["params"] == {"key": "value"}


# === Synthetic Trace Generator ===

class TestSyntheticTraces:
    def test_generates_clean_traces(self):
        from lucin.behavioral.synthetic import generate_traces
        traces = generate_traces("support_agent", duration_hours=2, seed=123)
        assert len(traces) > 10
        # All should have required fields
        for t in traces:
            assert "timestamp" in t
            assert "agent_id" in t
            assert "tool" in t

    def test_generates_attack_traces(self):
        from lucin.behavioral.synthetic import generate_traces
        traces = generate_traces("support_agent", duration_hours=2,
                                inject_attack="data_exfiltration",
                                attack_at_hour=1.0, seed=456)
        # Should have attack actions with webhook.site
        attack_actions = [t for t in traces if "webhook" in str(t.get("params", {}))]
        assert len(attack_actions) >= 1


# === Red Team Attacks ===

class TestRedTeamAttacks:
    def test_all_attacks_have_mitre_atlas(self):
        from lucin.redteam.attacks import ALL_ATTACKS
        for attack in ALL_ATTACKS:
            assert attack.mitre_atlas != "", f"Attack {attack.id} missing MITRE ATLAS ID"

    def test_targeted_attacks_use_tool_names(self, tmp_dir):
        from lucin.redteam.targeted import generate_targeted_attacks
        from lucin.models import Agent, Tool, ToolCapability
        agent = Agent(
            name="test", framework="test",
            tools=[
                Tool(name="my_database", capabilities=[ToolCapability.READ_DATA]),
                Tool(name="my_sender", capabilities=[ToolCapability.NETWORK_ACCESS]),
            ]
        )
        attacks = generate_targeted_attacks(agent)
        # Attacks should reference the agent's actual tool names
        all_payloads = " ".join(a.payload for a in attacks)
        assert "my_database" in all_payloads or "my_sender" in all_payloads
