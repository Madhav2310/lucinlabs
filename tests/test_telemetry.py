"""Telemetry: default-on, opt-out honored, and the payload never leaks scan content.

This mirrors the discovery.py redaction-test pattern: assert the invariant
positively (what a real payload looks like) AND adversarially (fabricate
values that would be a privacy incident if they ever leaked, confirm they
never appear in the built event).
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from lucin import telemetry
from lucin.models import Agent, Finding, ScanResult, Severity, Tool


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setattr(telemetry, "CONFIG_DIR", tmp_path / ".lucin")
    monkeypatch.setattr(telemetry, "CONFIG_PATH", tmp_path / ".lucin" / "config.json")
    monkeypatch.delenv("LUCIN_TELEMETRY", raising=False)
    yield


def _result_with_secret_finding() -> ScanResult:
    agent = Agent(
        name="super_secret_customer_agent",
        framework="langchain",
        tools=[Tool(name="exfil_customer_ssn_to_vendor", capabilities=[])],
    )
    finding = Finding(
        id="AG-007",
        title="Hardcoded secret",
        severity=Severity.HIGH,
        description="STRIPE_KEY = 'sk_live_realSecretValue123'",
        agent_name=agent.name,
        tool_name="exfil_customer_ssn_to_vendor",
        source_file="/Users/realuser/acme-corp-internal/billing/secrets.py",
        source_line=42,
        owasp_ref="ASI-06",
        fix_suggestion="Use env vars",
    )
    return ScanResult(target="/Users/realuser/acme-corp-internal", agents=[agent],
                       findings=[finding], scan_duration_ms=12.3)


def test_scan_event_contains_only_allowlisted_shape():
    result = _result_with_secret_finding()
    event = telemetry.build_scan_event(result, "rich", ci=False)
    assert set(event) <= {
        "event_type", "lucin_version", "python_version", "os", "frameworks",
        "agent_count", "tool_count", "file_count", "scan_duration_ms",
        "output_format", "ci_mode", "finding_counts_json",
    }
    assert event["finding_counts_json"] == {"AG-007": 1}
    assert event["frameworks"] == "langchain"


def test_scan_event_never_leaks_paths_names_or_secrets():
    result = _result_with_secret_finding()
    event = telemetry.build_scan_event(result, "rich", ci=False)
    serialized = json.dumps(event)
    for leaked in (
        "realuser", "acme-corp-internal", "secrets.py",
        "super_secret_customer_agent", "exfil_customer_ssn_to_vendor",
        "sk_live_realSecretValue123", "STRIPE_KEY",
    ):
        assert leaked not in serialized, f"{leaked!r} leaked into telemetry payload"


def test_disabled_via_env_var_never_sends():
    os.environ["LUCIN_TELEMETRY"] = "0"
    try:
        with patch("lucin.telemetry._urlrequest.urlopen") as mock_urlopen:
            telemetry.send_event({"event_type": "scan"})
            mock_urlopen.assert_not_called()
    finally:
        del os.environ["LUCIN_TELEMETRY"]


def test_disabled_via_config_never_sends():
    telemetry.disable()
    assert telemetry.is_enabled() is False
    with patch("lucin.telemetry._urlrequest.urlopen") as mock_urlopen:
        telemetry.send_event({"event_type": "scan"})
        mock_urlopen.assert_not_called()


def test_enabled_by_default():
    assert telemetry.is_enabled() is True


def test_enable_disable_roundtrip():
    telemetry.disable()
    assert telemetry.is_enabled() is False
    telemetry.enable()
    assert telemetry.is_enabled() is True


def test_send_event_never_raises_on_network_failure():
    with patch("lucin.telemetry._urlrequest.urlopen", side_effect=OSError("network down")):
        telemetry.send_event({"event_type": "scan"})  # must not raise


def test_send_event_includes_persisted_anon_id():
    captured = {}

    def fake_urlopen(req, timeout):
        captured["body"] = json.loads(req.data)
        return MagicMock()

    with patch("lucin.telemetry._urlrequest.urlopen", side_effect=fake_urlopen):
        telemetry.send_event({"event_type": "scan"})
    assert "anon_id" in captured["body"]
    assert len(captured["body"]["anon_id"]) == 32  # uuid4().hex


def test_first_run_notice_shown_once():
    console = MagicMock()
    telemetry.maybe_print_first_run_notice(console)
    assert console.print.called
    console.print.reset_mock()
    telemetry.maybe_print_first_run_notice(console)
    console.print.assert_not_called()
