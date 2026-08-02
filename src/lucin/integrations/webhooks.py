"""Webhook Integrations — Alert security teams in real-time.

When the behavioral monitor detects an anomaly or a scan finds critical
issues, notify the security team immediately via their preferred channels.

Supported:
- Slack (incoming webhook)
- Microsoft Teams (incoming webhook)
- PagerDuty (Events API v2)
- Generic webhook (POST JSON to any URL)
- OpsGenie

Each integration is a simple HTTP POST with the appropriate payload format.
No SDKs required — just a webhook URL.
"""

import json
import urllib.request
import urllib.error
from datetime import datetime
from typing import Any

from lucin.models import Finding, Severity
from lucin.behavioral.scoring import RiskScore


class WebhookNotifier:
    """Send security alerts to external services via webhooks."""

    def __init__(self, config: dict[str, str]):
        """Initialize with webhook configuration.

        Config format:
        {
            "slack_url": "https://hooks.slack.com/services/...",
            "teams_url": "https://outlook.office.com/webhook/...",
            "pagerduty_key": "your-routing-key",
            "generic_url": "https://your-service.com/webhook",
        }
        """
        self.slack_url = config.get("slack_url")
        self.teams_url = config.get("teams_url")
        self.pagerduty_key = config.get("pagerduty_key")
        self.generic_url = config.get("generic_url")

    def notify_finding(self, finding: Finding, target: str = "") -> dict[str, bool]:
        """Send alert for a scan finding. Returns success status per channel."""
        results = {}

        if self.slack_url:
            results["slack"] = self._send_slack(finding, target)
        if self.teams_url:
            results["teams"] = self._send_teams(finding, target)
        if self.pagerduty_key and finding.severity in (Severity.CRITICAL, Severity.HIGH):
            results["pagerduty"] = self._send_pagerduty(finding, target)
        if self.generic_url:
            results["generic"] = self._send_generic(finding, target)

        return results

    def notify_anomaly(self, agent_id: str, tool: str, score: RiskScore) -> dict[str, bool]:
        """Send alert for a behavioral anomaly detection."""
        results = {}

        alert_text = (
            f"🚨 Agent Anomaly Detected\n"
            f"Agent: {agent_id}\n"
            f"Tool: {tool}\n"
            f"Risk Score: {score.score}/99\n"
            f"Action: {score.action_threshold}\n"
            f"Factors: {'; '.join(score.contributing_factors[:3])}"
        )

        if self.slack_url:
            results["slack"] = self._post_json(self.slack_url, {
                "text": alert_text,
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": "🚨 Lucin: Anomaly Detected"}},
                    {"type": "section", "fields": [
                        {"type": "mrkdwn", "text": f"*Agent:* `{agent_id}`"},
                        {"type": "mrkdwn", "text": f"*Tool:* `{tool}`"},
                        {"type": "mrkdwn", "text": f"*Score:* {score.score}/99"},
                        {"type": "mrkdwn", "text": f"*Action:* {score.action_threshold.upper()}"},
                    ]},
                    {"type": "section", "text": {
                        "type": "mrkdwn",
                        "text": f"*Factors:*\n" + "\n".join(f"• {f}" for f in score.contributing_factors[:5])
                    }},
                ],
            })

        if self.generic_url:
            results["generic"] = self._post_json(self.generic_url, {
                "type": "anomaly",
                "agent_id": agent_id,
                "tool": tool,
                "score": score.score,
                "action": score.action_threshold,
                "factors": score.contributing_factors,
                "timestamp": datetime.now().isoformat(),
            })

        return results

    def _send_slack(self, finding: Finding, target: str) -> bool:
        """Send finding to Slack via incoming webhook."""
        severity_emoji = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "⚪",
        }
        emoji = severity_emoji.get(finding.severity, "ℹ️")

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{emoji} Lucin: {finding.title}"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Severity:* {finding.severity.value.upper()}"},
                        {"type": "mrkdwn", "text": f"*Rule:* {finding.id}"},
                        {"type": "mrkdwn", "text": f"*Agent:* {finding.agent_name or 'N/A'}"},
                        {"type": "mrkdwn", "text": f"*Target:* {target}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": finding.description[:500]},
                },
            ],
        }

        if finding.fix_suggestion:
            payload["blocks"].append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Fix:* {finding.fix_suggestion[:200]}"},
            })

        return self._post_json(self.slack_url, payload)

    def _send_teams(self, finding: Finding, target: str) -> bool:
        """Send finding to Microsoft Teams via incoming webhook."""
        color = {
            Severity.CRITICAL: "FF0000",
            Severity.HIGH: "FF8C00",
            Severity.MEDIUM: "FFD700",
            Severity.LOW: "808080",
        }.get(finding.severity, "0078D7")

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"Lucin: {finding.title}",
            "sections": [{
                "activityTitle": f"Lucin Finding: {finding.title}",
                "activitySubtitle": f"Severity: {finding.severity.value.upper()} | Rule: {finding.id}",
                "facts": [
                    {"name": "Agent", "value": finding.agent_name or "N/A"},
                    {"name": "Target", "value": target},
                    {"name": "OWASP", "value": finding.owasp_ref or "N/A"},
                ],
                "text": finding.description[:500],
            }],
        }

        return self._post_json(self.teams_url, payload)

    def _send_pagerduty(self, finding: Finding, target: str) -> bool:
        """Send finding to PagerDuty via Events API v2."""
        severity_map = {
            Severity.CRITICAL: "critical",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "info",
        }

        payload = {
            "routing_key": self.pagerduty_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"[Lucin] {finding.severity.value.upper()}: {finding.title} in {target}",
                "severity": severity_map.get(finding.severity, "info"),
                "source": "lucin",
                "component": finding.agent_name or target,
                "group": finding.id,
                "class": "agent_security",
                "custom_details": {
                    "finding_id": finding.id,
                    "description": finding.description[:500],
                    "agent_name": finding.agent_name,
                    "tool_name": finding.tool_name,
                    "owasp_ref": finding.owasp_ref,
                    "fix_suggestion": finding.fix_suggestion[:300] if finding.fix_suggestion else "",
                },
            },
        }

        return self._post_json("https://events.pagerduty.com/v2/enqueue", payload)

    def _send_generic(self, finding: Finding, target: str) -> bool:
        """Send finding to a generic webhook URL."""
        payload = {
            "source": "lucin",
            "type": "finding",
            "timestamp": datetime.now().isoformat(),
            "severity": finding.severity.value,
            "finding": {
                "id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "agent_name": finding.agent_name,
                "tool_name": finding.tool_name,
                "owasp_ref": finding.owasp_ref,
                "blast_radius": finding.blast_radius,
                "fix_suggestion": finding.fix_suggestion,
                "source_file": finding.source_file,
                "source_line": finding.source_line,
            },
            "target": target,
        }

        return self._post_json(self.generic_url, payload)

    def _post_json(self, url: str, payload: dict) -> bool:
        """POST JSON to a URL. Returns True on success."""
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 201, 202, 204)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError):
            return False
