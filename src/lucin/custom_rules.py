"""Custom YAML Detection Rules — user-defined security checks.

Users can define their own detection rules in YAML format and place them in
.lucin/rules/ or specify via config. This enables org-specific policies.

Rule format:
```yaml
rules:
  - id: CUSTOM-001
    title: "No production database in dev config"
    severity: high
    pattern:
      type: content  # or 'tool_name' or 'mcp_server'
      regex: "prod.*\\.company\\.com"
    message: "Production database URL found in agent config"
    fix: "Use environment variables for database URLs"

  - id: CUSTOM-002
    title: "Require human approval for email tools"
    severity: medium
    pattern:
      type: tool_name
      regex: "send_email|send_message|notify"
    condition: "no_human_approval"
    message: "Email/messaging tools should require human approval"
```

This gives us parity with Semgrep's custom rules and Microsoft AGT's policy languages.
"""

import re
from pathlib import Path

import yaml

from lucin.models import Agent, Finding, Severity


def load_custom_rules(rules_path: Path | None = None) -> list[dict]:
    """Load custom rules from YAML files.

    Searches in order:
    1. Explicit path (if provided)
    2. .lucin/rules/*.yaml in current directory
    3. ~/.lucin/rules/*.yaml (user-level)
    """
    rules = []

    search_paths = []
    if rules_path:
        search_paths.append(rules_path)
    else:
        # Project-level
        project_rules = Path.cwd() / ".lucin" / "rules"
        if project_rules.exists():
            search_paths.append(project_rules)
        # User-level
        user_rules = Path.home() / ".lucin" / "rules"
        if user_rules.exists():
            search_paths.append(user_rules)

    for search_dir in search_paths:
        if search_dir.is_file():
            rules.extend(_parse_rules_file(search_dir))
        elif search_dir.is_dir():
            for f in sorted(search_dir.glob("*.yaml")) + sorted(search_dir.glob("*.yml")):
                rules.extend(_parse_rules_file(f))

    return rules


def run_custom_rules(agents: list[Agent], rules: list[dict]) -> list[Finding]:
    """Run custom detection rules against parsed agents."""
    findings = []

    for agent in agents:
        for rule in rules:
            rule_findings = _evaluate_rule(agent, rule)
            findings.extend(rule_findings)

    return findings


def _parse_rules_file(filepath: Path) -> list[dict]:
    """Parse a custom rules YAML file."""
    try:
        content = filepath.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
    except (yaml.YAMLError, UnicodeDecodeError, PermissionError):
        return []

    if not isinstance(data, dict):
        return []

    return data.get("rules", [])


def _evaluate_rule(agent: Agent, rule: dict) -> list[Finding]:
    """Evaluate a single custom rule against an agent."""
    findings = []

    rule_id = rule.get("id", "CUSTOM-000")
    title = rule.get("title", "Custom Rule Violation")
    severity_str = rule.get("severity", "medium").lower()
    severity = getattr(Severity, severity_str.upper(), Severity.MEDIUM)
    message = rule.get("message", "Custom rule triggered")
    fix = rule.get("fix", "")
    pattern = rule.get("pattern", {})
    condition = rule.get("condition", "")

    pattern_type = pattern.get("type", "content")
    regex = pattern.get("regex", "")

    if not regex:
        return findings

    try:
        compiled = re.compile(regex, re.IGNORECASE)
    except re.error:
        return findings

    if pattern_type == "content":
        # Match against source file content
        if agent.source_file:
            try:
                content = Path(agent.source_file).read_text(encoding="utf-8")
                if compiled.search(content):
                    findings.append(_make_finding(rule_id, title, severity, message, fix, agent))
            except (FileNotFoundError, PermissionError):
                pass

    elif pattern_type == "tool_name":
        # Match against tool names
        for tool in agent.tools:
            if compiled.search(tool.name):
                # Check condition
                if condition == "no_human_approval" and agent.has_human_in_loop:
                    continue  # Condition not met
                if condition == "no_sandbox" and tool.has_sandbox:
                    continue
                findings.append(_make_finding(
                    rule_id, title, severity,
                    f"{message} (tool: {tool.name})", fix, agent
                ))

    elif pattern_type == "mcp_server":
        # Match against MCP server names
        for server in agent.mcp_servers:
            if compiled.search(server.name):
                findings.append(_make_finding(
                    rule_id, title, severity,
                    f"{message} (server: {server.name})", fix, agent
                ))

    elif pattern_type == "tool_description":
        # Match against tool descriptions
        for tool in agent.tools:
            if compiled.search(tool.description):
                findings.append(_make_finding(
                    rule_id, title, severity,
                    f"{message} (tool: {tool.name})", fix, agent
                ))

    return findings


def _make_finding(rule_id: str, title: str, severity: Severity,
                  message: str, fix: str, agent: Agent) -> Finding:
    """Create a Finding from a custom rule match."""
    return Finding(
        id=rule_id,
        title=title,
        severity=severity,
        description=message,
        agent_name=agent.name,
        owasp_ref="Custom Rule",
        fix_suggestion=fix,
        source_file=agent.source_file or "",
    )
