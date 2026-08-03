"""Lucin Configuration — .lucin.yml support.

Allows enterprises to configure Lucin behavior without code changes:
- Set severity thresholds
- Disable specific rules
- Configure webhook endpoints
- Set custom scan paths
- Define framework hints
- Set behavioral monitoring parameters

Config file locations (searched in order):
1. .lucin.yml (project root)
2. ~/.lucin.yml (user home)
3. /etc/lucin/config.yml (system-wide)

Example .lucin.yml:
```yaml
scan:
  fail_on: high
  exclude_rules: [AG-010]  # Don't flag missing rate limits
  exclude_paths: [tests/, node_modules/]
  frameworks: [langchain, mcp]

monitor:
  baseline_actions: 50
  alert_threshold: 60
  auto_save: true

webhooks:
  slack_url: https://hooks.slack.com/services/...
  pagerduty_key: your-routing-key

redteam:
  include_multi_turn: true
  targeted: true
```
"""

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ScanConfig:
    """Scan command configuration."""
    fail_on: str = "high"
    exclude_rules: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=lambda: ["auto"])
    output_format: str = "rich"


@dataclass
class MonitorConfig:
    """Monitor command configuration."""
    baseline_actions: int = 50
    alert_threshold: int = 60
    auto_save: bool = True
    save_dir: str = ".lucin/baselines"


@dataclass
class WebhookConfig:
    """Webhook notification configuration."""
    slack_url: str = ""
    teams_url: str = ""
    pagerduty_key: str = ""
    generic_url: str = ""


@dataclass
class RedteamConfig:
    """Red team configuration."""
    include_multi_turn: bool = False
    targeted: bool = True
    timeout_seconds: int = 30


@dataclass
class LucinConfig:
    """Complete Lucin configuration."""
    scan: ScanConfig = field(default_factory=ScanConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    webhooks: WebhookConfig = field(default_factory=WebhookConfig)
    redteam: RedteamConfig = field(default_factory=RedteamConfig)


def load_config(project_dir: Path | None = None) -> LucinConfig:
    """Load configuration from .lucin.yml.

    Searches for config file in standard locations.
    Returns default config if no file found.
    """
    search_paths = []

    if project_dir:
        search_paths.append(project_dir / ".lucin.yml")
        search_paths.append(project_dir / ".lucin.yaml")

    search_paths.extend([
        Path.cwd() / ".lucin.yml",
        Path.cwd() / ".lucin.yaml",
        Path.home() / ".lucin.yml",
        Path("/etc/lucin/config.yml"),
    ])

    for path in search_paths:
        if path.exists():
            return _parse_config_file(path)

    # No config file found — use defaults
    return LucinConfig()


def _parse_config_file(path: Path) -> LucinConfig:
    """Parse a .lucin.yml config file."""
    try:
        content = path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
    except (yaml.YAMLError, UnicodeDecodeError, PermissionError):
        return LucinConfig()

    if not isinstance(data, dict):
        return LucinConfig()

    config = LucinConfig()

    # Parse scan section
    if "scan" in data and isinstance(data["scan"], dict):
        scan = data["scan"]
        config.scan.fail_on = scan.get("fail_on", "high")
        config.scan.exclude_rules = scan.get("exclude_rules", [])
        config.scan.exclude_paths = scan.get("exclude_paths", [])
        config.scan.frameworks = scan.get("frameworks", ["auto"])
        config.scan.output_format = scan.get("output_format", "rich")

    # Parse monitor section
    if "monitor" in data and isinstance(data["monitor"], dict):
        mon = data["monitor"]
        config.monitor.baseline_actions = mon.get("baseline_actions", 50)
        config.monitor.alert_threshold = mon.get("alert_threshold", 60)
        config.monitor.auto_save = mon.get("auto_save", True)
        config.monitor.save_dir = mon.get("save_dir", ".lucin/baselines")

    # Parse webhooks section
    if "webhooks" in data and isinstance(data["webhooks"], dict):
        wh = data["webhooks"]
        config.webhooks.slack_url = wh.get("slack_url", "")
        config.webhooks.teams_url = wh.get("teams_url", "")
        config.webhooks.pagerduty_key = wh.get("pagerduty_key", "")
        config.webhooks.generic_url = wh.get("generic_url", "")

    # Parse redteam section
    if "redteam" in data and isinstance(data["redteam"], dict):
        rt = data["redteam"]
        config.redteam.include_multi_turn = rt.get("include_multi_turn", False)
        config.redteam.targeted = rt.get("targeted", True)
        config.redteam.timeout_seconds = rt.get("timeout_seconds", 30)

    return config
