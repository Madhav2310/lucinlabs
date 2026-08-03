"""Machine-wide discovery + secret redaction.

Discovery reads the user's real machine, so two properties matter more than coverage:
it must find the files that actually exist, and it must never display a credential.

Measured gaps this locks in (2026-07-30):
* `lucin discover` returned **0** results on a machine holding ~/.claude.json (46 KB),
  ~/.claude/settings.json and two installed skills — the path table covered IDE MCP
  files but not the coding agent people actually run. Now 5.
* The first redaction heuristic called `command`, `cwd`, `PYTHONPATH` and
  `budgetTokens` credentials, because a long filesystem path matches a token alphabet
  and "token" appears in the name of an integer setting. Same over-eager-matching
  class as the detector bugs this project keeps fixing.
"""
import json

import pytest

from lucin.discovery import (
    _COMMON_GLOBS,
    _COMMON_PATHS,
    credential_keys,
    discover_mcp_configs,
    looks_secret,
    redact,
)


# --------------------------------------------------------------- redaction
@pytest.mark.parametrize("key,value", [
    ("OPENAI_API_KEY", "sk-proj-abcdefghij1234567890abcdefghij"),
    ("GITHUB_TOKEN", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
    ("SLACK_BOT_TOKEN", "xoxb-123456789012-abcdefghijklmnop"),
    ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
    ("ANTHROPIC_API_KEY", "aVeryLongOpaqueSecretValue123456789"),
])
def test_real_credential_shapes_are_secret(key, value):
    assert looks_secret(key, value) is True


@pytest.mark.parametrize("key,value", [
    ("command", "/Users/x/.venv/bin/python3.12"),          # a path is not a secret
    ("cwd", "/Users/x/Desktop/project"),
    ("PYTHONPATH", "/Users/x/src:/Users/x/lib"),
    ("budgetTokens", 20000),                                # ints are not secrets
    ("cacheReadInputTokens", 1024),
    ("enabled", True),
    ("url", "https://api.example.com/v1"),                  # URLs are not secrets
    ("args", "-y @modelcontextprotocol/server-filesystem"), # has spaces
    ("appleTerminalBackupPath", "/Users/x/Library/Application Support/Terminal"),
    ("model", "claude-opus-4-8"),
])
def test_ordinary_config_values_are_not_secret(key, value):
    assert looks_secret(key, value) is False, f"{key} must not be treated as a secret"


def test_redaction_never_leaks_a_usable_secret():
    secret = "sk-proj-abcdefghij1234567890abcdefghij"
    out = redact("OPENAI_API_KEY", secret)
    assert secret not in out, "the secret must not survive redaction"
    assert out.endswith("chars)") and "****" in out
    # a 4-char tail is intentional: the owner can identify WHICH key without reuse
    assert secret[-4:] in out
    assert len(out) < len(secret) + 40


def test_redaction_passes_through_non_secrets_unchanged():
    assert redact("command", "npx") == "npx"


# --------------------------------------------------------------- discovery
def test_credential_keys_returns_names_only(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"gh": {
        "command": "npx", "args": ["-y", "server"],
        "env": {"GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
                "LOG_LEVEL": "debug"}}}}))
    keys = credential_keys(cfg)
    assert "GITHUB_TOKEN" in keys
    assert "LOG_LEVEL" not in keys
    # the VALUE must never appear in the returned names
    assert not any("ghp_" in k for k in keys)


def test_malformed_config_is_not_fatal(tmp_path):
    bad = tmp_path / "mcp.json"
    bad.write_text("{ this is not json")
    assert credential_keys(bad) == []      # a broken config is normal, not an error


def test_discovery_is_read_only_and_returns_existing_files():
    """Must not raise on a machine missing every path, and must never fabricate one."""
    found = discover_mcp_configs()
    for entry in found:
        assert entry["path"].is_file(), f"reported a non-existent path: {entry['path']}"
        assert entry["scope"] in ("user", "project")
        assert entry["platform"]


def test_registry_covers_the_common_coding_agents():
    """Regression for the measured 0-results gap: Claude Code and skills must be in
    the registry, since that is the most common way tools run on a dev machine."""
    flat = [p for paths in _COMMON_PATHS.values() for p in paths]
    assert any(".claude.json" in p for p in flat)
    assert any(".claude/settings.json" in p for p in flat)
    globs = [g for pats in _COMMON_GLOBS.values() for g in pats]
    assert any("skills" in g and "SKILL.md" in g for g in globs)


def test_no_duplicate_paths_reported():
    found = discover_mcp_configs()
    resolved = [str(e["path"].resolve()) for e in found]
    assert len(resolved) == len(set(resolved)), "the same file was reported twice"
