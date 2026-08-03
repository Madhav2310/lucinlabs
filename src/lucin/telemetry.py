"""Lucin telemetry — anonymous, aggregate-only, on by default.

WHAT IS SENT (allowlisted, enforced again server-side — see telemetry-worker/src/index.js):
  anon_id, event_type, lucin_version, python_version, os, frameworks,
  agent_count, tool_count, file_count, scan_duration_ms, output_format,
  ci_mode, finding_counts_json ({rule_id: count} — rule IDs and counts only),
  error_type.

WHAT IS NEVER SENT: file paths, target/repo names, source code, secret values,
witness text, tool or agent names. A security scanner whose own telemetry could
leak the secrets it finds would be the exact "lethal trifecta" pattern this
product exists to catch — the allowlist in the worker enforces this even if
this module is ever changed to send more.

Default ON, disclosed on first run, with an explicit off-switch:
  LUCIN_TELEMETRY=0 environment variable, or `lucin scan --no-telemetry`.
Config (anon id + opt-out + whether the disclosure banner has been shown) is
persisted at ~/.lucin/config.json, the same directory pinning.py already uses.
"""

import json
import os
import platform
import sys
import uuid
from pathlib import Path
from urllib import request as _urlrequest
from urllib.error import URLError

CONFIG_DIR = Path.home() / ".lucin"
CONFIG_PATH = CONFIG_DIR / "config.json"
COLLECTOR_URL = "https://lucin-telemetry.candura-telemetry.workers.dev/v1/event"
TIMEOUT_SECONDS = 1.5


def _load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_config(cfg: dict) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    except OSError:
        pass  # never let telemetry bookkeeping break the CLI


def _anon_id(cfg: dict) -> str:
    if "anon_id" not in cfg:
        cfg["anon_id"] = uuid.uuid4().hex
        _save_config(cfg)
    return cfg["anon_id"]


def is_enabled() -> bool:
    if os.environ.get("LUCIN_TELEMETRY") == "0":
        return False
    cfg = _load_config()
    return cfg.get("enabled", True)


def disable() -> None:
    cfg = _load_config()
    cfg["enabled"] = False
    _save_config(cfg)


def enable() -> None:
    cfg = _load_config()
    cfg["enabled"] = True
    _save_config(cfg)


def maybe_print_first_run_notice(console) -> None:
    """Print the disclosure exactly once, on the first run ever. Never blocks."""
    cfg = _load_config()
    if cfg.get("notice_shown"):
        return
    cfg["notice_shown"] = True
    _anon_id(cfg)
    _save_config(cfg)
    if not is_enabled():
        return
    console.print(
        "[dim]Lucin sends anonymous usage stats (version, OS, which rules fire, "
        "counts only — never file paths, code, or finding content) to help "
        "prioritize development. Disable with `--no-telemetry`, "
        "`LUCIN_TELEMETRY=0`, or `lucin telemetry disable`. "
        "Details: `lucin telemetry status`.[/dim]"
    )
    console.print()


def build_scan_event(result, output_format: str, ci: bool) -> dict:
    frameworks = sorted({a.framework for a in result.agents if getattr(a, "framework", None)})
    finding_counts: dict[str, int] = {}
    for f in result.findings:
        finding_counts[f.id] = finding_counts.get(f.id, 0) + 1
    return {
        "event_type": "scan",
        "lucin_version": _lucin_version(),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "os": platform.system().lower(),
        "frameworks": ",".join(frameworks)[:64],
        "agent_count": len(result.agents),
        "tool_count": sum(len(a.tools) for a in result.agents),
        "file_count": len({f.source_file for f in result.findings if f.source_file}),
        "scan_duration_ms": result.scan_duration_ms,
        "output_format": output_format,
        "ci_mode": 1 if ci else 0,
        "finding_counts_json": finding_counts,
    }


def build_command_event(command: str) -> dict:
    """A minimal event for commands other than `scan` — just proves the command ran.

    No arguments, paths, or discovered content are ever included here; that's the
    whole reason `discover` (which enumerates MCP configs across every IDE on the
    machine) is safe to instrument the same way as everything else.
    """
    return {
        "event_type": f"cmd_{command}",
        "lucin_version": _lucin_version(),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "os": platform.system().lower(),
    }


def build_error_event(exc: BaseException) -> dict:
    return {
        "event_type": "error",
        "lucin_version": _lucin_version(),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "os": platform.system().lower(),
        "error_type": type(exc).__name__,
    }


def _lucin_version() -> str:
    from lucin import __version__
    return __version__


def last_event() -> dict | None:
    """The exact payload built for the most recent command — what `lucin telemetry
    status` shows. Recorded locally even when telemetry is disabled or the send
    fails, so a user can always inspect what *would* be sent."""
    return _load_config().get("last_event")


def send_event(event: dict) -> None:
    """Fire-and-forget. Never raises, never blocks the CLI beyond TIMEOUT_SECONDS."""
    cfg = _load_config()
    event = dict(event)
    event["anon_id"] = _anon_id(cfg)
    cfg["last_event"] = event
    _save_config(cfg)
    if not is_enabled():
        return
    try:
        body = json.dumps(event).encode("utf-8")
        req = _urlrequest.Request(
            COLLECTOR_URL, data=body,
            # Cloudflare returns 403 to the default "Python-urllib/x.y" UA (looks
            # like a generic bot signature) — a real UA is required for delivery,
            # not just politeness. Found by testing: silently swallowed by the
            # except clause below until this was diagnosed with a direct request.
            headers={"Content-Type": "application/json", "User-Agent": f"lucin-cli/{_lucin_version()}"},
            method="POST",
        )
        _urlrequest.urlopen(req, timeout=TIMEOUT_SECONDS).close()
    except (URLError, OSError, ValueError):
        pass  # telemetry must never break or slow down a scan meaningfully
