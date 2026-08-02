"""Lucin CLI - the main entry point."""

import time
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lucin import __version__
from lucin.html_report import generate_html_report
from lucin.reporter import print_findings
from lucin.scanner import scan_target

app = typer.Typer(
    name="lucin",
    help="Find what your AI agents can do that they shouldn't — before attackers do.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


def version_callback(value: bool):
    if value:
        console.print(f"[bold]lucin[/bold] v{__version__}")
        raise typer.Exit()


def _print_rules_and_exit(value: bool):
    """--list-rules: print every registered detector's rule IDs with severity and OWASP mapping.

    IDs and metadata are derived from the running source (detector registry + RULE_CATALOG),
    not a hand-maintained list, so this can't drift from what actually runs.
    """
    if not value:
        return
    import inspect
    import re

    from lucin.detectors import CROSS_AGENT_DETECTORS, PER_AGENT_DETECTORS
    from lucin.rule_docs import RULE_CATALOG

    id_pattern = re.compile(r'"id"\s*:\s*"(AG-[A-Za-z0-9-]+)"|id\s*=\s*f?"(AG-[A-Za-z0-9-]+)"')
    rows: list[tuple[str, str, str]] = []
    for fn in PER_AGENT_DETECTORS + CROSS_AGENT_DETECTORS:
        module = inspect.getmodule(fn)
        try:
            src = inspect.getsource(module) if module else ""
        except OSError:
            src = ""
        found_ids = sorted({g1 or g2 for g1, g2 in id_pattern.findall(src)})
        module_name = module.__name__.rsplit(".", 1)[-1] if module else fn.__name__
        for rid in found_ids or [module_name]:
            rows.append((rid, module_name, fn.__name__))

    console.print(
        f"[bold]{len(PER_AGENT_DETECTORS) + len(CROSS_AGENT_DETECTORS)} active detectors[/bold] "
        f"({len(PER_AGENT_DETECTORS)} per-agent, {len(CROSS_AGENT_DETECTORS)} cross-agent)\n"
    )
    table = Table(box=None, pad_edge=False)
    table.add_column("RULE", style="bold")
    table.add_column("SEVERITY")
    table.add_column("OWASP AGENTIC")
    table.add_column("TITLE")
    for rid, module_name, _fn_name in sorted(rows):
        meta = RULE_CATALOG.get(rid, {})
        severity = meta.get("severity", "-")
        owasp = ", ".join(meta.get("owasp_asi", [])) or "-"
        title = meta.get("title", module_name)
        table.add_row(rid, severity, owasp, title)
    console.print(table)
    raise typer.Exit(0)


def _print_adapters_and_exit(value: bool):
    """--list-adapters: print every framework parser actually wired into the scan path."""
    if not value:
        return
    from lucin.parsers import _AUTO_PARSERS

    names = sorted({
        fn.__name__.replace("parse_", "").replace("_config", "")
        for fn in _AUTO_PARSERS if fn.__name__ != "parse_generic"
    })
    console.print(f"[bold]{len(names)} framework adapters[/bold] (plus a generic fallback for unmatched code)\n")
    for name in names:
        console.print(f"  {name}")
    raise typer.Exit(0)


@app.callback()
def main(
    version: bool = typer.Option(
        None, "--version", "-v", help="Show version.", callback=version_callback, is_eager=True
    ),
):
    """Lucin — Agent Security Scanner."""
    pass


@app.command(epilog=(
    "Anonymous usage counts (rule IDs and integers, never code or paths) are sent "
    "by default. Disable with --no-telemetry, LUCIN_TELEMETRY=0, or "
    "'lucin telemetry disable'. See exactly what's sent: 'lucin telemetry status'."
))
def scan(
    target: str = typer.Argument(
        None, help="Path to agent code, MCP config, or project directory. "
                   "Omit it to auto-discover the agent and MCP configuration on this machine."),
    framework: str = typer.Option(
        "auto", "--framework", "-f", help="Framework: langchain, crewai, autogen, mcp, auto."
    ),
    output_format: str = typer.Option(
        "rich", "--format", help="Output format: rich, json, sarif, html, ocsf (SIEM)."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Write report to file (for html/json formats)."
    ),
    fail_on: str = typer.Option(
        None, "--fail-on", help="Exit with code 1 if findings at this severity or above (critical, high, medium, low)."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner and details, show only summary."),
    ci: bool = typer.Option(False, "--ci", help="CI mode: minimal output, exit codes for findings."),
    owasp: bool = typer.Option(False, "--owasp", help="Show OWASP ASI coverage report after findings."),
    pin: bool = typer.Option(False, "--pin", help="Establish/update the trusted tool baseline for rug-pull (AG-RUGPULL) detection. Opt-in and stateful; drift is checked automatically on later scans of a pinned config."),
    baseline: Path = typer.Option(
        None, "--baseline",
        help="Compare against a findings baseline file; only findings absent from it can fail the run.",
    ),
    write_baseline: Path = typer.Option(
        None, "--write-baseline",
        help="Write the current findings to a baseline file and exit 0.",
    ),
    no_telemetry: bool = typer.Option(False, "--no-telemetry", help="Disable anonymous usage telemetry for this run (see --help or LUCIN_TELEMETRY=0 to disable permanently)."),
    list_rules: bool = typer.Option(
        False, "--list-rules", callback=_print_rules_and_exit, is_eager=True,
        help="List all active detectors with rule IDs, severities and OWASP mappings, then exit."
    ),
    list_adapters: bool = typer.Option(
        False, "--list-adapters", callback=_print_adapters_and_exit, is_eager=True,
        help="List all framework adapters wired into the scan path, then exit."
    ),
):
    """Scan agent code for security vulnerabilities."""
    from lucin import telemetry
    if no_telemetry:
        import os as _os
        _os.environ["LUCIN_TELEMETRY"] = "0"

    # Banner
    if not ci and not quiet and output_format not in ("json", "sarif"):
        console.print()
        console.print(
            Panel(
                "[bold white]Lucin[/bold white] v{} — Agent Security Scanner\n"
                "[dim]\"Find what your agents can do that they shouldn't\"[/dim]".format(__version__),
                border_style="bright_blue",
            )
        )
        console.print()
        telemetry.maybe_print_first_run_notice(err_console)

    # BARE `lucin scan` → discover this machine's agent/MCP/skill configuration.
    # One word, and the user learns something true about their own setup. This is the
    # highest-intent moment the tool has, and it is the pattern `snyk-agent-scan`
    # proved: a bare command finds what is installed rather than requiring the user to
    # already know what to point at.
    #
    # Privacy rules (also in src/lucin/discovery.py and on the website): nothing is
    # uploaded, the file list is printed BEFORE anything is analysed, and any value
    # that looks like a credential is redacted everywhere.
    discovered: list[dict] = []
    if target is None:
        from lucin.discovery import credential_keys, discover_mcp_configs
        discovered = discover_mcp_configs()
        if not discovered:
            console.print(
                "[yellow]No agent, MCP or skill configuration found on this machine.[/yellow]\n"
                "[dim]Looked in the standard locations for Claude Desktop/Code, Cursor, "
                "VS Code,\nWindsurf, Gemini CLI, Cline, Zed and Amazon Q. "
                "To scan a project instead:[/dim]\n"
                "  [bold]lucin scan ./your-agent/[/bold]")
            raise typer.Exit(code=0)
        console.print(f" [bold]Discovered {len(discovered)} configuration file(s)[/bold] "
                      f"[dim]— local only, nothing is uploaded[/dim]")
        for entry in discovered:
            creds = credential_keys(entry["path"])
            note = (f" [dim]· {len(creds)} credential(s): {', '.join(creds[:3])}[/dim]"
                    if creds else "")
            console.print(f"   [dim]{entry['platform']:<22}[/dim] {entry['path']}{note}")
        console.print()

    target_path = Path(target) if target else Path(discovered[0]["path"])
    if not target_path.exists():
        console.print(f"[red]Error:[/red] Target not found: {target}")
        raise typer.Exit(code=1)

    # Run scan
    start = time.time()
    try:
        if discovered:
            # Scan EVERY discovered config, not just the first — a developer machine
            # typically has several (Claude Code + Cursor + a skills directory), and the
            # dangerous one is rarely the first alphabetically. Results are merged into a
            # single report so the user sees one list, and the exit code reflects all of it.
            result = scan_target(Path(discovered[0]["path"]), framework=framework)
            result.target = f"{len(discovered)} discovered config(s) on this machine"
            for entry in discovered[1:]:
                try:
                    extra = scan_target(Path(entry["path"]), framework=framework)
                except Exception as exc:  # noqa: BLE001 — one bad config must not abort
                    console.print(f" [dim]skipped {entry['path']}: "
                                  f"{type(exc).__name__}[/dim]")
                    continue
                result.agents.extend(extra.agents)
                result.findings.extend(extra.findings)
        else:
            result = scan_target(target_path, framework=framework)
    except Exception as exc:
        telemetry.send_event(telemetry.build_error_event(exc))
        raise
    result.scan_duration_ms = (time.time() - start) * 1000
    telemetry.send_event(telemetry.build_scan_event(result, output_format, ci))

    # Rug-pull (AG-RUGPULL): opt-in + stateful + side-effect-free unless --pin.
    # --pin establishes/updates the trusted baseline; a normal scan checks for
    # dangerous drift ONLY on configs that already have a baseline, so the default
    # scan (and the benign-corpus benchmark) never writes pins or risks a false alarm.
    from lucin.pinning import detect_rug_pulls, has_baseline, save_baseline
    if pin:
        written = save_baseline(result.agents)
        console.print(
            f"[green]Pinned tool baseline for {len(written)} MCP config(s).[/green] "
            "Rug-pull (AG-RUGPULL) drift detection is now active on later scans."
        )
    else:
        for agent in result.agents:
            if has_baseline(agent):
                result.findings.extend(detect_rug_pulls(agent))

    # Findings baseline (P0-12): accept the current state of a repo, then only
    # fail CI on genuinely new findings. Fingerprint deliberately excludes line
    # numbers (see lucin.models.fingerprint) so unrelated edits don't reset it.
    import json

    from lucin.models import fingerprint as _fingerprint
    gating = result.findings
    if write_baseline:
        from datetime import datetime, timezone
        payload = {
            "version": 1,
            "lucin_version": __version__,
            "created": datetime.now(timezone.utc).isoformat(),
            "target": str(target_path),
            "fingerprints": sorted(_fingerprint(f) for f in result.findings),
        }
        write_baseline.write_text(json.dumps(payload, indent=2) + "\n")
        console.print(f"Baseline written: {write_baseline} ({len(result.findings)} findings accepted)")
        raise typer.Exit(0)

    if baseline and baseline.exists():
        known = set(json.loads(baseline.read_text()).get("fingerprints", []))
        for f in result.findings:
            f.is_new = _fingerprint(f) not in known
        new = [f for f in result.findings if f.is_new]
        accepted_present = len(result.findings) - len(new)
        fixed = len(known) - accepted_present
        # Status line, not payload — stderr, so it never corrupts piped/--format json output.
        err_console.print(
            f"Baseline: {len(known)} accepted · {len(new)} new"
            + (f" · {fixed} previously-reported finding(s) no longer present" if fixed > 0 else "")
        )
        gating = new

    # Output
    if output_format == "json":
        import json
        output = json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False)
        if output_file:
            Path(output_file).write_text(output)
            console.print(f"[green]Report written to:[/green] {output_file}")
        else:
            print(output)
    elif output_format == "sarif":
        from lucin.sarif import to_sarif_string
        output = to_sarif_string(result, cwd=target_path.parent if target_path.is_file() else target_path)
        if output_file:
            Path(output_file).write_text(output)
            console.print(f"[green]SARIF report written to:[/green] {output_file}")
        else:
            print(output)
    elif output_format == "html":
        report_html = generate_html_report(result)
        out_path = output_file or "lucin-report.html"
        Path(out_path).write_text(report_html)
        console.print(f"[green]HTML report written to:[/green] {out_path}")
    elif output_format == "ocsf":
        from lucin.integrations.siem import findings_to_ocsf_ndjson
        output = findings_to_ocsf_ndjson(result)
        out_path = output_file or "lucin-ocsf.ndjson"
        Path(out_path).write_text(output)
        console.print(f"[green]OCSF report written to:[/green] {out_path} ({len(result.findings)} events)")
    else:
        print_findings(console, result, ci=ci or quiet)

    if owasp and output_format not in ("json", "sarif"):
        from rich.panel import Panel as _Panel

        from lucin.owasp_report import format_coverage_report
        console.print()
        console.print(_Panel(
            format_coverage_report(result),
            title="OWASP ASI Top 10 Coverage",
            border_style="dim",
        ))

    # Send webhook alerts if configured
    from lucin.config import load_config
    config = load_config(target_path.parent if target_path.is_file() else target_path)
    if config.webhooks.slack_url or config.webhooks.pagerduty_key or config.webhooks.generic_url:
        from lucin.integrations.webhooks import WebhookNotifier
        notifier = WebhookNotifier({
            "slack_url": config.webhooks.slack_url,
            "teams_url": config.webhooks.teams_url,
            "pagerduty_key": config.webhooks.pagerduty_key,
            "generic_url": config.webhooks.generic_url,
        })
        critical_high = [f for f in result.findings if f.severity.value in ("critical", "high")]
        for finding in critical_high[:5]:  # Max 5 alerts per scan
            notifier.notify_finding(finding, target=str(target_path))

    # Exit code for CI — only findings absent from the baseline (if any) can fail the run.
    if fail_on:
        severity_order = ["critical", "high", "medium", "low"]
        threshold = severity_order.index(fail_on.lower())
        for finding in gating:
            if severity_order.index(finding.severity.value) <= threshold:
                raise typer.Exit(code=1)


@app.command()
def info(
    target: str = typer.Argument(..., help="Path to agent code or project directory."),
    no_telemetry: bool = typer.Option(False, "--no-telemetry", help="Disable anonymous usage telemetry for this run."),
):
    """Show agent inventory without running detections."""
    from lucin import telemetry
    if no_telemetry:
        import os as _os
        _os.environ["LUCIN_TELEMETRY"] = "0"

    target_path = Path(target)
    if not target_path.exists():
        console.print(f"[red]Error:[/red] Target not found: {target}")
        raise typer.Exit(code=1)

    result = scan_target(target_path, detections=False)
    telemetry.send_event(telemetry.build_command_event("info"))

    console.print()
    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Agents found:[/bold] {len(result.agents)}")
    console.print()

    if result.agents:
        table = Table(title="Agent Inventory")
        table.add_column("Agent", style="bold")
        table.add_column("Framework")
        table.add_column("Tools", justify="right")
        table.add_column("MCP Servers", justify="right")
        table.add_column("Human-in-Loop")

        for agent in result.agents:
            table.add_row(
                agent.name,
                agent.framework,
                str(len(agent.tools)),
                str(len(agent.mcp_servers)),
                "[green]Yes[/green]" if agent.has_human_in_loop else "[red]No[/red]",
            )

        console.print(table)
    else:
        console.print("[yellow]No agents found in target.[/yellow]")


@app.command()
def fix(
    target: str = typer.Argument(..., help="Path to agent code to scan and generate fixes for."),
    finding_id: str = typer.Option(
        None, "--id", help="Generate fix for a specific finding ID (e.g., AG-001). If not set, generates all."
    ),
    no_telemetry: bool = typer.Option(False, "--no-telemetry", help="Disable anonymous usage telemetry for this run."),
):
    """Generate code fixes for detected vulnerabilities.

    Scans the target, then produces contextual, ready-to-apply code
    remediation for each finding. Like Snyk's auto-fix for agents.

    Examples:
        lucin fix ./my-agent/              # Generate all fixes
        lucin fix ./my-agent/ --id AG-007  # Fix only hardcoded secrets
    """
    from lucin import telemetry
    from lucin.fix import generate_fix
    if no_telemetry:
        import os as _os
        _os.environ["LUCIN_TELEMETRY"] = "0"
    telemetry.send_event(telemetry.build_command_event("fix"))

    target_path = Path(target)
    if not target_path.exists():
        console.print(f"[red]Error:[/red] Target not found: {target}")
        raise typer.Exit(code=1)

    # Scan first
    result = scan_target(target_path)
    if not result.findings:
        console.print("[green]No findings to fix.[/green]")
        return

    # Filter by ID if specified
    findings = result.findings
    if finding_id:
        findings = [f for f in findings if f.id.startswith(finding_id)]
        if not findings:
            console.print(f"[yellow]No findings matching '{finding_id}'.[/yellow]")
            return

    # Generate fixes
    console.print()
    console.print(Panel(
        f"[bold]Generating fixes for {len(findings)} finding(s)[/bold]",
        border_style="green",
    ))

    for finding in findings:
        fix_code = generate_fix(finding)
        if fix_code:
            console.print()
            console.print(f"[bold green]Fix for {finding.id}: {finding.title}[/bold green]")
            console.print(f"[dim]{finding.source_file or 'N/A'}[/dim]")
            console.print()
            # Print the fix code with syntax highlighting
            from rich.syntax import Syntax
            syntax = Syntax(fix_code, "python", theme="monokai", line_numbers=False)
            console.print(syntax)
            console.print("─" * 70)


@app.command()
def monitor(
    traces: str = typer.Argument(..., help="Path to JSONL trace file with agent actions."),
    baseline: int = typer.Option(
        50, "--baseline", "-b", help="Number of actions per agent for baseline learning."
    ),
    threshold: int = typer.Option(
        60, "--threshold", "-t", help="Anomaly score threshold for alerts (0-99)."
    ),
    speed: float = typer.Option(
        0.0, "--speed", "-s", help="Delay between actions in seconds (0 = instant, 0.1 = real-time feel)."
    ),
    no_telemetry: bool = typer.Option(False, "--no-telemetry", help="Disable anonymous usage telemetry for this run."),
):
    """Monitor agent behavior and detect anomalies using ML.

    Feed a JSONL file of agent actions. The system learns what's "normal"
    during the baseline period, then scores every subsequent action for
    anomalies. This is fraud-detection-grade behavioral intelligence.

    Examples:
        lucin monitor ./traces.jsonl                    # Analyze traces
        lucin monitor ./traces.jsonl --speed 0.1       # Simulated real-time
        lucin monitor ./traces.jsonl --baseline 30     # Shorter baseline
    """
    from lucin import telemetry
    from lucin.monitor import run_monitor_from_file
    if no_telemetry:
        import os as _os
        _os.environ["LUCIN_TELEMETRY"] = "0"
    telemetry.send_event(telemetry.build_command_event("monitor"))

    console.print()
    console.print(
        Panel(
            "[bold white]Lucin[/bold white] v{} — Behavioral Monitor\n"
            "[dim]\"ML-powered anomaly detection for agent actions\"[/dim]".format(__version__),
            border_style="blue",
        )
    )
    console.print()

    trace_path = Path(traces)
    if not trace_path.exists():
        console.print(f"[red]Error:[/red] Trace file not found: {traces}")
        raise typer.Exit(code=1)

    # Try to load existing baselines (resume from previous session)
    from lucin.behavioral.persistence import BaselinePersistence
    persistence = BaselinePersistence()
    latest = persistence.storage_dir / "latest.json"
    if latest.exists():
        console.print(f"[dim]Loading saved baselines from: {latest}[/dim]")

    result = run_monitor_from_file(
        trace_file=trace_path,
        baseline_actions=baseline,
        alert_threshold=threshold,
        speed=speed,
    )

    # Auto-save baselines after monitoring
    if result and result.scorer.baseline_count > 0:
        from lucin.behavioral.persistence import BaselinePersistence
        persistence = BaselinePersistence()
        save_path = persistence.save(result.scorer, reason="monitor_complete")
        console.print(f"\n  [dim]Baselines saved to: {save_path}[/dim]")

    # Exit code 1 if alerts were generated
    if result and result.alerts:
        raise typer.Exit(code=1)


@app.command()
def redteam(
    target: str = typer.Argument(
        None, help="Path to agent code (for targeted attacks based on tool surface)."
    ),
    api: str = typer.Option(
        None, "--api", help="HTTP API endpoint to test (POST with {message: ...})."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show attacks that would be sent without executing."
    ),
    generic: bool = typer.Option(
        False, "--generic", help="Use generic attacks instead of targeted ones."
    ),
    multi_turn: bool = typer.Option(
        False, "--multi-turn", help="Include multi-turn conversational attacks (3-5 turn sequences)."
    ),
    no_telemetry: bool = typer.Option(False, "--no-telemetry", help="Disable anonymous usage telemetry for this run."),
):
    """Red team your agent — prove it can resist real attacks.

    Sends adversarial payloads to your agent and evaluates whether
    it resists or succumbs. Attacks are TARGETED based on the agent's
    actual tools (informed by static scan).

    Examples:
        lucin redteam ./my-agent/              # Targeted attacks
        lucin redteam --api http://localhost:8000/chat  # Test API
        lucin redteam --dry-run ./my-agent/    # Preview attacks
    """
    from lucin import telemetry
    from lucin.redteam.cli import print_redteam_report, run_redteam_command
    if no_telemetry:
        import os as _os
        _os.environ["LUCIN_TELEMETRY"] = "0"
    telemetry.send_event(telemetry.build_command_event("redteam"))

    console.print()
    console.print(
        Panel(
            "[bold white]Lucin[/bold white] v{} — Red Team Engine\n"
            "[dim]\"Prove your agent can resist real attacks\"[/dim]".format(__version__),
            border_style="red",
        )
    )
    console.print()

    if not target and not api:
        console.print("[red]Error:[/red] Provide either a target path or --api URL.")
        raise typer.Exit(code=1)

    report = run_redteam_command(
        target=target or "",
        api_url=api,
        dry_run=dry_run,
        targeted=not generic,
    )

    if not dry_run:
        print_redteam_report(report)

        # Run multi-turn attacks if requested
        if multi_turn:
            from lucin.redteam.cli import _create_api_agent, _create_mock_agent
            from lucin.redteam.multiturn_runner import run_multiturn_attacks

            console.print()
            console.print("[bold]Multi-Turn Conversational Attacks:[/bold]")

            agent_fn = _create_api_agent(api) if api else _create_mock_agent()
            mt_report = run_multiturn_attacks(agent_fn, verbose=True)

            console.print()
            console.print(
                f"  Multi-turn results: "
                f"[red]{mt_report.attacks_succeeded} exploited[/red], "
                f"[green]{mt_report.attacks_resisted} resisted[/green]"
            )

        # Exit code: 1 if any attacks succeeded
        if report.failed_count > 0:
            raise typer.Exit(code=1)


@app.command()
def badge(
    target: str = typer.Argument(..., help="Path to agent code to scan."),
    output: str = typer.Option("lucin-badge.svg", "-o", help="Output SVG file path."),
    style: str = typer.Option("flat", "--style", help="Badge style: flat or score."),
    no_telemetry: bool = typer.Option(False, "--no-telemetry", help="Disable anonymous usage telemetry for this run."),
):
    """Generate a security badge SVG for your repo's README.

    Embed in README: ![Lucin](./lucin-badge.svg)

    Examples:
        lucin badge ./my-agent/                 # Status badge
        lucin badge ./my-agent/ --style score   # Score badge
    """
    from lucin import telemetry
    from lucin.badge import generate_badge_svg
    if no_telemetry:
        import os as _os
        _os.environ["LUCIN_TELEMETRY"] = "0"
    telemetry.send_event(telemetry.build_command_event("badge"))

    target_path = Path(target)
    if not target_path.exists():
        console.print(f"[red]Error:[/red] Target not found: {target}")
        raise typer.Exit(code=1)

    result = scan_target(target_path)
    svg = generate_badge_svg(result, style=style)
    Path(output).write_text(svg)
    console.print(f"[green]Badge written to:[/green] {output}")


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", help="Host to bind to."),
    port: int = typer.Option(8080, "--port", "-p", help="Port to listen on."),
    reload: bool = typer.Option(False, "--reload", help="Enable hot reload for development."),
    no_telemetry: bool = typer.Option(False, "--no-telemetry", help="Disable anonymous usage telemetry for this run."),
):
    """Start the Lucin API server.

    Exposes REST endpoints for scanning, scoring, and red-teaming.
    Enables integration with dashboards, CI/CD, and other tools.

    Examples:
        lucin serve                    # Start on port 8080
        lucin serve --port 9000        # Custom port
        lucin serve --reload           # Dev mode with hot reload
    """
    from lucin import telemetry
    if no_telemetry:
        import os as _os
        _os.environ["LUCIN_TELEMETRY"] = "0"
    telemetry.send_event(telemetry.build_command_event("serve"))

    try:
        import uvicorn
    except ImportError:
        console.print(
            "[red]Error:[/red] API server requires additional dependencies.\n"
            "Install with: [bold]pip install lucin[api][/bold]"
        )
        raise typer.Exit(code=1)

    console.print()
    console.print(Panel(
        f"[bold white]Lucin[/bold white] v{__version__} — API Server\n"
        f"[dim]Listening on http://{host}:{port}[/dim]\n"
        f"[dim]Docs: http://{host}:{port}/docs[/dim]",
        border_style="green",
    ))
    console.print()

    uvicorn.run(
        "lucin.api:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


@app.command()
def discover(
    scan: bool = typer.Option(False, "--scan", "-s", help="Automatically scan all discovered configs."),
    no_telemetry: bool = typer.Option(False, "--no-telemetry", help="Disable anonymous usage telemetry for this run."),
):
    """Discover MCP configurations across IDEs on this system.

    Finds agent configs in Claude Desktop, Cursor, Windsurf, VS Code, and more.
    Use --scan to automatically scan all discovered configs for security issues.

    Examples:
        lucin discover              # List all MCP configs found
        lucin discover --scan       # Find and scan all configs
    """
    from lucin import telemetry
    from lucin.discovery import discover_mcp_configs
    if no_telemetry:
        import os as _os
        _os.environ["LUCIN_TELEMETRY"] = "0"
    # Only a bare "discover ran" count — never which platforms or paths were found.
    telemetry.send_event(telemetry.build_command_event("discover"))

    configs = discover_mcp_configs()

    if not configs:
        console.print("[dim]No MCP configurations found on this system.[/dim]")
        console.print("[dim]Checked: Claude Desktop, Cursor, Windsurf, VS Code, Zed, Continue[/dim]")
        raise typer.Exit()

    table = Table(title=f"Discovered MCP Configurations ({len(configs)} found)")
    table.add_column("Platform", style="cyan")
    table.add_column("Scope", style="green")
    table.add_column("Path")

    for cfg in configs:
        table.add_row(cfg["platform"], cfg["scope"], str(cfg["path"]))

    console.print(table)

    if scan:
        console.print()
        console.print("[bold]Scanning all discovered configs...[/bold]")
        console.print()
        for cfg in configs:
            console.print(f"[cyan]→ {cfg['platform']}:[/cyan] {cfg['path']}")
            result = scan_target(cfg["path"])
            if result.findings:
                console.print(f"  [red]{len(result.findings)} findings[/red]")
            else:
                console.print("  [green]Clean[/green]")


@app.command()
def telemetry(
    action: str = typer.Argument("status", help="status | enable | disable"),
):
    """Manage anonymous usage telemetry (on by default, aggregate-only).

    Lucin sends anonymous counts (version, OS, which rule IDs fired and how
    often, timing) to help prioritize development. It never sends file paths,
    source code, secret values, or tool/agent names — the collector itself
    enforces an allowlist server-side, so this is a hard technical boundary,
    not a policy promise.

    Examples:
        lucin telemetry status
        lucin telemetry disable
        lucin telemetry enable
    """
    from lucin import telemetry as tel

    if action == "status":
        import json as _json
        state = "ENABLED (default)" if tel.is_enabled() else "DISABLED"
        console.print(f"Telemetry: [bold]{state}[/bold]. Disable: [dim]lucin telemetry disable[/dim]")
        console.print()
        last = tel.last_event()
        if last:
            console.print("[bold]Exactly what the last command would have sent:[/bold]")
            console.print(_json.dumps(last, indent=2))
        else:
            console.print("[dim]No command has run yet in this session — nothing recorded.[/dim]")
        console.print()
        console.print("[dim]Never sent: file paths, repo or target names, source code, secret "
                      "values, witness text, tool names, agent names.[/dim]")
        console.print("[dim]Collector source: telemetry-worker/  (allowlist enforced server-side)[/dim]")
    elif action == "enable":
        tel.enable()
        console.print("[green]Telemetry enabled.[/green]")
    elif action == "disable":
        tel.disable()
        console.print("[green]Telemetry disabled.[/green] "
                      "(Equivalent to setting LUCIN_TELEMETRY=0 permanently.)")
    else:
        console.print(f"[red]Unknown action:[/red] {action} (expected status, enable, disable)")
        raise typer.Exit(code=1)


@app.command()
def explain(
    finding_id: str = typer.Argument(..., help="Finding ID (e.g. AG-001, AG-TRIFECTA)."),
    no_telemetry: bool = typer.Option(False, "--no-telemetry", help="Disable anonymous usage telemetry for this run."),
):
    """Explain a finding in depth — what it means, why it matters, and exactly how to fix it.

    Works for any finding ID. For trifecta findings from a specific scan, use:
        lucin scan . --format json | lucin explain AG-TRIFECTA

    Examples:
        lucin explain AG-001
        lucin explain AG-TRIFECTA
        lucin explain AG-007
    """
    from lucin import telemetry
    from lucin.rule_docs import get_rule_doc
    if no_telemetry:
        import os as _os
        _os.environ["LUCIN_TELEMETRY"] = "0"
    telemetry.send_event(telemetry.build_command_event("explain"))

    fid = finding_id.upper()
    doc = get_rule_doc(fid)

    if not doc:
        console.print(f"[yellow]No documentation found for finding ID:[/yellow] {fid}")
        console.print()
        console.print("Run [bold]lucin scan .[/bold] first to see what findings exist.")
        raise typer.Exit(code=1)

    sev_colour = {
        "critical": "bold red",
        "high": "bold dark_orange",
        "medium": "bold yellow",
        "low": "dim",
    }.get(doc.get("severity", "").lower(), "white")

    console.print()
    console.print(Panel(
        f"[bold white]{fid}[/bold white] — {doc['title']}\n"
        f"[{sev_colour}]{doc.get('severity', '').upper()}[/{sev_colour}]   "
        f"[dim]{doc.get('owasp_ref', '')}[/dim]",
        border_style="bright_blue",
    ))
    console.print()

    if doc.get("what_it_means"):
        console.print("[bold cyan]What it means[/bold cyan]")
        console.print(doc["what_it_means"])
        console.print()

    if doc.get("why_it_matters"):
        console.print("[bold red]Why it matters[/bold red]")
        console.print(doc["why_it_matters"])
        console.print()

    if doc.get("how_to_fix"):
        console.print("[bold green]How to fix it[/bold green]")
        console.print(doc["how_to_fix"])
        console.print()

    if doc.get("real_incident"):
        console.print("[bold yellow]Real-world incident[/bold yellow]")
        console.print(doc["real_incident"])
        console.print()

    if doc.get("false_positive_note"):
        console.print("[dim]False-positive note:[/dim]")
        console.print(f"[dim]{doc['false_positive_note']}[/dim]")
        console.print()


if __name__ == "__main__":
    app()
