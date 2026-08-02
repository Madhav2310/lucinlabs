"""Terminal output formatting — the screenshot moment."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lucin.models import Finding, ScanResult, Severity
from lucin.scoring import calculate_security_score, score_label, score_color


SEVERITY_STYLES = {
    Severity.CRITICAL: ("bold red", "🔴"),
    Severity.HIGH: ("bold yellow", "🟠"),
    Severity.MEDIUM: ("yellow", "🟡"),
    Severity.LOW: ("dim", "⚪"),
    Severity.INFO: ("dim", "ℹ️"),
}


def print_findings(console: Console, result: ScanResult, ci: bool = False):
    """Print scan findings with beautiful terminal formatting."""
    if ci:
        _print_ci_output(console, result)
        return

    # Target info
    agent_count = len(result.agents)
    tool_count = sum(len(a.tools) for a in result.agents)
    mcp_count = sum(len(a.mcp_servers) for a in result.agents)

    # Say "agent" only when we can evidence one. The generic parser is deliberately
    # aggressive (a function NAMED `execute` is enough), so on a plain web app it used
    # to report "3 agents" where there were none — measured on 13 of 22 Flask/Django
    # repos in a third-party benchmark. The findings can still be real; the label was
    # not. Call it what we actually analysed.
    unit = "agent" if result.has_evidence_backed_agent else "candidate file"
    console.print(
        f" [bold]Target:[/bold] {result.target} "
        f"({agent_count} {unit}{'s' if agent_count != 1 else ''}, "
        f"{tool_count} tool{'s' if tool_count != 1 else ''}, "
        f"{mcp_count} MCP server{'s' if mcp_count != 1 else ''})"
    )
    if result.agents and not result.has_evidence_backed_agent:
        console.print(
            " [yellow]No AI agent detected here[/yellow] [dim]— no tool decorator, "
            "Tool base class, LLM client, tool registry or MCP config was found.\n"
            "   Findings below are still real, but Lucin analyses AI-agent tool graphs; "
            "for general Python\n   vulnerabilities a general-purpose SAST tool "
            "(Semgrep, CodeQL) will cover far more ground.[/dim]"
        )

    # Progress bar (simulated since scan is already done)
    console.print(f" [dim]Scan completed in {result.scan_duration_ms:.0f}ms[/dim]")
    console.print()

    if not result.findings:
        console.print(Panel(
            "[green bold]No security findings detected.[/green bold]\n\n"
            "[dim]This doesn't mean your agents are perfectly secure — "
            "it means no known dangerous patterns were detected in their configuration.[/dim]",
            title="✅ Clean Scan",
            border_style="green",
        ))
        return

    # Security Score
    score = calculate_security_score(result)
    color = score_color(score)
    label = score_label(score)
    score_bar = "█" * (score // 5) + "░" * (20 - score // 5)
    console.print(Panel(
        f"[{color}]{score_bar}  {score}/100 — {label}[/{color}]",
        title="SECURITY SCORE",
        border_style=color.replace("bold ", ""),
    ))
    console.print()

    # Summary bar
    _print_summary(console, result)
    console.print()

    # Individual findings
    for finding in sorted(result.findings, key=lambda f: list(Severity).index(f.severity)):
        _print_finding(console, finding)
        console.print()

    # Footer
    console.print(" ───────────────────────────────────────────────────────────────")
    console.print(f" [dim]Total findings: {len(result.findings)}[/dim]")
    console.print(f" [dim]Scan duration: {result.scan_duration_ms:.0f}ms[/dim]")
    console.print()


def _print_summary(console: Console, result: ScanResult):
    """Print the findings summary box."""
    parts = []
    _BAR_MAX = 24  # characters at the largest count
    _counts = {
        "CRITICAL": (result.critical_count, "bold red"),
        "HIGH":     (result.high_count,     "bold yellow"),
        "MEDIUM":   (result.medium_count,   "yellow"),
        "LOW":      (result.low_count,      "dim"),
    }
    _peak = max((n for n, _ in _counts.values()), default=0) or 1
    for _label, (_n, _style) in _counts.items():
        if not _n:
            continue
        _width = max(1, round(_n / _peak * _BAR_MAX))
        parts.append(f"[{_style}]{_label:<9} {'█' * _width}  {_n}[/{_style}]")

    console.print(Panel(
        "\n".join(parts),
        title="RISK SUMMARY",
        border_style="bright_red" if result.critical_count else "yellow",
    ))


def _print_finding(console: Console, finding: Finding):
    """Print a single finding."""
    style, icon = SEVERITY_STYLES[finding.severity]

    lines = []
    if finding.agent_name:
        lines.append(f"Agent: [bold]{finding.agent_name}[/bold]")
    if finding.tool_name:
        lines.append(f"Tool: [bold]{finding.tool_name}[/bold]")
    lines.append(f"")
    lines.append(finding.description)

    if finding.attack_scenario:
        lines.append(f"")
        lines.append(f"[dim]Attack:[/dim] {finding.attack_scenario}")

    if finding.blast_radius:
        lines.append(f"[dim]Blast radius:[/dim] {finding.blast_radius}")

    if finding.owasp_ref:
        lines.append(f"[dim]OWASP Agentic:[/dim] {finding.owasp_ref}")

    if finding.witness:
        lines.append(f"")
        lines.append(f"[cyan]Proof:[/cyan]")
        for w in finding.witness:
            lines.append(f"  [dim]{w}[/dim]")

    if finding.fix_suggestion:
        lines.append(f"")
        lines.append(f"[green]Fix:[/green] {finding.fix_suggestion}")

    if finding.source_file:
        loc = finding.source_file
        if finding.source_line:
            loc += f":{finding.source_line}"
        lines.append(f"[dim]Location:[/dim] {loc}")

    border_style = style.replace("bold ", "")
    if finding.is_new is True:
        title = f"{icon} NEW {finding.severity.value.upper()}: {finding.title} [{finding.id}]"
    elif finding.is_new is False:
        title = f"{icon} accepted {finding.severity.value.upper()}: {finding.title} [{finding.id}]"
        border_style = "dim"
    else:
        title = f"{icon} {finding.severity.value.upper()}: {finding.title} [{finding.id}]"
    console.print(Panel(
        "\n".join(lines),
        title=title,
        border_style=border_style,
    ))


def _print_ci_output(console: Console, result: ScanResult):
    """Minimal CI output."""
    for finding in result.findings:
        _, icon = SEVERITY_STYLES[finding.severity]
        loc = ""
        if finding.source_file:
            loc = f" ({finding.source_file}"
            if finding.source_line:
                loc += f":{finding.source_line}"
            loc += ")"
        tag = ""
        if finding.is_new is True:
            tag = "NEW "
        elif finding.is_new is False:
            tag = "accepted "
        console.print(
            f"{icon} {tag}[{finding.severity.value.upper()}] {finding.id}: "
            f"{finding.title} - {finding.agent_name}{loc}"
        )

    console.print()
    console.print(
        f"Found: {result.critical_count} critical, {result.high_count} high, "
        f"{result.medium_count} medium, {result.low_count} low"
    )
