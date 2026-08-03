"""Terminal output formatting — the screenshot moment."""

import textwrap
from pathlib import PurePath

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lucin.models import Finding, ScanResult, Severity
from lucin.scoring import calculate_security_score, score_color, score_label


def _print_hanging(console: Console, text: Text, indent: int) -> None:
    """Print a Rich Text with a hanging indent on wrapped continuation lines,
    at narrow widths, instead of Rich's default (which wraps to column 0)."""
    width = console.width
    pad = Text(" " * indent)
    for i, line in enumerate(text.wrap(console, width)):
        console.print(pad + line if i > 0 else line)


# No emoji markers. Two independent reasons converged on dropping them
# entirely rather than gating behind a flag or NO_COLOR check:
#   - Emoji render at inconsistent cell widths across terminals and font
#     stacks (Rich sizes panel borders from the Unicode width category, not
#     the terminal's actual glyph rendering, so the two can disagree and the
#     border misaligns).
#   - The severity word ("CRITICAL:", "HIGH:", ...) already states the same
#     information the marker did, and border/text color already carries it a
#     second time — the marker was pure redundancy, and in NO_COLOR mode it
#     used to duplicate literally: "[CRIT] CRITICAL: ...".
SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
    Severity.INFO: "dim",
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
    target_text = Text.from_markup(
        f" [bold]Target:[/bold] {result.target} "
        f"({agent_count} {unit}{'s' if agent_count != 1 else ''}, "
        f"{tool_count} tool{'s' if tool_count != 1 else ''}, "
        f"{mcp_count} MCP server{'s' if mcp_count != 1 else ''})"
    )
    _print_hanging(console, target_text, indent=9)  # aligns under "Target: "
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

    # Security Score — rendered on both paths, including a clean scan: 100/100 is the
    # one genuinely shareable moment the product produces, and it used to vanish exactly
    # when the news was good.
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

    if not result.findings:
        console.print(Panel(
            "[green bold]No security findings detected.[/green bold]\n\n"
            "[dim]This doesn't mean your agents are perfectly secure — "
            "it means no known dangerous patterns were detected in their configuration.[/dim]\n\n"
            "[dim]Show it: [/dim]lucin badge . --style score[dim]  →  drops an SVG for your README.[/dim]",
            title="✅ Clean Scan",
            border_style="green",
        ))
        return

    # Triage table — every finding, one line each, so the shape of the
    # problem is visible before scrolling into the full panels below.
    _print_triage_table(console, result)
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


def _print_triage_table(console: Console, result: ScanResult):
    """Print every finding as one table row, sorted by severity, so the shape
    of the problem — how many, which severity, which tool, where — is visible
    in one screen before the full panels below. Every finding still gets its
    full panel; this table adds a triage view in front of it, it does not
    replace or gate anything."""
    counts_line = " · ".join(
        f"[{style}]{n} {label.lower()}[/{style}]"
        for label, n, style in (
            ("CRITICAL", result.critical_count, "bold red"),
            ("HIGH", result.high_count, "bold yellow"),
            ("MEDIUM", result.medium_count, "yellow"),
            ("LOW", result.low_count, "dim"),
        )
        if n
    )

    table = Table(title=f"RISK SUMMARY  ·  {counts_line}", title_justify="left",
                  box=None, pad_edge=False, show_edge=False, expand=True)
    table.add_column("SEV")
    table.add_column("RULE")
    table.add_column("TOOL")
    table.add_column("LOCATION")

    for finding in sorted(result.findings, key=lambda f: list(Severity).index(f.severity)):
        style = SEVERITY_STYLES[finding.severity]
        # Basename only: the target's directory prefix is already in the
        # "Target:" line above and repeating it on every row is what forced
        # truncation of the one column that identifies where to look.
        loc = PurePath(finding.source_file).name if finding.source_file else "—"
        if finding.source_line:
            loc += f":{finding.source_line}"
        table.add_row(
            f"[{style}]{finding.severity.value.upper()}[/{style}]",
            finding.id,
            finding.tool_name or "—",
            loc,
        )

    console.print(Panel(table, border_style="bright_red" if result.critical_count else "yellow"))


def _print_finding(console: Console, finding: Finding):
    """Print a single finding."""
    style = SEVERITY_STYLES[finding.severity]

    lines = []
    if finding.agent_name:
        lines.append(f"Agent: [bold]{finding.agent_name}[/bold]")
    if finding.tool_name:
        lines.append(f"Tool: [bold]{finding.tool_name}[/bold]")
    lines.append("")
    lines.append(finding.description)

    if finding.attack_scenario:
        lines.append("")
        lines.append(f"[dim]Attack:[/dim] {finding.attack_scenario}")

    if finding.blast_radius:
        lines.append(f"[dim]Blast radius:[/dim] {finding.blast_radius}")

    if finding.owasp_ref:
        lines.append(f"[dim]OWASP Agentic:[/dim] {finding.owasp_ref}")

    if finding.witness:
        lines.append("")
        lines.append("[cyan]Proof:[/cyan]")
        # Wrap each witness line ourselves, with every physical line — first
        # and continuation alike — carrying the same 2-space indent. Left to
        # Rich's own paragraph wrapping, a long witness resets to the panel's
        # left edge on wrap, so "confirmed by body inspection" reads as a
        # new, unrelated fact instead of a continuation of the line above it.
        content_width = max(20, console.width - 6)  # panel border + padding
        for w in finding.witness:
            for wrapped_line in textwrap.wrap(w, width=content_width - 2) or [""]:
                lines.append(f"  [dim]{wrapped_line}[/dim]")

    if finding.fix_suggestion:
        lines.append("")
        lines.append(f"[green]Fix:[/green] {finding.fix_suggestion}")

    if finding.source_file:
        loc = finding.source_file
        if finding.source_line:
            loc += f":{finding.source_line}"
        # Skip if the same file:line already appears in the proof witness above —
        # two lines to say the same thing costs 66 lines across a 33-finding scan.
        already_shown = any(loc in w for w in finding.witness)
        if not already_shown:
            lines.append(f"[dim]Location:[/dim] {loc}")

    border_style = style.replace("bold ", "")
    if finding.is_new is True:
        title = f"NEW {finding.severity.value.upper()}: {finding.title} [{finding.id}]"
    elif finding.is_new is False:
        title = f"accepted {finding.severity.value.upper()}: {finding.title} [{finding.id}]"
        border_style = "dim"
    else:
        title = f"{finding.severity.value.upper()}: {finding.title} [{finding.id}]"
    console.print(Panel(
        "\n".join(lines),
        title=title,
        border_style=border_style,
    ))


def _print_ci_output(console: Console, result: ScanResult):
    """Minimal CI output."""
    for finding in result.findings:
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
            f"{tag}[{finding.severity.value.upper()}] {finding.id}: "
            f"{finding.title} - {finding.agent_name}{loc}"
        )

    console.print()
    console.print(
        f"Found: {result.critical_count} critical, {result.high_count} high, "
        f"{result.medium_count} medium, {result.low_count} low"
    )
