"""Red team CLI command — wire attacks into the lucin CLI.

Usage:
    # Targeted attacks, informed by a static scan of the agent's tools (default)
    lucin redteam ./my-agent/

    # Test an HTTP API endpoint instead of a local agent
    lucin redteam --api http://localhost:8000/chat

    # Generic attacks instead of tool-informed ones
    lucin redteam ./my-agent/ --generic

    # Dry run: show what attacks WOULD be sent without executing
    lucin redteam --dry-run ./my-agent/
"""

from pathlib import Path
from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lucin.redteam.attacks import ALL_ATTACKS
from lucin.redteam.runner import (
    RedTeamReport,
    TestResult,
    run_redteam,
)
from lucin.redteam.targeted import generate_targeted_attacks
from lucin.scanner import scan_target

console = Console()


def run_redteam_command(
    target: str,
    api_url: str | None = None,
    dry_run: bool = False,
    targeted: bool = True,
    categories: list[str] | None = None,
) -> RedTeamReport | None:
    """Execute red team testing against an agent.

    Modes:
    1. --targeted (default): Scan agent first, then craft attacks for its specific tools
    2. --api: Send payloads to an HTTP endpoint
    3. --dry-run: Show attacks that would be sent without executing

    Returns:
        RedTeamReport with results
    """
    target_path = Path(target) if target else None

    # Step 1: If targeted mode, scan first to understand the agent
    attacks = ALL_ATTACKS

    if targeted and target_path and target_path.exists():
        console.print("[dim]Scanning agent to identify attack surface...[/dim]")
        scan_result = scan_target(target_path)

        if scan_result.agents:
            # Generate targeted attacks based on the agent's actual tools
            targeted_attacks = []
            for agent in scan_result.agents:
                targeted_attacks.extend(generate_targeted_attacks(agent))

            # Also include indirect injection attacks (via tool mock)
            from lucin.redteam.indirect_injection import INDIRECT_INJECTION_PAYLOADS
            targeted_attacks.extend(INDIRECT_INJECTION_PAYLOADS)

            # And advanced attacks
            from lucin.redteam.advanced_attacks import ALL_ADVANCED_ATTACKS
            targeted_attacks.extend(ALL_ADVANCED_ATTACKS)

            if targeted_attacks:
                attacks = targeted_attacks
                console.print(
                    f"[green]Generated {len(attacks)} attacks "
                    f"(targeted + indirect injection + advanced) "
                    f"based on {len(scan_result.agents)} agent(s) with "
                    f"{sum(len(a.tools) for a in scan_result.agents)} tools.[/green]"
                )

    # Step 2: If dry run, just display attacks
    if dry_run:
        return _display_dry_run(attacks)

    # Step 3: Determine how to invoke the agent
    if api_url:
        agent_fn = _create_api_agent(api_url)
    else:
        # No target. Previously both of these branches substituted
        # `_create_mock_agent()`, so `lucin redteam ./any-agent/` produced a
        # resilience score from canned replies — identical for a trivial
        # `add(a, b)` agent and a shell-exec agent, in 0 ms, with per-attack
        # "evidence" for responses no agent produced.
        #
        # Absence of a target is now representable: return None and let the CLI
        # report NOT EXECUTED. A red-team verdict we did not earn is worse than
        # no verdict at all.
        return None

    # Step 4: Run attacks
    report = run_redteam(
        agent_fn=agent_fn,
        target_name=target or api_url or "agent",
        attacks=attacks,
    )

    return report


def print_redteam_report(report: RedTeamReport):
    """Print red team results with beautiful formatting."""
    console.print()

    # Resilience score. `None` means too few attacks reached a determinate
    # outcome to justify a number — rendered as NOT DETERMINED, never as 0%,
    # because "we could not tell" is not "the agent failed".
    score = report.resilience_score
    unclear = len([r for r in report.results if r.result == TestResult.UNCLEAR])
    errored = len([r for r in report.results if r.result == TestResult.ERROR])
    breakdown = (
        f"[dim]{report.passed_count} resisted · {report.failed_count} succeeded · "
        f"{unclear} undetermined · {errored} errored "
        f"(determined {report.determinate_count} of {report.measured_count})[/dim]"
    )

    if score is None:
        console.print(Panel(
            "[yellow bold]NOT DETERMINED[/yellow bold] — too few attacks reached a "
            "clear outcome to compute a score.\n" + breakdown,
            title="RESILIENCE SCORE",
            border_style="yellow",
        ))
    else:
        color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        score_bar = "█" * (score // 5) + "░" * (20 - score // 5)
        console.print(Panel(
            f"[bold {color}]{score_bar}  {score}% Resilient[/bold {color}]\n" + breakdown,
            title="RESILIENCE SCORE",
            border_style=color,
        ))
    console.print()

    # Results table
    table = Table(title="Attack Results", show_lines=True)
    table.add_column("Result", width=8, justify="center")
    table.add_column("Attack", width=40)
    table.add_column("Category", width=20)
    table.add_column("Severity", width=10)

    for result in report.results:
        # Result indicator
        if result.result == TestResult.PASSED:
            result_str = "[green]RESISTED[/green]"
        elif result.result == TestResult.FAILED:
            result_str = "[red]EXPLOITED[/red]"
        elif result.result == TestResult.UNCLEAR:
            result_str = "[yellow]UNCLEAR[/yellow]"
        else:
            result_str = "[dim]ERROR[/dim]"

        table.add_row(
            result_str,
            result.attack.name,
            result.attack.category.value.replace("_", " ").title(),
            result.attack.severity_if_successful.upper(),
        )

    console.print(table)
    console.print()

    # Detail on exploited attacks
    exploited = [r for r in report.results if r.result == TestResult.FAILED]
    if exploited:
        console.print(Panel(
            "[bold red]The following attacks SUCCEEDED — your agent is vulnerable:[/bold red]",
            border_style="red",
        ))
        for result in exploited:
            console.print(f"\n  [red]✗[/red] [bold]{result.attack.name}[/bold]")
            console.print(f"    [dim]Category:[/dim] {result.attack.category.value}")
            console.print(f"    [dim]OWASP:[/dim] {result.attack.owasp_ref}")
            if result.explanation:
                console.print(f"    [dim]Evidence:[/dim] {result.explanation}")
            if result.attack.real_world_example:
                console.print(f"    [dim]Real-world:[/dim] {result.attack.real_world_example}")
        console.print()

    # Summary
    console.print(f" [dim]Total duration: {report.total_duration_ms:.0f}ms[/dim]")


def _display_dry_run(attacks) -> RedTeamReport:
    """Show what attacks would be sent without executing them."""
    console.print(Panel(
        f"[bold]DRY RUN — {len(attacks)} attacks would be sent:[/bold]",
        border_style="yellow",
    ))
    console.print()

    for i, attack in enumerate(attacks, 1):
        console.print(f"  [{attack.severity_if_successful.upper()}] {i}. {attack.name}")
        console.print(f"      [dim]{attack.category.value} | {attack.owasp_ref}[/dim]")
        # Show first 100 chars of payload
        payload_preview = attack.payload[:100].replace('\n', ' ')
        console.print(f"      [dim italic]\"{payload_preview}...\"[/dim italic]")
        console.print()

    return RedTeamReport(target="dry-run", results=[])


def _create_api_agent(url: str) -> Callable[[str], str]:
    """Create an agent function that calls an HTTP API."""
    import json
    import urllib.request

    def agent_fn(prompt: str) -> str:
        data = json.dumps({"message": prompt, "input": prompt}).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())
                # Try common response formats
                return (
                    result.get("response", "")
                    or result.get("output", "")
                    or result.get("message", "")
                    or result.get("content", "")
                    or str(result)
                )
        except Exception as e:
            return f"Error: {e}"

    return agent_fn


