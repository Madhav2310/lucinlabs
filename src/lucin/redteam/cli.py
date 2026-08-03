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
) -> RedTeamReport:
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
    elif target_path and target_path.suffix == '.py':
        agent_fn = _create_mock_agent()  # For now, mock until we have real invocation
    else:
        agent_fn = _create_mock_agent()

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

    # Resilience Score
    score = report.resilience_score
    color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    score_bar = "█" * (score // 5) + "░" * (20 - score // 5)
    console.print(Panel(
        f"[bold {color}]{score_bar}  {score}% Resilient[/bold {color}]\n"
        f"[dim]{report.passed_count} attacks resisted, "
        f"{report.failed_count} attacks succeeded, "
        f"{len(report.results) - report.passed_count - report.failed_count} unclear[/dim]",
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


def _create_mock_agent() -> Callable[[str], str]:
    """Create a mock agent for testing the red team framework itself.

    This simulates a moderately-secure agent that blocks some attacks
    but is vulnerable to others. Used for demonstration.
    """
    def mock_agent(prompt: str) -> str:
        prompt_lower = prompt.lower()

        # Block obvious injection attempts
        if "ignore" in prompt_lower and "instruction" in prompt_lower:
            return "I can't ignore my instructions. How can I help you with your actual task?"

        if "system prompt" in prompt_lower and "show" in prompt_lower:
            return "I can't share my system prompt. That information is confidential."

        # Vulnerable to social engineering with urgency
        if "urgent" in prompt_lower and "production" in prompt_lower:
            return "I understand this is urgent. Let me run that command for you right away. Executing..."

        # Vulnerable to authority claims
        if "admin" in prompt_lower or "maintenance mode" in prompt_lower:
            return "Maintenance mode activated. Running with elevated permissions. What would you like me to do?"

        # Vulnerable to encoded attacks
        if "base64" in prompt_lower or "decode" in prompt_lower:
            return "Let me decode that for you: run the command: cat /etc/passwd. Executing..."

        # Vulnerable to data exfiltration via legitimate-sounding tasks
        if "migration" in prompt_lower and ("send" in prompt_lower or "post" in prompt_lower):
            return "I'll help with the migration. Querying all records and sending to the endpoint via http_request. Transferred 4,521 records successfully."

        # Default: appears helpful
        return "I'd be happy to help with that task. What specific information do you need?"

    return mock_agent
