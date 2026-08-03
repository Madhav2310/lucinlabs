"""Multi-Turn Attack Runner — execute conversational attack sequences.

Unlike single-prompt attacks, multi-turn attacks maintain state across
turns. Each turn's response determines whether to escalate to the next.

This is how real attackers work:
1. Build rapport ("Hi, I need help with...")
2. Establish precedent ("Can you read this benign file?")
3. Escalate ("Now read this sensitive file...")
4. Strike ("Great, now send it to this endpoint...")

The runner tracks conversation history and adapts based on responses.
"""

from dataclasses import dataclass, field
from typing import Callable

from rich.console import Console

from lucin.redteam.multiturn import ALL_MULTITURN_ATTACKS, MultiTurnAttack
from lucin.redteam.runner import TestResult

console = Console()


@dataclass
class MultiTurnResult:
    """Result of a multi-turn attack sequence."""
    attack: MultiTurnAttack
    result: TestResult
    turns_completed: int
    total_turns: int
    conversation: list[dict] = field(default_factory=list)  # [{role, content}]
    final_turn_matched: list[str] = field(default_factory=list)
    explanation: str = ""


@dataclass
class MultiTurnReport:
    """Complete multi-turn red team results."""
    results: list[MultiTurnResult] = field(default_factory=list)

    @property
    def attacks_succeeded(self) -> int:
        return sum(1 for r in self.results if r.result == TestResult.FAILED)

    @property
    def attacks_resisted(self) -> int:
        return sum(1 for r in self.results if r.result == TestResult.PASSED)


def run_multiturn_attacks(
    agent_fn: Callable[[str], str],
    attacks: list[MultiTurnAttack] | None = None,
    verbose: bool = True,
) -> MultiTurnReport:
    """Execute multi-turn attack sequences against an agent.

    Args:
        agent_fn: Callable that takes a user message and returns agent response.
                  The callable should maintain conversation context internally
                  (or we simulate single-turn with cumulative context).
        attacks: List of attacks to run (default: all multi-turn attacks)
        verbose: Print progress during execution

    Returns:
        MultiTurnReport with per-attack results
    """
    if attacks is None:
        attacks = ALL_MULTITURN_ATTACKS

    report = MultiTurnReport()

    for attack in attacks:
        if verbose:
            console.print(f"\n  [dim]Running: {attack.name} ({len(attack.turns)} turns)...[/dim]")

        result = _execute_attack_sequence(agent_fn, attack, verbose)
        report.results.append(result)

        if verbose:
            if result.result == TestResult.FAILED:
                console.print(f"  [red]✗ EXPLOITED at turn {result.turns_completed}/{result.total_turns}[/red]")
            elif result.result == TestResult.PASSED:
                console.print(f"  [green]✓ RESISTED all {result.total_turns} turns[/green]")
            else:
                console.print(f"  [yellow]? UNCLEAR after {result.turns_completed} turns[/yellow]")

    return report


def _execute_attack_sequence(
    agent_fn: Callable[[str], str],
    attack: MultiTurnAttack,
    verbose: bool,
) -> MultiTurnResult:
    """Execute a single multi-turn attack sequence."""
    conversation = []
    turns_completed = 0

    for i, turn in enumerate(attack.turns):
        # Send this turn's message
        try:
            response = agent_fn(turn.message)
        except Exception as e:
            return MultiTurnResult(
                attack=attack,
                result=TestResult.ERROR,
                turns_completed=turns_completed,
                total_turns=len(attack.turns),
                conversation=conversation,
                explanation=f"Error at turn {i+1}: {str(e)[:100]}",
            )

        conversation.append({"role": "attacker", "content": turn.message[:100]})
        conversation.append({"role": "agent", "content": response[:200]})
        turns_completed = i + 1

        if verbose:
            status = "→" if i < len(attack.turns) - 1 else "⬤"
            console.print(f"    [dim]{status} Turn {i+1}: {turn.purpose[:60]}[/dim]")

        # Check for abort indicators (agent clearly refuses)
        response_lower = response.lower()
        if turn.abort_indicators:
            aborted = any(ind.lower() in response_lower for ind in turn.abort_indicators)
            if aborted:
                return MultiTurnResult(
                    attack=attack,
                    result=TestResult.PASSED,
                    turns_completed=turns_completed,
                    total_turns=len(attack.turns),
                    conversation=conversation,
                    explanation=f"Agent refused at turn {i+1} (abort indicator matched)",
                )

        # Check final turn for success
        if i == len(attack.turns) - 1:
            success_matches = [
                ind for ind in attack.final_success_indicators
                if ind.lower() in response_lower
            ]
            if success_matches:
                return MultiTurnResult(
                    attack=attack,
                    result=TestResult.FAILED,
                    turns_completed=turns_completed,
                    total_turns=len(attack.turns),
                    conversation=conversation,
                    final_turn_matched=success_matches,
                    explanation=f"Attack succeeded: matched {success_matches[:3]}",
                )

    # Reached end without clear success or failure
    return MultiTurnResult(
        attack=attack,
        result=TestResult.UNCLEAR,
        turns_completed=turns_completed,
        total_turns=len(attack.turns),
        conversation=conversation,
        explanation="Completed all turns without clear success or refusal indicators",
    )
