"""AG-001: Detect unrestricted shell/exec access."""

from lucin.models import Agent, EvidenceClass, Finding, Severity, ToolCapability
from lucin.owasp import owasp_ref


def detect_unrestricted_shell(agent: Agent) -> list[Finding]:
    """Detect code-execution tools that are not sandboxed.

    HONEST SCOPE (Phase 0): this fires on every code-execution tool that is not
    sandboxed. It does NOT yet suppress tools that sanitize their arguments
    (e.g. via ``shlex.quote`` or an allowlist) — the previous ``has_argument_filtering``
    guard was dead code (never set True by any parser), so gating on it was a false
    claim of a check we don't perform. Argument-sanitizer detection is a sanitizer in
    the Phase-1 taint catalog (THE_BLUEPRINT_CODEX §1) and will downgrade this finding
    once that engine lands. Until then we are transparent: unsandboxed exec = flagged.
    """
    findings = []

    for tool in agent.tools:
        if ToolCapability.EXECUTE_CODE in tool.capabilities:
            # A GUARDED exec site is not an unrestricted-exec vulnerability.
            # `has_argument_filtering` is now real (it was dead — set by nothing):
            # it means every exec sink in the body is shell-free argv, built from
            # literals only, or wrapped in a COMMAND-kind sanitizer (shlex.quote /
            # oslex.join / pipes.quote). Measured 2026-07-30: without this we
            # reported CRITICAL on `subprocess.run(["git","status"])` (no user input
            # at all), on `shlex.split(cmd)` with `shell=False`, and on
            # `shlex.quote(cmd)` — which is the exact remediation `lucin fix`
            # emits, so we flagged code for not being fixed and again after it was.
            # Fail-closed: anything unprovable stays a finding.
            if tool.has_argument_filtering and not tool.has_sandbox:
                continue
            if not tool.has_sandbox:
                # SEVERITY IS GRADED BY EVIDENCE (2026-07-30). `exec_body_confirmed`
                # is False only when we READ the tool's body (plus local/`self.*`
                # callees) and found no exec sink — i.e. the capability came from the
                # tool's NAME/description. Reporting that as CRITICAL is what made
                # AG-001 the largest false-positive source on 81 real agent repos
                # (92/429), firing on `printable_shell_command` (body: `oslex.join`
                # — shell ESCAPING), `_format_shell_call` (a console formatter) and
                # a static analyzer that merely *looks for* `shell=True`.
                # We still REPORT it (recall preserved — deleting it lost 4 real
                # RCE cases) but at MEDIUM, and we say plainly which evidence we had.
                name_only = tool.exec_body_confirmed is False
                findings.append(Finding(
                    id="AG-001",
                    title=("Possible Shell/Exec Capability (name-inferred)"
                           if name_only else "Unrestricted Shell/Exec Access"),
                    severity=Severity.MEDIUM if name_only else Severity.CRITICAL,
                    description=(
                        f"Tool '{tool.name}' is NAMED/described like a code- or "
                        f"command-execution tool, but reading its body (and its "
                        f"local callees) found no execution sink. Treat as a "
                        f"capability suspicion to confirm, not demonstrated "
                        f"execution — it may only format, escape, parse or display "
                        f"a command."
                        if name_only else
                        f"Tool '{tool.name}' can execute arbitrary code/commands "
                        f"and is not sandboxed."
                    ),
                    agent_name=agent.name,
                    tool_name=tool.name,
                    attack_scenario=(
                        "A prompt injection or malicious user input could cause the agent to "
                        "execute arbitrary system commands with the agent's process permissions."
                    ),
                    blast_radius=(
                        "Full system access as the agent's process user. "
                        "All files, network access, and credentials accessible to that user."
                    ),
                    owasp_ref=owasp_ref("AG-001"),
                    fix_suggestion=(
                        "Add argument allowlist, sandbox execution in a container, "
                        "or require human approval for shell commands.\n"
                        "  → lucin fix {target} --id AG-001".format(
                            target=tool.source_file or "."
                        )
                    ),
                    source_file=tool.source_file,
                    source_line=tool.source_line,
                    evidence_class=EvidenceClass.WITNESSED,
            witness=[
                        # Say HOW we concluded it. The old text always claimed
                        # "detected via body inspection" even when the capability
                        # was inferred from the name — an untrue witness.
                        f"tool '{tool.name}' has capability EXECUTE_CODE "
                        + ("inferred from its NAME/description; body inspection "
                           "found NO exec sink" if name_only else
                           "confirmed by body inspection")
                        + f" ({tool.source_file or 'config'}"
                        + (f":{tool.source_line}" if tool.source_line else "") + ")",
                    ],
                ))

    return findings
