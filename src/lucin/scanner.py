"""Core scanning orchestrator."""

import time
import warnings
from pathlib import Path

from lucin.detectors import ACTIVE_DETECTOR_COUNT, run_all_detectors
from lucin.models import ScanMetadata, ScanResult
from lucin.parsers import detect_and_parse


def _active_detector_count() -> int:
    """Number of detectors that actually run (H4: derived, not hardcoded)."""
    return ACTIVE_DETECTOR_COUNT


def _active_secret_pattern_count() -> int:
    """Number of live secret-detection patterns (H4: derived from the catalog)."""
    from lucin.detectors.secrets import SECRET_PATTERNS
    return len(SECRET_PATTERNS)


def _active_injection_pattern_count() -> int:
    """Number of live tool-poisoning / injection regexes (H4: derived)."""
    from lucin.detectors import tool_poisoning as _tp
    return (len(_tp.INJECTION_INDICATORS)
            + len(_tp.JAILBREAK_INDICATORS)
            + len(_tp.PROMPT_EXTRACTION_INDICATORS)
            + len(_tp.MULTILANG_INJECTION_INDICATORS)
            + len(_tp.SUSPICIOUS_PATTERNS))


def scan_target(target: Path, framework: str = "auto", detections: bool = True) -> ScanResult:
    """Scan a target path for agent definitions and security issues.

    Crash-isolated (E1): parse-unit and per-detector failures are collected as
    diagnostics rather than aborting the scan, so one malformed file can never
    zero out recall on an otherwise-scannable repo.
    """
    start = time.time()

    diagnostics: list[str] = []

    # Suppress warnings raised by parsing the TARGET's code. `ast.parse` emits
    # SyntaxWarning for things like an invalid `\.` escape, so scanning a repo that
    # has one printed Python's warning to our stderr — noise about someone else's
    # code, in the middle of our report, from a tool whose whole pitch is signal.
    # Suppressed here, at the single entry point, rather than at each of the 8+
    # parse sites: a future parser cannot reintroduce it.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        warnings.simplefilter("ignore", DeprecationWarning)

        # Step 1: Parse agent definitions (per-parser crash isolation)
        agents = detect_and_parse(target, framework, diagnostics=diagnostics)

        # Step 2: Run detectors (if enabled; per-detector crash isolation)
        findings = []
        if detections:
            findings = run_all_detectors(agents, diagnostics=diagnostics)

    elapsed_ms = (time.time() - start) * 1000

    # Step 3: Build metadata (transparency counts derived from the LIVE registry,
    # H4 — never a hardcoded number that silently drifts from what actually runs).
    frameworks_detected = list(set(a.framework for a in agents))
    metadata = ScanMetadata(
        frameworks_detected=frameworks_detected,
        parsers_used=len(frameworks_detected),
        detection_rules_active=_active_detector_count(),
        secret_patterns_active=_active_secret_pattern_count(),
        injection_patterns_active=_active_injection_pattern_count(),
        diagnostics=diagnostics,
    )

    # Step 4: Check for binary/archive payloads in skill directories.
    # Only when agent definitions were actually found — a directory with zero
    # parseable agents is not a "skill directory", and scanning it for binaries
    # produced field false-positives (e.g. a project's compiled dependencies).
    if target.is_dir() and agents:
        binary_findings = _detect_binary_payloads(target)
        findings.extend(binary_findings)

    result = ScanResult(
        target=str(target),
        agents=agents,
        findings=findings,
        scan_duration_ms=elapsed_ms,
        metadata=metadata,
    )

    return result


def _detect_binary_payloads(directory: Path) -> list:
    """Detect binary/archive files that may contain malicious payloads.

    Skill directories should only contain text files (Python, YAML, JSON, MD).
    Binary files (.zip, .tar, .exe, .dll, .so, .whl) are suspicious —
    they could contain malware that the skill installs.

    This is the Trail of Bits finding: malicious skills hide payloads in
    binary formats that text-based scanners can't inspect.
    """
    from lucin._fs import iter_files
    from lucin.models import Finding, Severity

    # Genuinely-binary payload formats only. Shell/batch/PowerShell scripts
    # (.sh/.bat/.cmd/.ps1) are TEXT — they are not "binary payloads a text
    # scanner cannot inspect" and flagging them here was a false-positive class.
    SUSPICIOUS_EXTENSIONS = {
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",  # Archives
        ".exe", ".dll", ".so", ".dylib",  # Executables
        ".whl", ".egg",  # Python packages (could contain compiled code)
        ".bin", ".dat",  # Generic binary
    }

    findings = []
    # iter_files() prunes vendored/build dirs (venv, node_modules, site-packages,
    # *.dist-info, dist, build, __pycache__ ...) so a project's own dependencies
    # are never mistaken for a malicious skill payload.
    for file in iter_files(directory, "*"):
        if file.is_file() and file.suffix.lower() in SUSPICIOUS_EXTENSIONS:
            findings.append(Finding(
                id="AG-015",
                title=f"Binary Payload in Skill Directory: {file.name}",
                severity=Severity.HIGH,
                description=(
                    f"Found binary/archive file '{file.name}' in agent directory. "
                    f"Skill directories should only contain text files (Python, YAML, JSON). "
                    f"Binary files may contain malicious executables or obfuscated payloads "
                    f"that text-based scanners cannot inspect.\n\n"
                    f"The ClawHavoc campaign delivered AMOS stealer via password-protected "
                    f"ZIP files hidden in skill directories."
                ),
                agent_name="",
                attack_scenario=(
                    "1. Attacker publishes a skill with a binary payload (.zip, .exe, .sh)\n"
                    "2. Skill's install script extracts and runs the binary\n"
                    "3. Binary contains malware (credential stealer, backdoor, etc.)\n"
                    "4. Text-based scanners miss it because they can't parse binary content"
                ),
                blast_radius="Full system compromise if binary is executed.",
                owasp_ref="A08 - Supply Chain Attacks",
                fix_suggestion=(
                    "1. Remove binary files from skill directories\n"
                    "2. If the binary is needed, verify its checksum against a known-good hash\n"
                    "3. Scan binary content with antivirus/VirusTotal before allowing\n"
                    "4. Never auto-execute binaries from untrusted skill packages"
                ),
                source_file=str(file),
            ))

    return findings


def scan_multiple_targets(targets: list[Path], framework: str = "auto") -> ScanResult:
    """Scan multiple targets and merge results.

    Useful for CI/CD scanning multiple agent configs:
        lucin scan agents/ mcp_configs/ tools/

    Returns a single merged ScanResult with all findings.
    """
    import time as _time
    start = _time.time()

    all_agents = []
    all_findings = []
    all_frameworks = set()

    for target in targets:
        if not target.exists():
            continue
        result = scan_target(target, framework)
        all_agents.extend(result.agents)
        all_findings.extend(result.findings)
        all_frameworks.update(result.metadata.frameworks_detected)

    elapsed = (_time.time() - start) * 1000

    return ScanResult(
        target=", ".join(str(t) for t in targets),
        agents=all_agents,
        findings=all_findings,
        scan_duration_ms=elapsed,
        metadata=ScanMetadata(
            frameworks_detected=sorted(all_frameworks),
            parsers_used=len(all_frameworks),
            detection_rules_active=_active_detector_count(),
            secret_patterns_active=_active_secret_pattern_count(),
            injection_patterns_active=_active_injection_pattern_count(),
        ),
    )


def get_top_recommendations(result: ScanResult, max_count: int = 3) -> list[str]:
    """Generate top actionable recommendations from scan results.

    Returns the N most impactful things the user should fix first,
    prioritized by severity and attack surface reduction.
    """
    if not result.findings:
        return ["No security issues found. Your agent configuration looks good."]

    recommendations = []

    # Priority 1: Critical findings (fix these immediately)
    criticals = [f for f in result.findings if f.severity.value == "critical"]
    if criticals:
        # Group by type
        critical_types = set(f.id for f in criticals)
        if "AG-001" in critical_types:
            recommendations.append(
                "CRITICAL: Sandbox or restrict shell/code execution tools. "
                "Use Docker containers or argument allowlists to prevent arbitrary command execution."
            )
        if "AG-002" in critical_types or "AG-COMP" in critical_types:
            recommendations.append(
                "CRITICAL: Break the data exfiltration path. Separate read-capable tools "
                "from network-capable tools into different agents, or add DLP boundaries."
            )
        if "AG-007" in critical_types:
            recommendations.append(
                "CRITICAL: Remove hardcoded credentials. Move all secrets to environment "
                "variables or a secrets manager (Vault, AWS Secrets Manager, etc.)."
            )
        if "AG-026" in critical_types:
            recommendations.append(
                "CRITICAL: Enable container isolation for code execution. "
                "Set use_docker=True or use sandboxed execution environments."
            )

    # Priority 2: High findings
    highs = [f for f in result.findings if f.severity.value == "high"]
    if highs and len(recommendations) < max_count:
        high_types = set(f.id for f in highs)
        if "AG-015" in high_types:
            recommendations.append(
                "HIGH: Pin MCP server versions. Replace `npx -y package` with "
                "`npx -y package@1.2.3` for every server to prevent supply chain attacks."
            )
        if "AG-006" in high_types and len(recommendations) < max_count:
            recommendations.append(
                "HIGH: Add human-in-the-loop for destructive operations. "
                "Use interrupt_before (LangGraph) or HumanApprovalCallbackHandler (LangChain)."
            )
        if "AG-016" in high_types and len(recommendations) < max_count:
            recommendations.append(
                "HIGH: Restrict filesystem access to project directories only. "
                "Remove access to ~/.ssh, ~/.aws, and other sensitive paths."
            )

    # Priority 3: Structural improvements
    if len(recommendations) < max_count:
        if any(f.id == "AG-010" for f in result.findings):
            recommendations.append(
                "Add rate limiting to high-risk tools (max N calls per minute). "
                "This would have triggered earlier detection of the HuggingFace breach (17K actions)."
            )

    return recommendations[:max_count]
