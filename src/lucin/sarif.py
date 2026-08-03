"""SARIF 2.1.0 serializer for Lucin findings.

SARIF (Static Analysis Results Interchange Format) is the format GitHub
Code Scanning, GitLab SAST, and most CI/CD pipelines consume natively.
Outputting SARIF means zero integration work for users who already have
code scanning enabled.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
GitHub ingestion: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-github-code-scanning

Pure stdlib — no external dependencies.
"""

import json
from pathlib import Path

from lucin import __version__
from lucin.models import Finding, ScanResult, Severity

_SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

_SEVERITY_TO_SECURITY_SCORE = {
    # SARIF security-severity is a CVSS-like 0-10 float used by GitHub to
    # map findings to "critical/high/medium/low" in the Security tab.
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 2.0,
}


def _make_rule(finding: Finding) -> dict:
    """One SARIF rule descriptor per unique finding ID."""
    return {
        "id": finding.id,
        "name": finding.title.replace(" ", "").replace(":", "").replace("/", ""),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "helpUri": f"https://github.com/Madhav2310/lucinlabs/blob/main/docs/rules/{finding.id}.md",
        "properties": {
            "tags": ["security", "ai-agent", "owasp-agentic"],
            "security-severity": str(_SEVERITY_TO_SECURITY_SCORE[finding.severity]),
        },
        "defaultConfiguration": {
            "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
        },
    }


def _make_result(finding: Finding, cwd: Path) -> dict:
    """One SARIF result per finding instance."""
    result: dict = {
        "ruleId": finding.id,
        "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
        "message": {
            "text": finding.description,
        },
        "properties": {
            "agent": finding.agent_name,
            "severity": finding.severity.value,
            # CWE goes in `tags` because that is where GitHub code scanning and most
            # SARIF consumers actually look for it (`security/cwe/cwe-78` is the
            # convention CodeQL uses), and in a plain `cwe` list for anything that
            # prefers structured data. Without this, every CWE-keyed pipeline is
            # blind to our findings.
            **({"tags": [f"external/cwe/{c.lower()}" for c in finding.cwe],
                "cwe": list(finding.cwe)} if finding.cwe else {}),
        },
    }

    if finding.source_file:
        try:
            rel = str(Path(finding.source_file).relative_to(cwd))
        except ValueError:
            rel = finding.source_file

        location: dict = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": rel,
                    "uriBaseId": "%SRCROOT%",
                },
            }
        }
        if finding.source_line and finding.source_line > 0:
            location["physicalLocation"]["region"] = {
                "startLine": finding.source_line,
            }
        result["locations"] = [location]

    if finding.fix_suggestion:
        # NOT SARIF `fixes`: that field requires a concrete `artifactChanges` /
        # `replacements` patch per the schema, which we don't have — only prose
        # guidance. Claiming a structured fix we can't back up is worse than not
        # having one, so this goes in the message text instead.
        result["message"]["text"] += f"\n\nFix: {finding.fix_suggestion[:1000]}"

    if finding.witness:
        # SARIF: witness chain goes in the message as additional context
        # (relatedLocations requires physical file references we don't always have)
        result["message"]["text"] += (
            "\n\nProof witness:\n" + "\n".join(f"  {w}" for w in finding.witness)
        )

    return result


def to_sarif(scan_result: ScanResult, cwd: Path | None = None) -> dict:
    """Convert a ScanResult to a SARIF 2.1.0 document (dict, not string)."""
    cwd = cwd or Path.cwd()

    # Deduplicate rules by finding ID
    seen_rules: dict[str, dict] = {}
    for f in scan_result.findings:
        if f.id not in seen_rules:
            seen_rules[f.id] = _make_rule(f)

    results = [_make_result(f, cwd) for f in scan_result.findings]

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Lucin",
                        "version": __version__,
                        "informationUri": "https://github.com/Madhav2310/lucinlabs",
                        "rules": list(seen_rules.values()),
                        "properties": {
                            "description": "Static security scanner for AI agents — finds dangerous capability configurations before deployment.",
                        },
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [],
                    }
                ],
                "properties": {
                    "lucin:scanDurationMs": scan_result.scan_duration_ms,
                    "lucin:agentsScanned": len(scan_result.agents),
                },
            }
        ],
    }


def to_sarif_string(scan_result: ScanResult, cwd: Path | None = None) -> str:
    return json.dumps(to_sarif(scan_result, cwd), indent=2, ensure_ascii=False)
