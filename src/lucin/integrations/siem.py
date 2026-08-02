"""SIEM Integration — Output findings in OCSF format for enterprise security tools.

OCSF (Open Cybersecurity Schema Framework) is the standard for security event
data interchange. Supported by: AWS Security Lake, Splunk, IBM QRadar,
Microsoft Sentinel, CrowdStrike, Palo Alto Cortex.

By outputting in OCSF format, Lucin findings can be directly ingested
by ANY enterprise SIEM without custom parsing or transformation.

OCSF Event Class: Security Finding (class_uid: 2001)
Category: Findings (category_uid: 2)

Reference: https://schema.ocsf.io/1.1.0/classes/security_finding
"""

import json
from datetime import datetime, timezone
from typing import Any

from lucin.models import Finding, ScanResult, Severity


# OCSF severity mapping
SEVERITY_TO_OCSF = {
    Severity.CRITICAL: 5,  # Critical
    Severity.HIGH: 4,      # High
    Severity.MEDIUM: 3,    # Medium
    Severity.LOW: 2,       # Low
    Severity.INFO: 1,      # Informational
}

# OCSF severity labels
SEVERITY_LABELS = {
    5: "Critical",
    4: "High",
    3: "Medium",
    2: "Low",
    1: "Informational",
}


def findings_to_ocsf(result: ScanResult) -> list[dict[str, Any]]:
    """Convert Lucin findings to OCSF Security Finding events.

    Each finding becomes one OCSF event that can be ingested by any
    OCSF-compatible SIEM (Splunk, Elastic, Sentinel, etc.).

    Returns:
        List of OCSF-formatted event dictionaries.
    """
    events = []

    for finding in result.findings:
        event = _finding_to_ocsf_event(finding, result.target)
        events.append(event)

    return events


def findings_to_ocsf_ndjson(result: ScanResult) -> str:
    """Convert findings to newline-delimited JSON (NDJSON) in OCSF format.

    This is the most common format for SIEM ingestion pipelines.
    Each line is a complete JSON event.
    """
    events = findings_to_ocsf(result)
    return "\n".join(json.dumps(event) for event in events)


def _finding_to_ocsf_event(finding: Finding, target: str) -> dict[str, Any]:
    """Convert a single Finding to an OCSF Security Finding event.

    OCSF class: Security Finding (2001)
    Reference: https://schema.ocsf.io/1.1.0/classes/security_finding
    """
    now = datetime.now(timezone.utc)
    severity_id = SEVERITY_TO_OCSF.get(finding.severity, 1)

    event = {
        # OCSF base event fields
        "class_uid": 2001,
        "class_name": "Security Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "type_uid": 200101,  # Security Finding: Create
        "type_name": "Security Finding: Create",
        "severity_id": severity_id,
        "severity": SEVERITY_LABELS.get(severity_id, "Unknown"),
        "time": now.isoformat(),
        "message": finding.description,

        # Activity
        "activity_id": 1,  # Create
        "activity_name": "Create",
        "status_id": 1,  # New
        "status": "New",

        # Finding details
        "finding_info": {
            "uid": finding.id,
            "title": finding.title,
            "desc": finding.description,
            "types": [finding.owasp_ref] if finding.owasp_ref else [],
            "created_time": now.isoformat(),
            "modified_time": now.isoformat(),
            "src_url": finding.source_file or "",

            # Remediation
            "remediation": {
                "desc": finding.fix_suggestion or "",
            },

            # Attack details
            "attacks": [
                {
                    "tactic": {
                        "name": finding.owasp_ref or "Unknown",
                    },
                    "technique": {
                        "name": finding.title,
                        "uid": finding.id,
                    },
                }
            ] if finding.owasp_ref else [],

            # Data sources
            "data_sources": [finding.source_file] if finding.source_file else [],
        },

        # Resource (the agent/tool affected)
        "resources": [
            {
                "type": "AI Agent",
                "name": finding.agent_name or "Unknown Agent",
                "uid": finding.agent_name or "",
                "labels": [
                    f"tool:{finding.tool_name}" if finding.tool_name else "",
                    f"file:{finding.source_file}" if finding.source_file else "",
                ],
            }
        ],

        # Metadata
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "Lucin",
                "vendor_name": "Lucin",
                "version": "0.1.0",
            },
            "log_name": "agent_security_scan",
            "logged_time": now.isoformat(),
        },

        # Observables (for correlation)
        "observables": [
            {
                "name": "finding_id",
                "type": "Other",
                "value": finding.id,
            },
            {
                "name": "agent_name",
                "type": "Other",
                "value": finding.agent_name or "",
            },
        ],

        # Lucin-specific extensions
        "unmapped": {
            "lucin.scan_target": target,
            "lucin.blast_radius": finding.blast_radius or "",
            "lucin.attack_scenario": finding.attack_scenario or "",
            "lucin.finding_id": finding.id,
            "lucin.owasp_ref": finding.owasp_ref or "",
        },
    }

    # Add source location if available
    if finding.source_file:
        event["finding_info"]["src_url"] = finding.source_file
        if finding.source_line:
            event["finding_info"]["src_url"] += f":{finding.source_line}"

    return event
