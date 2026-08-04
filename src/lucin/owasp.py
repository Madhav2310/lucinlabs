"""OWASP Top 10 for Agentic Applications (2026) mapping.

Source: OWASP GenAI Security Project, announced 2025-12-09.
https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/

One mapping table, so a rule cannot cite a category that does not exist.
"""

ASI = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

# rule id -> (primary, *secondary)
RULE_TO_ASI: dict[str, tuple[str, ...]] = {
    "AG-001":             ("ASI05", "ASI02"),
    "AG-002":             ("ASI02", "ASI01"),
    "AG-003":             ("ASI03",),
    "AG-005a":            ("ASI02",),
    "AG-005b":            ("ASI02",),
    "AG-006":             ("ASI09",),
    "AG-007":             ("ASI03",),
    "AG-009":             ("ASI08",),
    "AG-010":             ("ASI08",),
    "AG-011":             ("ASI01", "ASI02"),
    "AG-012":             ("ASI07",),
    "AG-013":             ("ASI06",),
    "AG-014":             ("ASI08", "ASI07"),
    "AG-015":             ("ASI04",),
    "AG-016":             ("ASI03",),
    "AG-017":             ("ASI03",),
    "AG-019":             ("ASI06",),
    "AG-021":             ("ASI01",),
    "AG-023":             ("ASI10",),
    "AG-024":             ("ASI07", "ASI03"),
    "AG-025":             ("ASI02",),
    "AG-026":             ("ASI05",),
    "AG-027":             ("ASI01", "ASI03"),
    "AG-028":             ("ASI10",),
    "AG-COMP":            ("ASI02",),
    "AG-CORS":            ("ASI03",),
    "AG-DESERIALIZE":     ("ASI05",),
    "AG-DOCKER-EXEC":     ("ASI05",),
    "AG-ENV-FALLBACK":    ("ASI03",),
    "AG-FRAMEWORK-PIN":   ("ASI04",),
    "AG-MCP-TOKENLEAK":   ("ASI03",),
    "AG-NOAUTH":          ("ASI03",),
    "AG-PATH-TRAVERSAL":  ("ASI02",),
    "AG-RAG-NO-SANITIZE": ("ASI06",),
    "AG-SQL":             ("ASI05", "ASI02"),
    "AG-SSRF":            ("ASI02",),
    "AG-TRIFECTA":        ("ASI01", "ASI02"),
    "AG-SKILL-CHAIN":     ("ASI02", "ASI05"),
    "AG-SKILL-EXTERNAL-INSTRUCTIONS": ("ASI05",),
    "AG-SKILL-MANIFEST-GAP": ("ASI04",),
}


def owasp_ref(rule_id: str) -> str:
    """Render the OWASP Agentic reference for a rule, e.g. 'ASI01 Agent Goal Hijack · ASI02 Tool Misuse & Exploitation'."""
    codes = RULE_TO_ASI.get(rule_id)
    if not codes:
        return ""
    return " · ".join(f"{c} {ASI[c]}" for c in codes)
