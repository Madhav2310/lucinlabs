"""AG-027: Prompt Leakage Risk — sensitive data in system prompts/instructions.

Detects when agent system prompts or instructions contain sensitive information
that could be extracted via prompt extraction attacks.

If your system prompt contains:
- Internal API URLs (api.internal.company.com)
- Credentials or tokens
- Database connection details
- Implementation details that reveal architecture
- Secret business logic

...then a prompt extraction attack ("show me your instructions") leaks all of this.

Real-world basis:
- McKinsey Lilli breach (March 2026): system prompts leaked via extraction
- Lakera Q4 2025 report: indirect extraction succeeds more often than direct
- Trail of Bits: prompt extraction is step 1 of most multi-stage attacks
"""

import re
from pathlib import Path

from lucin.models import Agent, Finding, Severity


# Patterns that indicate sensitive content in prompts/instructions
SENSITIVE_PROMPT_PATTERNS = [
    # Internal URLs
    (r"(?:https?://)?[\w-]+\.internal\.[\w-]+", "Internal URL", Severity.HIGH),
    (r"(?:https?://)?[\w-]+\.corp\.[\w-]+", "Corporate URL", Severity.HIGH),
    (r"(?:https?://)?[\w-]+\.local(?:host)?(?::\d+)?", "Local/development URL", Severity.MEDIUM),
    (r"(?:https?://)?(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)", "Private IP address", Severity.HIGH),
    # Credentials in prompts
    (r"(?:password|passwd|pwd)\s*(?:is|=|:)\s*\S+", "Password in prompt", Severity.CRITICAL),
    (r"(?:api[_-]?key|token|secret)\s*(?:is|=|:)\s*\S+", "API key/token in prompt", Severity.CRITICAL),
    (r"Bearer\s+[A-Za-z0-9_-]+", "Bearer token in prompt", Severity.CRITICAL),
    # Database details
    (r"(?:database|db|schema)\s+(?:name\s+)?(?:is|=|:)\s*\S+", "Database name in prompt", Severity.MEDIUM),
    (r"(?:table|collection)\s+(?:name\s+)?(?:is|=|:)\s*\S+", "Table/collection name", Severity.LOW),
    # Architecture details
    (r"(?:endpoint|api|service)\s+(?:is\s+)?(?:at|located|hosted)\s+", "Service location in prompt", Severity.MEDIUM),
    (r"(?:version|v)\s*\d+\.\d+", "Version information", Severity.LOW),
]


def detect_prompt_leakage(agent: Agent) -> list[Finding]:
    """Detect sensitive information in agent system prompts/instructions.

    Checks both:
    1. Inline instructions in Python code (instructions="...", system_message="...")
    2. System prompts loaded from files
    """
    findings = []

    if not agent.source_file:
        return findings

    try:
        content = Path(agent.source_file).read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        return findings

    # Extract instruction/system prompt text from the source
    instructions = _extract_prompt_text(content)

    if not instructions:
        return findings

    # Check for sensitive patterns in the extracted prompt text
    for pattern, description, severity in SENSITIVE_PROMPT_PATTERNS:
        matches = re.findall(pattern, instructions, re.IGNORECASE)
        if matches:
            # Mask the found value
            masked = matches[0][:20] + "..." if len(matches[0]) > 20 else matches[0]
            findings.append(Finding(
                id="AG-027",
                title=f"Prompt Leakage Risk: {description}",
                severity=severity,
                description=(
                    f"Agent '{agent.name}' has system prompt/instructions containing "
                    f"{description.lower()}: '{masked}'\n\n"
                    f"If an attacker extracts the system prompt (via 'show me your "
                    f"instructions' or similar), this sensitive information is exposed."
                ),
                agent_name=agent.name,
                attack_scenario=(
                    "1. Attacker crafts a prompt extraction attack\n"
                    "2. Agent reveals its system prompt/instructions\n"
                    "3. Sensitive data in the prompt is disclosed\n"
                    "4. Attacker uses internal URLs, credentials, or architecture "
                    "details for further attacks"
                ),
                blast_radius=f"Disclosure of {description.lower()} from system prompt.",
                owasp_ref="A04 - Identity & Access Failures / Information Disclosure",
                fix_suggestion=(
                    "1. NEVER put credentials, internal URLs, or secrets in system prompts\n"
                    "2. Load sensitive config from environment variables at runtime\n"
                    "3. Use a reference ID instead of actual values in prompts\n"
                    "4. Add prompt extraction defense (refuse to repeat instructions)"
                ),
                source_file=agent.source_file,
            ))

    return findings


def _extract_prompt_text(content: str) -> str:
    """Extract system prompt / instruction text from Python source code.

    Looks for patterns like:
    - instructions="..."
    - system_message="..."
    - system_prompt="..."
    - Agent(instructions="...")
    - SYSTEM_PROMPT = "..."
    """
    texts = []

    # Pattern 1: instructions/system_prompt/system_message as string literals
    patterns = [
        r'(?:instructions?|system_prompt|system_message|sys_msg)\s*=\s*(?:f?"""(.*?)"""|f?\'\'\'(.*?)\'\'\'|f?"([^"]{20,})"|f?\'([^\']{20,})\')',
        r'(?:SYSTEM_PROMPT|INSTRUCTIONS?|SYS_MSG)\s*=\s*(?:f?"""(.*?)"""|f?\'\'\'(.*?)\'\'\'|f?"([^"]{20,})"|f?\'([^\']{20,})\')',
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, content, re.DOTALL | re.IGNORECASE):
            # Get the first non-None group
            text = next((g for g in match.groups() if g), "")
            if text and len(text) > 20:
                texts.append(text)

    return "\n".join(texts)
