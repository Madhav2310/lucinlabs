"""AG-021: Encoding and Obfuscation Detection in Tool Parameters.

Detects when tool definitions or agent configs contain encoded/obfuscated
content that may be hiding malicious payloads. Attackers use encoding to:

1. Bypass input filters (base64-encoded shell commands)
2. Hide prompt injection in tool descriptions
3. Obfuscate exfiltration URLs
4. Evade human review of configs

Encoding types detected:
- Base64 (aGVsbG8gd29ybGQ=)
- Hex strings (68656c6c6f)
- URL encoding (%68%65%6c%6c%6f)
- Unicode escapes (\\u0068\\u0065\\u006c)
- Zero-width characters (\\u200b, \\u200c, \\ufeff)
- HTML entities (&#104;&#101;&#108;)

Real-world basis:
- Guardrail bypass via base64: documented in multiple prompt injection attacks
- Zero-width injection: arXiv:2607.05744 (Unicode TAG-Block concealment)
- URL encoding bypass: common in web security, now applied to agent inputs
"""

import base64
import math
import re
from collections import Counter

from lucin.models import Agent, Finding, Severity
from lucin.owasp import owasp_ref

# Minimum length for encoded content to be suspicious
MIN_ENCODED_LENGTH = 20

# Base64 pattern (at least 20 chars of valid base64 ending with optional padding)
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

# Hex string pattern (even number of hex chars, at least 20)
HEX_PATTERN = re.compile(r'(?:0x)?([0-9a-fA-F]{20,})')

# URL encoding pattern (3+ consecutive %XX sequences)
URL_ENCODED_PATTERN = re.compile(r'(?:%[0-9a-fA-F]{2}){3,}')

# Unicode escape pattern
UNICODE_ESCAPE_PATTERN = re.compile(r'(?:\\u[0-9a-fA-F]{4}){3,}')

# Zero-width characters
ZERO_WIDTH_CHARS = [
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\ufeff',  # BOM / zero-width no-break space
    '\u2060',  # Word joiner
    '\u2061',  # Function application
    '\u2062',  # Invisible times
    '\u2063',  # Invisible separator
    '\u2064',  # Invisible plus
    '\u180e',  # Mongolian vowel separator
]

# HTML entity pattern
HTML_ENTITY_PATTERN = re.compile(r'(?:&#x?[0-9a-fA-F]+;){3,}')


def detect_encoding_obfuscation(agent: Agent) -> list[Finding]:
    """Detect encoded or obfuscated content in agent tools and configs."""
    findings = []

    for tool in agent.tools:
        # Check tool description
        if tool.description:
            desc_findings = _check_text_for_encoding(
                tool.description, agent.name, tool.name, "tool description",
                agent.source_file, tool.source_line
            )
            findings.extend(desc_findings)

        # Check tool parameters (if stored as string representations)
        params_str = str(tool.parameters)
        if len(params_str) > 50:  # Only check non-trivial params
            param_findings = _check_text_for_encoding(
                params_str, agent.name, tool.name, "tool parameters",
                agent.source_file, tool.source_line
            )
            findings.extend(param_findings)

    if agent.skill:
        for block in agent.skill.instructions:
            findings.extend(_check_text_for_encoding(
                block.text, agent.name, "Skill Instructions", "markdown body",
                block.source_file, block.line_start
            ))

    return findings


def _check_text_for_encoding(
    text: str,
    agent_name: str,
    tool_name: str,
    location: str,
    source_file: str,
    source_line: int = 0,
) -> list[Finding]:
    """Check a text string for various encoding patterns."""
    findings = []

    # Check for zero-width characters (most suspicious — invisible text)
    zero_width_found = [c for c in text if c in ZERO_WIDTH_CHARS]
    if zero_width_found:
        findings.append(Finding(
            id="AG-021",
            title="Zero-Width Characters Detected (Invisible Content)",
            severity=Severity.HIGH,
            description=(
                f"Tool '{tool_name}' {location} contains {len(zero_width_found)} "
                f"zero-width/invisible characters. These can hide instructions "
                f"that are invisible to humans but processed by the LLM."
            ),
            agent_name=agent_name,
            tool_name=tool_name,
            attack_scenario=(
                "Zero-width characters can encode hidden instructions:\n"
                "- Invisible to human reviewers\n"
                "- Processed by LLMs as normal text\n"
                "- Can spell out commands using zero-width encoding\n"
                "Reference: arXiv:2607.05744 (Unicode TAG-Block concealment)"
            ),
            blast_radius="Hidden instructions execute with agent's full permissions.",
            owasp_ref=owasp_ref("AG-021"),
            fix_suggestion=(
                "Strip all zero-width and non-printable characters:\n"
                "  text = ''.join(c for c in text if c.isprintable())"
            ),
            source_file=source_file,
            source_line=source_line,
        ))

    # Check for base64 encoded content
    base64_matches = BASE64_PATTERN.findall(text)
    for match in base64_matches:
        if _is_likely_base64(match):
            # Try to decode and see if it looks like instructions
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if _looks_suspicious(decoded):
                    findings.append(Finding(
                        id="AG-021",
                        title="Base64-Encoded Suspicious Content",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Tool '{tool_name}' {location} contains base64-encoded "
                            f"content that decodes to potentially malicious text: "
                            f"'{decoded[:80]}...'"
                        ),
                        agent_name=agent_name,
                        tool_name=tool_name,
                        attack_scenario=(
                            "Encoded content bypasses text-based input filters. "
                            "If the agent or a downstream system decodes this, "
                            "the hidden instructions execute."
                        ),
                        blast_radius="Depends on decoded content.",
                        owasp_ref=owasp_ref("AG-021"),
                        fix_suggestion="Decode and inspect all base64 content. Block if suspicious.",
                        source_file=source_file,
                        source_line=source_line,
                    ))
            except Exception:
                pass

    # Check for URL encoding
    url_matches = URL_ENCODED_PATTERN.findall(text)
    if url_matches:
        findings.append(Finding(
            id="AG-021",
            title="URL-Encoded Content in Tool Definition",
            severity=Severity.LOW,
            description=(
                f"Tool '{tool_name}' {location} contains URL-encoded sequences. "
                f"While sometimes legitimate, this can be used to hide malicious URLs or commands."
            ),
            agent_name=agent_name,
            tool_name=tool_name,
            attack_scenario="URL encoding can hide malicious endpoints or parameters from review.",
            blast_radius="Depends on decoded content.",
            owasp_ref=owasp_ref("AG-021"),
            fix_suggestion="Decode URL-encoded content and verify it's legitimate.",
            source_file=source_file,
            source_line=source_line,
        ))

    return findings


def _is_likely_base64(text: str) -> bool:
    """Heuristic: is this string likely intentional base64 encoding?

    Excludes common false positives (package names, hashes, etc.)
    """
    if len(text) < 20:
        return False

    # Must have mixed case (pure lowercase/uppercase is likely something else)
    has_upper = any(c.isupper() for c in text)
    has_lower = any(c.islower() for c in text)
    has_digit = any(c.isdigit() for c in text)

    if not (has_upper and has_lower and has_digit):
        return False

    # Check if it's a valid base64 length (multiple of 4, or with padding)
    if len(text) % 4 not in (0, 2, 3):
        return False

    # High entropy suggests encoding (random-looking)
    entropy = _shannon_entropy(text)
    return entropy > 4.5


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_suspicious(decoded_text: str) -> bool:
    """Check if decoded text contains suspicious patterns."""
    suspicious_patterns = [
        "exec", "eval", "import", "subprocess", "os.system",
        "curl", "wget", "http", "bash", "shell",
        "password", "secret", "token", "key",
        "ignore", "override", "instruction",
    ]
    text_lower = decoded_text.lower()
    return any(p in text_lower for p in suspicious_patterns)
