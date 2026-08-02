"""AG-011: Detect tool description injection risks (tool poisoning).

Tool poisoning occurs when a tool's description contains hidden instructions
that manipulate the LLM into performing unintended actions. This is one of the
most dangerous attack vectors because it's invisible to the user and the tool
appears to function normally.

Reference: Invariant Labs MCP Tool Poisoning research (2025-2026)
"""

import re

from lucin.models import Agent, Finding, Severity, Tool


# Patterns that suggest hidden/manipulative instructions in tool descriptions
INJECTION_INDICATORS = [
    # Direct instruction patterns
    r"ignore\s+(?:all\s+)?(?:previous|other|above)",
    r"do\s+not\s+(?:tell|inform|notify|alert)",
    # NOTE: must require a DANGEROUS OBJECT after the verb. The bare
    # "always\s+(include|add|send)" fired on benign documentation like
    # "the owner's email address is always included" (AgentDojo docstrings,
    # caught 2026-07-30) — passive "included" and "always adds a timestamp"
    # are not injections. Require an exfil/secret/covert target to follow.
    r"always\s+(?:include|add|append|send|forward|bcc)\s+"
    r"(?:the\s+|your\s+|a\s+|all\s+|this\s+|these\s+)?"
    r"(?:api[_ ]?key|secret|token|password|credential|copy|following|hidden|"
    r"payload|instruction|to\s+(?:me\b|us\b|https?://|\S+@))",
    r"before\s+(?:responding|answering|replying)",
    r"you\s+must\s+(?:first|always)",
    # Covert-action instruction: an adverb of secrecy immediately governing an
    # action verb ("silently send", "secretly forward the data", "covertly
    # exfiltrate"). The bare adverb alone (e.g. the benign "Secretly this tool
    # does not care about the location" joke in smolagents' demo) is NOT an
    # injection and must not fire — require the directed action to follow.
    r"(?:secretly|silently|quietly|covertly)\s+(?:always\s+|also\s+|then\s+|first\s+)?"
    r"(?:send|forward|copy|include|add|append|email|post|transmit|exfiltrate|"
    r"leak|share|report|route|relay|upload|deliver|redirect|dump|export|collect|"
    r"call|invoke|execute|run|store|save|log|record|attach|bcc|cc|pass)",
    # Data exfiltration instructions hidden in descriptions
    r"(?:append|add|include|send|forward|copy)\s+(?:to|all|the)\s+(?:data|content|result|output)",
    r"(?:bcc|cc|forward)\s+(?:to|all)",
    # Overriding behavior — require behavioral context after "override"
    # Bare "override" is too common in code (method override, config override, etc.)
    r"override\s+(?:the\s+)?(?:system|instructions?|rules?|behavior|restrictions?|filters?)",
    r"disregard\s+(?:the\s+)?(?:above|previous|instructions?|rules?|constraints?)",
    r"regardless\s+of\s+(?:the\s+)?(?:above|instructions?|rules?|what)",
]

# Jailbreak patterns — attempts to override agent identity/behavior
# These are patterns Lakera and Snyk catch that we must also detect
JAILBREAK_INDICATORS = [
    # Identity override
    r"(?:you\s+are|act\s+as|pretend\s+(?:you\s+are|to\s+be))\s+(?:now|a|an)\s+",
    r"from\s+now\s+on\s+you\s+(?:are|will|must)",
    r"(?:new|updated)\s+(?:instructions?|rules?|persona|role)",
    r"(?:enter|switch\s+to|activate)\s+(?:developer|admin|debug|god|sudo)\s+mode",
    r"DAN\s+(?:mode|prompt|jailbreak)",
    # Constraint removal
    r"(?:remove|drop|disable|turn\s+off)\s+(?:all\s+)?(?:restrictions?|limitations?|filters?|guardrails?|safety)",
    r"(?:no\s+)?(?:more\s+)?(?:ethical|moral|safety)\s+(?:constraints?|guidelines?|rules?)",
    r"without\s+(?:any\s+)?(?:restrictions?|limitations?|censorship)",
    # Authority escalation in descriptions
    r"(?:system|admin|root)\s+(?:level|privilege|access|override)",
    r"(?:elevated|maximum|unrestricted)\s+(?:permissions?|access|privileges?)",
]

# Prompt extraction patterns — attempts to steal system prompt / instructions
PROMPT_EXTRACTION_INDICATORS = [
    r"(?:show|display|print|output|reveal|tell\s+me)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|configuration)",
    r"(?:repeat|echo|copy)\s+(?:everything|all\s+text|all\s+instructions?)\s+(?:above|before|from\s+the\s+beginning)",
    r"what\s+(?:are|were)\s+your\s+(?:original\s+)?(?:instructions?|rules?|directives?)",
    r"(?:beginning|start)\s+of\s+(?:your\s+)?(?:prompt|instructions?|conversation)",
    r"(?:verbatim|exactly|word\s+for\s+word)\s+(?:your\s+)?(?:system|initial)\s+(?:prompt|message)",
    r"(?:between|inside)\s+(?:the\s+)?(?:system|first)\s+(?:message|prompt)",
]

# Multi-language injection keywords (top 10 languages by developer population)
# These catch injection attempts in non-English languages that bypass English-only regex
MULTILANG_INJECTION_INDICATORS = [
    # Spanish
    r"ignora\s+(?:las\s+)?instrucciones",
    r"olvida\s+(?:las\s+)?reglas",
    r"ahora\s+eres",
    # French
    r"ignore[rz]?\s+(?:les\s+)?instructions",
    r"oublie[rz]?\s+(?:les\s+)?règles",
    r"tu\s+es\s+maintenant",
    # German
    r"ignorier(?:e|en)?\s+(?:die\s+)?(?:Anweisungen|Regeln)",
    r"vergiss\s+(?:die\s+)?(?:vorherigen|Regeln)",
    r"du\s+bist\s+jetzt",
    # Portuguese
    r"ignor(?:e|ar)\s+(?:as\s+)?instruções",
    r"esqueça\s+(?:as\s+)?regras",
    r"agora\s+você\s+é",
    # Chinese (simplified)
    r"忽略(?:所有)?(?:之前的)?指[令示]",
    r"无视(?:之前的)?(?:指令|规则|限制)",
    r"你现在是",
    r"忘记(?:之前的)?(?:规则|指令)",
    # Japanese
    r"(?:以前の|前の)?指示を無視",
    r"ルールを忘れ",
    r"あなたは今",
    # Arabic
    r"تجاهل\s+(?:جميع\s+)?(?:التعليمات|القواعد)",
    r"أنت\s+الآن",
    # Hindi
    r"(?:पिछले|सभी)\s+निर्देश(?:ों)?\s+(?:को\s+)?(?:अनदेखा|भूल)",
    r"अब\s+(?:तुम|आप)\s+",
    # Korean
    r"(?:이전|모든)\s*지시(?:를|를\s+)?무시",
    r"너는\s+이제",
    # Russian
    r"игнорируй(?:те)?\s+(?:все\s+)?(?:предыдущие\s+)?(?:инструкции|правила)",
    r"забудь(?:те)?\s+(?:все\s+)?правила",
    r"(?:ты|вы)\s+теперь",
]

# Suspicious patterns in tool descriptions (less severe but worth flagging)
SUSPICIOUS_PATTERNS = [
    # Descriptions that are unusually long (may hide instructions)
    # Descriptions containing markdown/formatting that could hide text
    r"\[.*?\]\(.*?\)",  # Markdown links (could hide instructions)
    r"<!--.*?-->",  # HTML comments (hidden text)
    r"\x00",  # Null bytes
    r"[\u200b\u200c\u200d\ufeff]",  # Zero-width characters
]


def _deobfuscate(text: str) -> str:
    """De-obfuscation preprocessing — decode encoded content BEFORE detection.

    Per QFIRE research: attackers encode injection payloads to bypass regex.
    We must decode FIRST, then detect on the decoded text.

    Handles: Base64, hex, URL encoding, zero-width characters, homoglyphs.
    """
    import base64
    import urllib.parse

    result = text

    # 1. Strip zero-width characters (invisible instruction hiding)
    zero_width = '\u200b\u200c\u200d\ufeff\u2060\u2061\u2062\u2063\u2064\u180e'
    result = ''.join(c for c in result if c not in zero_width)

    # 2. Decode URL-encoded sequences (%XX)
    try:
        if '%' in result:
            result = urllib.parse.unquote(result)
    except Exception:
        pass

    # 3. Decode Base64 segments (look for valid base64 blocks)
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    for match in b64_pattern.finditer(result):
        try:
            decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
            if decoded and len(decoded) > 5 and decoded.isprintable():
                # Replace the encoded segment with decoded content for detection
                result = result.replace(match.group(), decoded, 1)
        except Exception:
            pass

    # 4. Normalize homoglyphs (common substitutions)
    homoglyph_map = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',  # Cyrillic
        'ı': 'i', 'ǀ': 'l', 'ⅰ': 'i', 'ⅼ': 'l',  # Latin-like
        '＠': '@', '．': '.', '／': '/',  # Fullwidth
    }
    for fake, real in homoglyph_map.items():
        result = result.replace(fake, real)

    # (Removed in Phase 0: leetspeak digit-folding and vowel-folding normalization.
    # Leetspeak mapped ALL digits (0→o, 3→e, 8→b, ...), corrupting legitimate technical
    # text before the injection regexes ran — "port 8080"→"port bobo", "sha256"→"shazse",
    # "utf-8"→"utf-b" — a false-positive source with little real detection value. Kept:
    # zero-width strip, URL-decode, guarded base64 decode, homoglyph normalization.)

    return result


def detect_tool_poisoning(agent: Agent) -> list[Finding]:
    """Detect potential tool description injection attacks.

    Architecture (per QFIRE research):
    1. De-obfuscate the description (decode encodings)
    2. Run regex patterns on DECODED text
    3. Also check original text for hidden content indicators
    """
    findings = []

    for tool in agent.tools:
        if not tool.description:
            continue

        # PREPROCESSING: De-obfuscate before detection (QFIRE pattern)
        decoded_description = _deobfuscate(tool.description)

        # Check for injection indicators on DECODED text
        injection_matches = []
        for pattern in INJECTION_INDICATORS:
            if re.search(pattern, decoded_description, re.IGNORECASE):
                injection_matches.append(pattern)

        if injection_matches:
            findings.append(Finding(
                id="AG-011",
                title="Tool Description Injection Risk",
                severity=Severity.HIGH,
                description=(
                    f"Tool '{tool.name}' has a description containing patterns "
                    f"consistent with prompt injection. The description may contain "
                    f"hidden instructions that manipulate the agent's behavior."
                ),
                agent_name=agent.name,
                tool_name=tool.name,
                attack_scenario=(
                    "A malicious MCP server or compromised tool registry can modify "
                    "tool descriptions to include hidden instructions. The LLM reads these "
                    "descriptions to decide how to use tools, and will follow injected "
                    "instructions invisibly. This was demonstrated in the Postmark MCP attack (Sep 2025)."
                ),
                blast_radius=(
                    "The injected instructions execute with the agent's full permissions. "
                    "The attack is invisible to the user since tool descriptions are not shown."
                ),
                owasp_ref="A02 - Tool Misuse / Tool Poisoning",
                fix_suggestion=(
                    "1. Pin MCP server versions and verify checksums before connecting\n"
                    "2. Review all tool descriptions manually for hidden instructions\n"
                    "3. Use a tool description sanitizer that strips injection patterns\n"
                    "4. Monitor for tool description changes between versions"
                ),
                source_file=tool.source_file,
                source_line=tool.source_line,
            ))

        # Check for multi-language injection (non-English bypass attempts)
        # NOTE: Use ORIGINAL description, not decoded — homoglyph normalization
        # converts Cyrillic characters to Latin, breaking non-English patterns
        multilang_matches = []
        for pattern in MULTILANG_INJECTION_INDICATORS:
            if re.search(pattern, tool.description, re.IGNORECASE):
                multilang_matches.append(pattern)

        if multilang_matches:
            findings.append(Finding(
                id="AG-011",
                title="Multi-Language Injection in Tool Description",
                severity=Severity.HIGH,
                description=(
                    f"Tool '{tool.name}' contains injection patterns in a non-English "
                    f"language. Attackers use foreign-language instructions to bypass "
                    f"English-only detection filters."
                ),
                agent_name=agent.name,
                tool_name=tool.name,
                attack_scenario=(
                    "Injection in Chinese (忽略指令), Spanish (ignora instrucciones), "
                    "or other languages bypasses English-only regex filters. The LLM "
                    "understands all languages equally, so the injection still works."
                ),
                blast_radius="Same as English injection — full agent behavior override.",
                owasp_ref="A02 - Tool Misuse / Tool Poisoning (Multi-Language)",
                fix_suggestion=(
                    "1. Use language-agnostic injection detection (not just English regex)\n"
                    "2. Restrict tool descriptions to a single language\n"
                    "3. Use ML-based classifier that handles all languages (e.g., PromptGuard 2)"
                ),
                source_file=tool.source_file,
                source_line=tool.source_line,
            ))

        # Check for jailbreak patterns (identity override, constraint removal)
        jailbreak_matches = []
        for pattern in JAILBREAK_INDICATORS:
            if re.search(pattern, decoded_description, re.IGNORECASE):
                jailbreak_matches.append(pattern)

        if jailbreak_matches:
            findings.append(Finding(
                id="AG-011",
                title="Jailbreak Pattern in Tool Description",
                severity=Severity.CRITICAL,
                description=(
                    f"Tool '{tool.name}' description contains jailbreak patterns that "
                    f"attempt to override the agent's identity, remove safety constraints, "
                    f"or escalate privileges. This is a deliberate attack pattern."
                ),
                agent_name=agent.name,
                tool_name=tool.name,
                attack_scenario=(
                    "A malicious tool description attempts to override the agent's core "
                    "behavior by claiming new identity ('you are now...'), removing constraints "
                    "('disable all restrictions'), or escalating authority ('admin mode'). "
                    "The ClawHavoc campaign used this pattern across 1,200+ malicious skills."
                ),
                blast_radius="Complete agent behavior override — all safety guardrails bypassed.",
                owasp_ref="A01 - Excessive Agency / A02 - Tool Misuse",
                fix_suggestion=(
                    "1. Reject tool descriptions containing identity override patterns\n"
                    "2. Implement immutable system prompt (cannot be overridden by tool context)\n"
                    "3. Monitor for jailbreak attempts in tool registration logs\n"
                    "4. Use tool description allowlisting (only pre-approved descriptions)"
                ),
                source_file=tool.source_file,
                source_line=tool.source_line,
            ))

        # Check for prompt extraction patterns
        extraction_matches = []
        for pattern in PROMPT_EXTRACTION_INDICATORS:
            if re.search(pattern, decoded_description, re.IGNORECASE):
                extraction_matches.append(pattern)

        if extraction_matches:
            findings.append(Finding(
                id="AG-011",
                title="Prompt Extraction Attempt in Tool Description",
                severity=Severity.HIGH,
                description=(
                    f"Tool '{tool.name}' description contains patterns attempting to "
                    f"extract the agent's system prompt or instructions. This is a "
                    f"reconnaissance step before more targeted attacks."
                ),
                agent_name=agent.name,
                tool_name=tool.name,
                attack_scenario=(
                    "An attacker first extracts the system prompt to understand the agent's "
                    "capabilities and constraints, then crafts targeted injection attacks. "
                    "Prompt extraction is step 1 of most multi-stage agent attacks."
                ),
                blast_radius="System prompt disclosure enables targeted follow-up attacks.",
                owasp_ref="A02 - Tool Misuse / Information Disclosure",
                fix_suggestion=(
                    "1. Never include the full system prompt in tool descriptions\n"
                    "2. Detect and reject extraction patterns in tool inputs\n"
                    "3. Use instruction hierarchy (system > tool > user) to prevent override"
                ),
                source_file=tool.source_file,
                source_line=tool.source_line,
            ))

        # Check for hidden/invisible content
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, tool.description):
                findings.append(Finding(
                    id="AG-011",
                    title="Suspicious Hidden Content in Tool Description",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Tool '{tool.name}' description contains hidden content "
                        f"(zero-width characters, HTML comments, or markdown that may obscure text)."
                    ),
                    agent_name=agent.name,
                    tool_name=tool.name,
                    attack_scenario=(
                        "Hidden characters or formatting in tool descriptions can be used "
                        "to conceal injected instructions from human reviewers while remaining "
                        "visible to the LLM processing the description."
                    ),
                    blast_radius="Depends on what instructions are hidden.",
                    owasp_ref="A02 - Tool Misuse / Tool Poisoning",
                    fix_suggestion="Strip all non-printable and zero-width characters from tool descriptions.",
                    source_file=tool.source_file,
                    source_line=tool.source_line,
                ))
                break  # One finding per tool for suspicious patterns

        # Check for excessively long descriptions (potential instruction hiding)
        if len(tool.description) > 500:
            findings.append(Finding(
                id="AG-011",
                title="Unusually Long Tool Description",
                severity=Severity.LOW,
                description=(
                    f"Tool '{tool.name}' has a description of {len(tool.description)} characters. "
                    f"Excessively long descriptions may hide injected instructions."
                ),
                agent_name=agent.name,
                tool_name=tool.name,
                attack_scenario="Long descriptions can hide injected content that's not visible during casual review.",
                blast_radius="Unknown without manual review.",
                owasp_ref="A02 - Tool Misuse / Tool Poisoning",
                fix_suggestion="Review and shorten tool descriptions to essential information only.",
                source_file=tool.source_file,
                source_line=tool.source_line,
            ))

    return findings
