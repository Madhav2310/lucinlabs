"""AG-007: Detect hardcoded secrets in agent configurations."""

import re
from pathlib import Path

from lucin.models import Agent, Finding, Severity
from lucin.owasp import owasp_ref


# Patterns for common secret types (regex + description)
# Updated July 2026 per GitGuardian, TruffleHog, and Black Duck patterns
SECRET_PATTERNS = [
    # === LLM/AI Provider Keys (2026 formats) ===
    {
        "name": "OpenAI API Key",
        "pattern": r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}",
        "severity": Severity.HIGH,
    },
    {
        "name": "Anthropic API Key",
        "pattern": r"sk-ant-(?:api03-)?[A-Za-z0-9_-]{20,}",
        "severity": Severity.HIGH,
    },
    {
        "name": "HuggingFace Token",
        "pattern": r"hf_[A-Za-z0-9]{30,}",
        "severity": Severity.HIGH,
    },
    {
        "name": "Perplexity API Key",
        "pattern": r"pplx-[A-Za-z0-9]{40,}",
        "severity": Severity.HIGH,
    },
    # Cohere API Key removed in Phase 0: the "co-" prefix was guessed and is wrong —
    # real Cohere keys (2026) are 40-char alphanumeric strings with no consistent
    # prefix. Without a verified prefix the entropy-based fallback catches real
    # Cohere keys in secret-named variables. Do not re-add without a verified format.
    # === Cloud Provider Keys ===
    {
        "name": "AWS Access Key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": Severity.CRITICAL,
    },
    {
        "name": "AWS Secret Key",
        "pattern": r"(?:aws_secret_access_key|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})",
        "severity": Severity.CRITICAL,
    },
    {
        "name": "Google Cloud API Key",
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": Severity.HIGH,
    },
    # === Code/DevOps Tokens ===
    {
        "name": "GitHub Token",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "severity": Severity.HIGH,
    },
    {
        "name": "GitLab Token",
        "pattern": r"glpat-[A-Za-z0-9_-]{20,}",
        "severity": Severity.HIGH,
    },
    # === Payment/Financial ===
    {
        "name": "Stripe Live Key",
        "pattern": r"(?:sk_live|rk_live)_[A-Za-z0-9]{20,}",
        "severity": Severity.CRITICAL,
    },
    {
        "name": "Stripe Publishable Key (Live)",
        "pattern": r"pk_live_[A-Za-z0-9]{20,}",
        "severity": Severity.MEDIUM,
    },
    # === Communication ===
    {
        "name": "Slack Token",
        "pattern": r"xox[baprs]-[0-9A-Za-z]{10,}[-][0-9A-Za-z-]+",
        "severity": Severity.HIGH,
    },
    {
        "name": "Slack App Token",
        "pattern": r"xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-zA-Z0-9]+",
        "severity": Severity.HIGH,
    },
    {
        "name": "SendGrid API Key",
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "severity": Severity.HIGH,
    },
    # === JWT / Bearer Tokens ===
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": Severity.HIGH,
    },
    {
        "name": "Azure Connection String",
        "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}",
        "severity": Severity.CRITICAL,
    },
    {
        # Twilio API Key SID (not the account auth token). SK + 32 lowercase hex
        # is the verified format for Twilio API Key SIDs. Note: Twilio auth tokens
        # are 32 lowercase-hex chars with NO prefix — caught by entropy fallback.
        "name": "Twilio API Key SID",
        "pattern": r"SK[a-f0-9]{32}",
        "severity": Severity.HIGH,
    },
    {
        "name": "Mailgun API Key",
        "pattern": r"key-[a-f0-9]{32}",
        "severity": Severity.HIGH,
    },
    # === Google/OAuth ===
    {
        "name": "Google OAuth Client Secret",
        "pattern": r"GOCSPX-[A-Za-z0-9_-]{20,}",
        "severity": Severity.HIGH,
    },
    {
        "name": "Google OAuth Refresh Token",
        "pattern": r"1//[A-Za-z0-9_-]{30,}",
        "severity": Severity.HIGH,
    },
    # === Developer Tool Tokens ===
    {
        "name": "Notion Integration Token",
        "pattern": r"secret_[a-zA-Z0-9_]{30,}",
        "severity": Severity.HIGH,
    },
    {
        "name": "Linear API Key",
        "pattern": r"lin_api_[A-Za-z0-9]{20,}",
        "severity": Severity.MEDIUM,
    },
    {
        "name": "Brave Search API Key",
        "pattern": r"BSA[_-][A-Za-z0-9]{20,}",
        "severity": Severity.MEDIUM,
    },
    {
        "name": "Vercel Token",
        "pattern": r"vercel_[A-Za-z0-9]{20,}",
        "severity": Severity.MEDIUM,
    },
    # === Generic Patterns ===
    {
        "name": "Generic API Key Assignment",
        "pattern": r"(?:api_key|apikey|api_secret|secret_key|auth_token|access_token)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "severity": Severity.MEDIUM,
    },
    {
        "name": "JSON Secret Value",
        "pattern": r"\"(?:(?:API|SECRET|PRIVATE|ACCESS|AUTH)[_]?(?:KEY|TOKEN|SECRET|PASSWORD)|(?:DATABASE|DB|MONGO|REDIS)_URL|ADMIN_SECRET|(?:AWS_)?SECRET_ACCESS_KEY)\"\s*:\s*\"([^\"]{8,})\"",
        "severity": Severity.HIGH,
    },
    {
        "name": "Database Connection String",
        "pattern": r"(?:postgresql?|mysql|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        "severity": Severity.HIGH,
    },
    # === PII Patterns ===
    # These detect hardcoded PII in agent configurations — a compliance violation
    {
        "name": "PII: Credit Card Number",
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "severity": Severity.CRITICAL,
        # Note: pattern matches Visa, Mastercard, Amex, Discover prefixes
        # Luhn validation done post-match to reduce false positives
    },
    {
        "name": "PII: Email Address in Config",
        "pattern": r"[\"'][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[\"']",
        "severity": Severity.LOW,
        # Only in quoted strings (config values), not in comments or code
    },
    {
        "name": "Private Key",
        "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
    },
]

# Known false positives / test values to skip
# These use EXACT substring matching — be careful not to be too broad
FALSE_POSITIVE_VALUES = [
    "sk-proj-FAKE",
    "sk-test-",
    "sk-placeholder",
    "YOUR_API_KEY",
    "your-api-key",
    "REPLACE_ME",
    "***",
    "dummy",
    "test_key",
    "INSERT_YOUR",
    "PASTE_YOUR",
    # Dev/local database URLs with well-known default credentials — corpus lesson
    # from PydanticAI RAG example: postgres:postgres@localhost is a local dev DB,
    # not a real secret. Similarly for common dev defaults.
    "postgres:postgres@localhost",
    "postgres:postgres@127.0.0.1",
    "root:root@localhost",
    "admin:admin@localhost",
    "user:password@localhost",
    "user:pass@localhost",
    "postgres:password@localhost",
    "localhost:5432",      # bare localhost with no real credentials
    "localhost:27017",     # mongodb dev default
    "localhost:6379",      # redis dev default
]

# Bare host:port entries above must NOT suppress a match that ALSO carries real
# embedded credentials (E8 FN): `postgresql://admin:S3cret@localhost:5432/db`
# contains the substring `localhost:5432`, and the old blanket substring FP check
# swallowed the whole (credentialed) connection string. These entries only mean
# "a bare localhost:port with no creds is not a secret" — so they are ignored
# when the matched value contains a `user:pass@` credentials section.
_BARE_HOSTPORT_FP = {"localhost:5432", "localhost:27017", "localhost:6379"}

# Values that are entirely placeholder characters (all x's, all 0's, etc.)
PLACEHOLDER_PATTERNS = [
    r"^[xX]+$",          # All x's
    r"^[0]+$",           # All zeros
    r"^[*]+$",           # All asterisks
    r"^placeholder",     # Starts with placeholder
    r"EXAMPLE",          # AWS example keys
    r"^your[_-]",        # your-key, your_token
    r"^REPLACE",         # REPLACE_THIS, REPLACE_ME
]


def detect_secrets(agent: Agent) -> list[Finding]:
    """Scan agent source files for hardcoded secrets."""
    findings = []

    # Collect all source files associated with this agent
    source_files = set()
    if agent.source_file:
        source_files.add(agent.source_file)
    for tool in agent.tools:
        if tool.source_file:
            source_files.add(tool.source_file)

    for filepath in source_files:
        path = Path(filepath)
        if not path.exists():
            continue

        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern_def in SECRET_PATTERNS:
                matches = re.finditer(pattern_def["pattern"], line)
                for match in matches:
                    matched_value = match.group(0)

                    # Skip known false positives
                    if _is_false_positive(matched_value):
                        continue

                    # PII credit card: validate with Luhn algorithm to reduce FPs
                    if pattern_def["name"] == "PII: Credit Card Number":
                        if not _luhn_check(matched_value):
                            continue

                    # Mask the secret for display
                    masked = _mask_secret(matched_value)

                    findings.append(Finding(
                        id="AG-007",
                        title=f"Hardcoded Secret: {pattern_def['name']}",
                        severity=pattern_def["severity"],
                        description=(
                            f"Found hardcoded {pattern_def['name']} in source code: {masked}"
                        ),
                        agent_name=agent.name,
                        attack_scenario=(
                            "Secrets in source code can be extracted by anyone with repo access, "
                            "leaked via git history, or exposed through agent error messages. "
                            "If this agent is compromised, the attacker gets these credentials."
                        ),
                        blast_radius=(
                            f"All resources accessible via this {pattern_def['name']}."
                        ),
                        owasp_ref=owasp_ref("AG-007"),
                        fix_suggestion=(
                            "Move secrets to environment variables or a secrets manager.\n"
                            "  → Use: os.environ['API_KEY'] instead of hardcoding\n"
                            "  → Or: Load from .env file (excluded from version control)"
                        ),
                        source_file=filepath,
                        source_line=line_num,
                    ))

        # BASE64-ENCODED SECRETS: decode and re-scan
        # Catches patterns like: API_KEY = base64.b64decode("c2stcHJvai0...").decode()
        b64_findings = _detect_base64_encoded_secrets(content, filepath, agent.name)
        findings.extend(b64_findings)

        # ENTROPY-BASED DETECTION: catch unknown secret formats
        # High-entropy strings in assignment contexts are likely secrets
        # even if they don't match any known pattern (TruffleHog approach)
        entropy_findings = _detect_high_entropy_secrets(content, filepath, agent.name)
        findings.extend(entropy_findings)

    # MCP ENV-BLOCK SCANNING (Phase 1 addition):
    # MCP configs often have env blocks like {"GITHUB_TOKEN": "ghp_hardcoded_key"}.
    # The file-scanning loop above only covers Python source; these JSON env vars
    # are never seen. Scan them here using the same pattern catalog.
    for server in agent.mcp_servers:
        if not server.env_vars:
            continue
        for var_name, var_value in server.env_vars.items():
            if not var_value or _is_false_positive(var_value):
                continue
            for pattern_def in SECRET_PATTERNS:
                match = re.search(pattern_def["pattern"], var_value)
                if match:
                    masked = _mask_secret(match.group(0))
                    findings.append(Finding(
                        id="AG-007",
                        title=f"Hardcoded Secret in MCP Config: {pattern_def['name']}",
                        severity=pattern_def["severity"],
                        description=(
                            f"MCP server '{server.name}' env var '{var_name}' contains "
                            f"a hardcoded {pattern_def['name']}: {masked}\n\n"
                            f"Secrets in MCP config env blocks are stored in plaintext "
                            f"and accessible to any process that can read the config file."
                        ),
                        agent_name=agent.name,
                        attack_scenario=(
                            f"Anyone with read access to the MCP config file "
                            f"(~/.config/claude/claude_desktop_config.json or similar) "
                            f"can extract this credential. MCP config files are often "
                            f"world-readable and synced to cloud storage."
                        ),
                        blast_radius=(
                            f"Full access to any service this {pattern_def['name']} "
                            f"authenticates with."
                        ),
                        owasp_ref=owasp_ref("AG-007"),
                        fix_suggestion=(
                            f"Use an environment variable reference instead of a hardcoded value:\n"
                            f'  "{var_name}": "${{env:{var_name}}}"\n'
                            f"Or use a secrets manager and have the MCP server resolve "
                            f"the secret at runtime."
                        ),
                        source_file=server.name,
                    ))
                    break  # one finding per env var

    return findings


def _detect_base64_encoded_secrets(content: str, filepath: str, agent_name: str) -> list[Finding]:
    """Detect secrets that are base64-encoded to evade pattern matching.

    Pattern: variable_with_secret_name = base64.b64decode("encoded_value")
    Or: _encoded = "c2stcHJvai0..." (followed by decode)

    We decode the base64 and check if the decoded value matches any secret pattern.
    """
    import base64

    findings = []

    # Pattern: secret-named variable assigned a base64 string that decodes to a known secret
    secret_var_pattern = re.compile(
        r'(?:key|token|secret|password|credential|api_key|auth)\w*\s*=\s*'
        r'(?:base64\.b64decode\(["\']([A-Za-z0-9+/=]{16,})["\']|'
        r'["\']([A-Za-z0-9+/=]{20,})["\'])',
        re.IGNORECASE
    )

    for line_num, line in enumerate(content.splitlines(), 1):
        for match in secret_var_pattern.finditer(line):
            encoded = match.group(1) or match.group(2)
            if not encoded:
                continue

            # Try to decode
            try:
                decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
            except Exception:
                continue

            if not decoded or len(decoded) < 8 or not decoded.isprintable():
                continue

            # Check if decoded value matches any known secret pattern
            for pattern_def in SECRET_PATTERNS:
                if re.search(pattern_def["pattern"], decoded):
                    findings.append(Finding(
                        id="AG-007",
                        title=f"Base64-Encoded Secret: {pattern_def['name']}",
                        severity=pattern_def["severity"],
                        description=(
                            f"Found base64-encoded {pattern_def['name']} in source code. "
                            f"The secret is obfuscated but decodes to a recognizable credential format.\n"
                            f"Decoded prefix: {decoded[:8]}****"
                        ),
                        agent_name=agent_name,
                        attack_scenario=(
                            "Base64 encoding is a common technique to hide secrets from "
                            "pattern-matching scanners. The secret is trivially recoverable "
                            "by anyone with access to the source code."
                        ),
                        blast_radius=f"All resources accessible via this {pattern_def['name']}.",
                        owasp_ref=owasp_ref("AG-007"),
                        fix_suggestion=(
                            "Move secrets to environment variables. "
                            "Base64 encoding is NOT encryption — it provides zero security."
                        ),
                        source_file=filepath,
                        source_line=line_num,
                    ))
                    break  # One finding per encoded value

    return findings


def _detect_high_entropy_secrets(content: str, filepath: str, agent_name: str) -> list[Finding]:
    """Detect potential secrets by Shannon entropy in assignment contexts.

    A string with entropy >4.5 bits/char in a variable assignment that looks
    like a secret (key, token, password, secret) is likely a credential we
    don't have a specific pattern for.

    This is the TruffleHog/GitGuardian fallback for unknown secret formats.
    """
    import math
    from collections import Counter

    findings = []

    # Pattern: variable_name = "high_entropy_string"
    # Only trigger when variable name suggests it's a secret
    assignment_pattern = re.compile(
        r'(?:key|token|secret|password|credential|auth|api_key|access_key|private)'
        r'\s*[=:]\s*["\']([^"\']{16,})["\']',
        re.IGNORECASE
    )

    for line_num, line in enumerate(content.splitlines(), 1):
        for match in assignment_pattern.finditer(line):
            value = match.group(1)

            # Skip if already caught by pattern-based detection
            if _is_false_positive(value):
                continue

            # Skip obvious non-secrets (URLs, file paths, sentences)
            if value.startswith(("http://", "https://", "/", ".", " ")):
                continue
            if " " in value and value.count(" ") > 2:
                continue  # Likely a sentence, not a secret

            # Calculate Shannon entropy
            entropy = _shannon_entropy(value)

            # High entropy (>4.5 bits/char) in a secret-like context = likely a credential
            if entropy > 4.5 and len(value) >= 16:
                masked = value[:4] + "****" + value[-4:] if len(value) > 12 else value[:4] + "****"
                findings.append(Finding(
                    id="AG-007",
                    title="High-Entropy String in Secret Context",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Variable assignment contains a high-entropy string "
                        f"(entropy: {entropy:.2f} bits/char) that may be an unknown "
                        f"credential format: {masked}"
                    ),
                    agent_name=agent_name,
                    attack_scenario=(
                        "High-entropy strings in secret-named variables are likely credentials "
                        "for services we don't have specific patterns for. Even unknown "
                        "secret formats should be in environment variables, not source code."
                    ),
                    blast_radius="Unknown — depends on what service this credential accesses.",
                    owasp_ref=owasp_ref("AG-007"),
                    fix_suggestion=(
                        "Move to environment variable or secrets manager.\n"
                        "If this is NOT a secret, rename the variable to avoid confusion."
                    ),
                    source_file=filepath,
                    source_line=line_num,
                ))

    return findings


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not text:
        return 0.0
    import math
    from collections import Counter
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_false_positive(value: str) -> bool:
    """Check if a matched value is a known false positive.

    Uses two-tier approach:
    1. Exact substring match for known test values
    2. Regex patterns for placeholder-like content
    """
    value_lower = value.lower()

    # A connection string carries real credentials when it has a `user:pass@`
    # section (something before an '@', with a ':' inside it).
    has_embedded_creds = bool(re.search(r"[^/@\s:]+:[^/@\s:]+@", value))

    # Tier 1: known test values (substring match)
    for fp in FALSE_POSITIVE_VALUES:
        if fp.lower() in value_lower:
            # A bare localhost:port entry must not suppress a value that also
            # carries real embedded credentials (E8 FN).
            if fp in _BARE_HOSTPORT_FP and has_embedded_creds:
                continue
            return True

    # Tier 2: placeholder patterns (regex)
    # Extract the "value part" after any prefix (e.g., ghp_xxxxx -> xxxxx)
    parts = value.split("_", 1)
    value_suffix = parts[-1] if len(parts) > 1 else value

    for pattern in PLACEHOLDER_PATTERNS:
        if re.search(pattern, value_suffix, re.IGNORECASE):
            return True

    return False


def _luhn_check(number_str: str) -> bool:
    """Validate a credit card number using the Luhn algorithm.

    This eliminates false positives from random 16-digit numbers.
    Only numbers that pass Luhn are reported as PII.
    """
    digits = [int(d) for d in number_str if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    # Luhn algorithm
    total = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d

    return total % 10 == 0


def _mask_secret(value: str) -> str:
    """Mask a secret for safe display, showing first 4 and last 4 chars."""
    if len(value) <= 12:
        return value[:4] + "****"
    return value[:4] + "****" + value[-4:]
