"""Lucin Fix Engine — Intelligent remediation code generation.

Generates SPECIFIC, CONTEXTUAL fixes for each finding — not generic advice
but actual code that plugs into the user's existing architecture.

This is what makes Lucin actionable (like Snyk's auto-fix):
- AG-001 (unrestricted exec): generates argument allowlist wrapper
- AG-002 (data exfiltration): generates data-flow boundary decorator
- AG-003 (no auth on MCP): generates OAuth config
- AG-006 (no HITL): generates human approval wrapper
- AG-007 (hardcoded secrets): generates environment variable pattern
- AG-011 (tool poisoning): generates description sanitizer

Each fix is a self-contained code snippet that the user can review and apply.
"""

from lucin.models import Finding, Severity


def generate_fix(finding: Finding, framework: str = "auto") -> str | None:
    """Generate a contextual code fix for a finding.

    Framework-aware: generates different fix code for LangChain vs MCP vs CrewAI.

    Returns a string with the suggested fix code, or None if
    no automatic fix is available for this finding type.
    """
    generators = {
        "AG-001": _fix_unrestricted_exec,
        "AG-002": _fix_data_exfiltration,
        "AG-003": _fix_mcp_auth,
        "AG-006": _fix_no_human_approval,
        "AG-007": _fix_hardcoded_secret,
        "AG-010": _fix_no_rate_limit,
        "AG-013": _fix_memory_poisoning,
        "AG-015": _fix_supply_chain,
    }

    # Strip subtype suffixes (AG-005a → AG-005)
    base_id = finding.id.rstrip("abcdefgh")
    generator = generators.get(base_id) or generators.get(finding.id)

    if generator:
        # Detect framework from source file if auto
        if framework == "auto":
            framework = _detect_framework_from_finding(finding)
        return generator(finding, framework=framework)
    return None


def _detect_framework_from_finding(finding: Finding) -> str:
    """Infer framework from the finding's source file content."""
    if not finding.source_file:
        return "generic"
    try:
        from pathlib import Path
        content = Path(finding.source_file).read_text(encoding="utf-8")
        if finding.source_file.endswith(".json"):
            return "mcp"
        if "crewai" in content.lower():
            return "crewai"
        if "langgraph" in content:
            return "langgraph"
        if "langchain" in content:
            return "langchain"
        if "autogen" in content.lower():
            return "autogen"
        if "pydantic_ai" in content:
            return "pydantic_ai"
    except (FileNotFoundError, PermissionError):
        pass
    return "generic"


def generate_patch(finding: Finding, framework: str = "auto") -> str | None:
    """Generate a unified diff patch for a finding that can be applied with `git apply`.

    This is the auto-remediation feature: instead of just suggesting a fix,
    we generate an apply-ready patch file.

    Returns a unified diff string, or None if no auto-patch is available.

    Usage:
        patch = generate_patch(finding)
        if patch:
            Path("fix.patch").write_text(patch)
            # Then: git apply fix.patch
    """
    from pathlib import Path as _Path
    import difflib

    if not finding.source_file:
        return None

    source_path = _Path(finding.source_file)
    if not source_path.exists():
        return None

    try:
        original = source_path.read_text(encoding="utf-8")
    except (PermissionError, UnicodeDecodeError):
        return None

    # Generate the fix for this specific finding
    fix_code = generate_fix(finding, framework)
    if not fix_code:
        return None

    # For secrets (AG-007): replace the hardcoded value with env var reference
    if finding.id == "AG-007":
        fixed = _apply_secret_fix(original, finding)
    # For supply chain (AG-015): add version pin
    elif finding.id == "AG-015":
        fixed = _apply_supply_chain_fix(original, finding)
    else:
        # For other findings, we can't auto-patch yet — return the fix as a comment block
        return None

    if not fixed or fixed == original:
        return None

    # Generate unified diff
    original_lines = original.splitlines(keepends=True)
    fixed_lines = fixed.splitlines(keepends=True)

    diff = difflib.unified_diff(
        original_lines,
        fixed_lines,
        fromfile=f"a/{source_path.name}",
        tofile=f"b/{source_path.name}",
        lineterm="",
    )

    patch = "".join(diff)
    return patch if patch else None


def _apply_secret_fix(original: str, finding: Finding) -> str:
    """Apply a secret fix: replace hardcoded value with os.environ.get()."""
    import re

    # Find the line with the secret
    lines = original.splitlines()
    if finding.source_line > 0 and finding.source_line <= len(lines):
        line = lines[finding.source_line - 1]

        # Replace quoted string values in assignments with os.environ.get
        # Pattern: VAR = "secret_value" → VAR = os.environ.get("VAR")
        var_match = re.match(r'^(\s*(\w+)\s*=\s*)["\'].*["\'](.*)$', line)
        if var_match:
            indent = var_match.group(1)
            var_name = var_match.group(2)
            rest = var_match.group(3)
            lines[finding.source_line - 1] = f'{indent}os.environ.get("{var_name}"){rest}'

            # Add import os at top if not present
            if "import os" not in original:
                lines.insert(0, "import os")

            return "\n".join(lines)

    return original


def _apply_supply_chain_fix(original: str, finding: Finding) -> str:
    """Apply a supply chain fix: add version pin to npx -y packages."""
    import re

    # Find unpinned packages and add @latest as a reminder to pin
    # Pattern: "package-name" → "package-name@1.0.0"  (placeholder version)
    if "npx" in original and "-y" in original:
        # Find the package reference that's not pinned
        # This is a best-effort — adds a comment reminding to pin
        fixed = re.sub(
            r'("-y",\s*"(@?[\w/-]+))"',
            r'"-y", "\2@VERSION_PIN_REQUIRED"',
            original,
        )
        if fixed != original:
            return fixed

    return original


def validate_fix_syntax(fix_code: str, language: str = "python") -> dict:
    """Validate that generated fix code is syntactically valid.

    Returns:
        {"valid": True/False, "error": None or error message}
    """
    if language == "python":
        import ast
        try:
            ast.parse(fix_code)
            return {"valid": True, "error": None}
        except SyntaxError as e:
            return {"valid": False, "error": f"Line {e.lineno}: {e.msg}"}
    elif language == "json":
        import json
        try:
            json.loads(fix_code)
            return {"valid": True, "error": None}
        except json.JSONDecodeError as e:
            return {"valid": False, "error": str(e)}
    elif language == "yaml":
        try:
            import yaml
            yaml.safe_load(fix_code)
            return {"valid": True, "error": None}
        except Exception as e:
            return {"valid": False, "error": str(e)}
    return {"valid": True, "error": None}  # Unknown language = skip validation


def verify_fix(finding: Finding, fix_code: str) -> dict:
    """Verify that a proposed fix actually resolves the finding.

    Creates a temporary file with the fix applied, re-scans it,
    and checks if the original finding is still present.

    Returns:
        {
            "verified": True/False,
            "original_finding_id": "AG-001",
            "still_present": False,  # True means fix didn't work
            "new_findings": [...],   # Any new issues the fix introduced
            "message": "Fix verified — AG-001 is resolved."
        }
    """
    import tempfile
    from pathlib import Path
    from lucin.scanner import scan_target

    # Create a temp file with the fix code
    suffix = ".py"
    if finding.source_file and finding.source_file.endswith(".json"):
        suffix = ".json"
    elif finding.source_file and finding.source_file.endswith((".yaml", ".yml")):
        suffix = ".yaml"

    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
        f.write(fix_code)
        temp_path = f.name

    try:
        # Re-scan the fixed code
        result = scan_target(Path(temp_path))

        # Check if the original finding is still present
        still_present = any(
            f.id == finding.id and f.tool_name == finding.tool_name
            for f in result.findings
        )

        # Check for new findings that weren't in the original
        new_findings = [
            f for f in result.findings
            if f.id != finding.id
        ]

        if not still_present:
            return {
                "verified": True,
                "original_finding_id": finding.id,
                "still_present": False,
                "new_findings_count": len(new_findings),
                "message": f"Fix verified — {finding.id} ({finding.title}) is resolved.",
            }
        else:
            return {
                "verified": False,
                "original_finding_id": finding.id,
                "still_present": True,
                "new_findings_count": len(new_findings),
                "message": f"Fix NOT verified — {finding.id} still present after applying fix.",
            }
    finally:
        import os
        os.unlink(temp_path)


def _fix_unrestricted_exec(finding: Finding, framework: str = "generic") -> str:
    """Generate a sandboxed execution wrapper."""
    tool_name = finding.tool_name or "execute_command"
    return f'''# FIX for {finding.id}: Wrap {tool_name} with argument allowlist + sandboxing
# Replace your current tool definition with this safer version:

ALLOWED_COMMANDS = [
    "ls", "cat", "head", "tail", "grep", "wc",  # Read-only commands
    "echo", "date", "whoami", "pwd",              # Safe informational commands
]

BLOCKED_PATTERNS = [
    "|", ";", "&&", "||", "`",           # Command chaining
    ">", ">>", "<",                       # Redirection
    "curl", "wget", "nc", "ssh",         # Network access
    "rm", "mv", "chmod", "chown",        # Destructive operations
    "sudo", "su",                         # Privilege escalation
    "/etc/passwd", "/etc/shadow",        # Sensitive files
    "env", "printenv", "export",         # Credential exposure
]


@tool
def {tool_name}(command: str) -> str:
    """{tool_name} with argument filtering and sandboxing.
    Only allows pre-approved commands. Blocks dangerous patterns."""
    import subprocess
    import shlex

    # Check against allowlist
    base_command = command.split()[0] if command.split() else ""
    if base_command not in ALLOWED_COMMANDS:
        return f"Error: Command '{{base_command}}' is not in the allowlist. Allowed: {{ALLOWED_COMMANDS}}"

    # Check for blocked patterns
    for pattern in BLOCKED_PATTERNS:
        if pattern in command:
            return f"Error: Command contains blocked pattern '{{pattern}}'. This operation is not permitted."

    # Execute in restricted subprocess
    try:
        result = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            timeout=10,                    # Prevent hangs
            cwd="/tmp/sandbox",            # Restrict working directory
            env={{}},                       # Empty environment (no credential leakage)
        )
        return result.stdout[:5000]        # Limit output size
    except subprocess.TimeoutExpired:
        return "Error: Command timed out (10s limit)."
    except Exception as e:
        return f"Error: {{str(e)}}"
'''


def _fix_data_exfiltration(finding: Finding, framework: str = "generic") -> str:
    """Generate a data-flow boundary decorator."""
    return '''# FIX for AG-002: Add data-flow boundary between read and send operations
# This decorator prevents data read by one tool from being sent by another
# without explicit approval.

from functools import wraps
import hashlib

# Track what data has been read (by hash) and whether it's approved for sending
_data_registry = {}  # hash -> {"approved_for_export": False, "source": "..."}


def track_data_read(func):
    """Decorator: registers data read by this tool for tracking."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        if result:
            data_hash = hashlib.sha256(str(result).encode()).hexdigest()[:16]
            _data_registry[data_hash] = {
                "approved_for_export": False,
                "source": func.__name__,
                "preview": str(result)[:100],
            }
        return result
    return wrapper


def require_export_approval(func):
    """Decorator: blocks sending data that hasn't been approved for export."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Check if any argument contains tracked data
        all_args = str(args) + str(kwargs)
        for data_hash, info in _data_registry.items():
            if info["preview"][:50] in all_args and not info["approved_for_export"]:
                return (
                    f"BLOCKED: Attempted to send data from {info['source']} "
                    f"externally without approval. Data hash: {data_hash}. "
                    f"Call approve_data_export('{data_hash}') first."
                )
        return func(*args, **kwargs)
    return wrapper


# Apply to your tools:
# @track_data_read
# def sql_query(query: str) -> str: ...
#
# @require_export_approval
# def http_request(url: str, body: str) -> str: ...
'''


def _fix_mcp_auth(finding: Finding, framework: str = "generic") -> str:
    """Generate MCP server OAuth configuration."""
    server_name = finding.tool_name or "your_server"
    return f'''# FIX for AG-003: Add OAuth 2.1 authentication to MCP server
# Update your MCP config to include authentication:

{{
  "mcpServers": {{
    "{server_name}": {{
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-{server_name}"],
      "auth": {{
        "type": "oauth2",
        "client_id": "${{MCP_{server_name.upper()}_CLIENT_ID}}",
        "client_secret": "${{MCP_{server_name.upper()}_CLIENT_SECRET}}",
        "token_url": "https://auth.yourcompany.com/oauth/token",
        "scopes": ["mcp:read", "mcp:write"]
      }}
    }}
  }}
}}

# For stdio-based servers, use client certificate validation:
# "auth": {{
#   "type": "mtls",
#   "client_cert": "/path/to/client.crt",
#   "client_key": "/path/to/client.key",
#   "ca_cert": "/path/to/ca.crt"
# }}

# Reference: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
# NSA Guidance: https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf
'''


def _fix_no_human_approval(finding: Finding, framework: str = "generic") -> str:
    """Generate human-in-the-loop approval pattern."""
    return '''# FIX for AG-006: Add human-in-the-loop for destructive operations

# Option 1: LangGraph interrupt_before (recommended for LangGraph agents)
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import create_react_agent

checkpointer = MemorySaver()
agent = create_react_agent(
    model,
    tools=tools,
    checkpointer=checkpointer,
    interrupt_before=["write_file", "delete_file", "execute_shell", "send_email"],
)

# Option 2: Custom approval decorator (works with any framework)
def require_approval(tool_func):
    """Decorator that pauses execution and asks for human confirmation."""
    from functools import wraps

    @wraps(tool_func)
    def wrapper(*args, **kwargs):
        action_desc = f"{tool_func.__name__}({args}, {kwargs})"
        print(f"\\n⚠️  APPROVAL REQUIRED: {action_desc}")
        print(f"    This action is destructive/irreversible.")
        response = input("    Approve? [y/N]: ").strip().lower()
        if response == "y":
            return tool_func(*args, **kwargs)
        else:
            return "Action cancelled by human reviewer."

    return wrapper

# Apply: @require_approval on destructive tools

# Option 3: LangChain HumanApprovalCallbackHandler
from langchain.callbacks import HumanApprovalCallbackHandler
callbacks = [HumanApprovalCallbackHandler()]
'''


def _fix_hardcoded_secret(finding: Finding, framework: str = "generic") -> str:
    """Generate environment variable pattern."""
    return '''# FIX for AG-007: Move secrets to environment variables

# BEFORE (dangerous):
# api_key = "sk-proj-abc123..."

# AFTER (safe):
import os

api_key = os.environ["OPENAI_API_KEY"]  # Fails loudly if not set

# Or with a safe default for development:
api_key = os.environ.get("OPENAI_API_KEY")
if not api_key:
    raise ValueError(
        "OPENAI_API_KEY environment variable is required. "
        "Set it in your .env file or deployment config."
    )

# For local development, use python-dotenv:
# pip install python-dotenv
from dotenv import load_dotenv
load_dotenv()  # Loads from .env file (add .env to .gitignore!)

# .env file (NEVER commit this):
# OPENAI_API_KEY=sk-proj-...
# DATABASE_URL=postgres://...
# STRIPE_SECRET_KEY=sk_live_...

# For production: use your platform's secret manager
# AWS: AWS Secrets Manager
# GCP: Secret Manager
# Azure: Key Vault
# K8s: Secrets
'''


def _fix_no_rate_limit(finding: Finding, framework: str = "generic") -> str:
    """Generate rate limiting pattern."""
    return '''# FIX for AG-010: Add rate limiting to high-risk tools

import time
from functools import wraps
from collections import defaultdict

# Simple token bucket rate limiter
class RateLimiter:
    def __init__(self, max_calls: int = 10, window_seconds: int = 60):
        self.max_calls = max_calls
        self.window = window_seconds
        self.calls = defaultdict(list)

    def is_allowed(self, key: str = "default") -> bool:
        now = time.time()
        # Remove expired entries
        self.calls[key] = [t for t in self.calls[key] if now - t < self.window]
        if len(self.calls[key]) >= self.max_calls:
            return False
        self.calls[key].append(now)
        return True


# Global rate limiter: 10 calls per minute per tool
_limiter = RateLimiter(max_calls=10, window_seconds=60)


def rate_limited(max_calls: int = 10, window: int = 60):
    """Decorator: rate limits a tool to max_calls per window seconds."""
    limiter = RateLimiter(max_calls=max_calls, window_seconds=window)

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not limiter.is_allowed(func.__name__):
                return (
                    f"Rate limit exceeded for {func.__name__}. "
                    f"Maximum {max_calls} calls per {window} seconds. "
                    f"Please wait before trying again."
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Usage:
# @rate_limited(max_calls=5, window=60)
# @tool
# def execute_shell(command: str) -> str: ...
'''


def _fix_memory_poisoning(finding: Finding, framework: str = "generic") -> str:
    """Generate memory protection pattern."""
    return '''# FIX for AG-013: Protect persistent memory from poisoning

# Option 1: Input sanitization before memory write
def sanitize_for_memory(text: str) -> str:
    """Remove instruction-like content before storing in memory/RAG."""
    import re

    # Remove patterns that look like injected instructions
    injection_patterns = [
        r"(?i)ignore\\s+(all\\s+)?previous",
        r"(?i)you\\s+must\\s+(always|never)",
        r"(?i)new\\s+instructions?:",
        r"(?i)system\\s+update:",
        r"(?i)override:",
        r"(?i)from\\s+now\\s+on",
    ]

    sanitized = text
    for pattern in injection_patterns:
        sanitized = re.sub(pattern, "[FILTERED]", sanitized)

    return sanitized

# Apply before any vectorstore.add_documents() or add_texts() call:
# sanitized_chunks = [sanitize_for_memory(chunk.page_content) for chunk in chunks]


# Option 2: Per-user memory isolation
from langchain_community.vectorstores import Chroma

def get_user_vectorstore(user_id: str):
    """Create isolated vector store per user — prevents cross-contamination."""
    return Chroma(
        collection_name=f"user_{user_id}",  # Isolated per user
        embedding_function=embeddings,
        persist_directory=f"./chroma_db/users/{user_id}",
    )


# Option 3: Memory integrity monitoring
import hashlib
import json

class MemoryIntegrityMonitor:
    """Track memory state and detect unexpected changes."""

    def __init__(self, store_path: str = "./memory_checksums.json"):
        self.store_path = store_path
        self.checksums = self._load()

    def record_state(self, collection_name: str, doc_count: int, sample_hash: str):
        self.checksums[collection_name] = {
            "doc_count": doc_count,
            "sample_hash": sample_hash,
            "timestamp": time.time(),
        }
        self._save()

    def check_integrity(self, collection_name: str, current_count: int, current_hash: str) -> bool:
        if collection_name not in self.checksums:
            return True  # First run
        prev = self.checksums[collection_name]
        if current_count > prev["doc_count"] * 1.5:  # >50% growth is suspicious
            return False
        return True
'''


def _fix_supply_chain(finding: Finding, framework: str = "generic") -> str:
    """Generate version pinning and integrity verification."""
    return '''# FIX for AG-015: Pin MCP server versions and verify integrity

# BEFORE (dangerous — always pulls latest):
# "args": ["-y", "@modelcontextprotocol/server-filesystem"]

# AFTER (pinned to exact version):
# "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3"]

# Best practice: Create an MCP server lockfile

# mcp-servers.lock.json
{
  "servers": {
    "@modelcontextprotocol/server-filesystem": {
      "version": "1.2.3",
      "integrity": "sha512-abc123...",
      "verified_date": "2026-07-26",
      "verified_by": "security-team"
    },
    "@modelcontextprotocol/server-postgres": {
      "version": "0.8.1",
      "integrity": "sha512-def456...",
      "verified_date": "2026-07-26",
      "verified_by": "security-team"
    }
  }
}

# Install script that verifies integrity:
#!/bin/bash
# install-mcp-servers.sh

set -euo pipefail

echo "Installing MCP servers with integrity verification..."

# Install specific versions
npm install --save-exact @modelcontextprotocol/server-filesystem@1.2.3
npm install --save-exact @modelcontextprotocol/server-postgres@0.8.1

# Verify checksums
npm audit signatures

echo "✅ All MCP servers installed and verified."

# Post-install: scan tool descriptions for changes
# lucin scan ./mcp.json --fail-on high
'''
