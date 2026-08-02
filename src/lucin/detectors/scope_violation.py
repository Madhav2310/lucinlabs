"""AG-016: Coding Agent File System Scope Violation.
AG-017: Browser Agent Credential Access Patterns.

These detect agent-TYPE-SPECIFIC vulnerabilities that generic detectors miss.

AG-016: Coding agents (Cursor, Claude Code, Devin, Replit Agent) that have
file system access BEYOND their project directory. A coding agent should only
read/write within the project it's working on — accessing ~/.ssh, ~/.aws,
/etc/passwd, or other user directories is a scope violation.

AG-017: Browser agents (Operator, Computer Use, Browserbase) with access to
credential stores, cookies, saved passwords, or autofill data. A browser
agent that can read browser credential stores can steal all saved passwords.

Real-world basis:
- Claude Code DNS rebinding CVE (CVE-2025-66414): allowed access beyond sandbox
- Cursor credential exfiltration (Jul 2025): support ticket injection led to
  credential theft because the agent had access to project secrets
- Browser agent attacks: academic demonstrations of Computer Use agents
  accessing credential stores

The principle: LEAST PRIVILEGE BY SCOPE.
A coding agent's scope is the PROJECT.
A browser agent's scope is the CURRENT TAB/SITE.
Anything beyond that is a violation.
"""

import re
from pathlib import Path

from lucin.models import Agent, Finding, Severity, Tool, ToolCapability


# File paths that indicate scope violation for coding agents
# (accessing files outside a typical project directory)
SENSITIVE_PATHS = [
    # Credentials and keys
    ("~/.ssh", "SSH private keys"),
    ("~/.aws", "AWS credentials"),
    ("~/.gcp", "GCP credentials"),
    ("~/.azure", "Azure credentials"),
    ("~/.config/gcloud", "Google Cloud config"),
    ("~/.kube/config", "Kubernetes config"),
    ("~/.docker/config.json", "Docker registry credentials"),
    ("~/.npmrc", "NPM auth tokens"),
    ("~/.pypirc", "PyPI credentials"),
    ("~/.gitconfig", "Git config (may contain tokens)"),
    ("~/.netrc", "Network credentials"),
    # System files
    ("/etc/passwd", "System user database"),
    ("/etc/shadow", "Password hashes"),
    ("/etc/hosts", "Host configuration"),
    # Environment and shell
    ("~/.bashrc", "Shell configuration (may export secrets)"),
    ("~/.zshrc", "Shell configuration"),
    ("~/.bash_history", "Command history (may contain secrets)"),
    ("~/.env", "Environment variables"),
    # Browser data
    ("~/Library/Application Support/Google/Chrome", "Chrome profile data"),
    ("~/.config/google-chrome", "Chrome profile (Linux)"),
    ("~/Library/Application Support/Firefox", "Firefox profile data"),
    ("~/.mozilla/firefox", "Firefox profile (Linux)"),
    ("~/Library/Keychains", "macOS Keychain"),
]

# Patterns in tool descriptions suggesting broad file access
BROAD_ACCESS_PATTERNS = [
    r"any\s+file",
    r"read\s+(?:any|all)\s+",
    r"access\s+(?:any|all)\s+",
    r"full\s+(?:file\s*)?system",
    r"entire\s+(?:file\s*)?system",
    r"no\s+(?:path\s+)?restrict",
    r"unrestricted\s+(?:file|path|directory)",
    r"/\s*$",  # Root path as argument
]

# Patterns suggesting browser credential store access.
# These must be specific enough to avoid matching normal API/auth docstrings.
# Bad: r"credential" — fires on "API credentials are loaded from env vars"
# Good: require browser context or specific storage path indicators.
BROWSER_CREDENTIAL_PATTERNS = [
    # Browser-specific storage APIs
    r"keychain",
    r"autofill",
    r"saved\s+(?:login|password)",
    r"auth.*cookie",
    r"local\s*storage",
    r"session\s*storage",
    # Specific browser profile/data paths
    r"chrome.*(?:profile|data|password)",
    r"firefox.*(?:profile|data|password)",
    r"safari.*(?:keychain|password)",
    r"browser.*(?:credential|password)\s+(?:store|file|db)",
    r"login\s*data",
    # Explicit password store files
    r"Cookies\s+(?:file|database)",
    r"Login\s+Data",
    r"key\d+\s+(?:file|db)",  # Chrome encryption key files
]


def detect_scope_violations(agent: Agent) -> list[Finding]:
    """Detect agent-type-specific scope violations."""
    findings = []

    # AG-016: Coding agent scope violations
    if _is_coding_agent(agent):
        findings.extend(_check_coding_agent_scope(agent))

    # AG-017: Browser agent credential access
    if _is_browser_agent(agent):
        findings.extend(_check_browser_credential_access(agent))

    # Also check any agent with file system tools for sensitive path access
    findings.extend(_check_sensitive_path_access(agent))

    return findings


def _is_coding_agent(agent: Agent) -> bool:
    """Determine if this is a coding/development agent."""
    coding_indicators = [
        "code", "coding", "developer", "dev", "engineer",
        "cursor", "copilot", "devin", "replit", "aider",
        "windsurf", "codeium",
    ]
    agent_lower = (agent.name + " " + agent.framework).lower()
    return any(ind in agent_lower for ind in coding_indicators)


def _is_browser_agent(agent: Agent) -> bool:
    """Determine if this is a browser/web automation agent."""
    browser_indicators = [
        "browser", "web", "scrape", "selenium", "playwright",
        "puppeteer", "operator", "computer_use", "browserbase",
        "multion",
    ]
    agent_lower = (agent.name + " " + " ".join(t.name for t in agent.tools)).lower()
    return any(ind in agent_lower for ind in browser_indicators)


def _check_coding_agent_scope(agent: Agent) -> list[Finding]:
    """Check if a coding agent has access beyond its project scope."""
    findings = []

    file_tools = [
        t for t in agent.tools
        if ToolCapability.FILE_SYSTEM in t.capabilities
        or ToolCapability.READ_DATA in t.capabilities
    ]

    for tool in file_tools:
        desc_lower = (tool.description + " " + tool.name).lower()

        # Check for broad/unrestricted file access
        for pattern in BROAD_ACCESS_PATTERNS:
            if re.search(pattern, desc_lower):
                findings.append(Finding(
                    id="AG-016",
                    title="Coding Agent: Unrestricted File System Scope",
                    severity=Severity.HIGH,
                    description=(
                        f"Coding agent '{agent.name}' has tool '{tool.name}' with "
                        f"unrestricted file system access. A coding agent should only "
                        f"access files within the project directory it's working on.\n\n"
                        f"Unrestricted access means the agent can read SSH keys, AWS credentials, "
                        f"browser data, and any file on the system."
                    ),
                    agent_name=agent.name,
                    tool_name=tool.name,
                    attack_scenario=(
                        "1. Attacker injects code suggestion or comment containing instructions\n"
                        "2. Coding agent reads ~/.ssh/id_rsa or ~/.aws/credentials\n"
                        "3. Agent includes credential content in its response or a generated file\n"
                        "4. Attacker extracts credentials from the response/commit\n\n"
                        "This is the exact pattern from the Cursor credential exfiltration (Jul 2025)."
                    ),
                    blast_radius="All files accessible to the user running the coding agent.",
                    owasp_ref="A01 - Excessive Agency",
                    fix_suggestion=(
                        "Restrict file tools to the project directory:\n"
                        "  → Set working directory: cwd='/path/to/project'\n"
                        "  → Validate all paths: assert path.resolve().is_relative_to(project_dir)\n"
                        "  → Block access to: ~/.ssh, ~/.aws, ~/.config, /etc/\n"
                        "  → Use a sandbox (Docker, firejail) for file operations"
                    ),
                    source_file=agent.source_file,
                    source_line=tool.source_line,
                ))
                break  # One finding per tool for broad access

    return findings


def _check_browser_credential_access(agent: Agent) -> list[Finding]:
    """Check if a browser agent can access credential stores."""
    findings = []

    for tool in agent.tools:
        combined = (tool.name + " " + tool.description).lower()

        credential_matches = [
            p for p in BROWSER_CREDENTIAL_PATTERNS
            if re.search(p, combined)
        ]

        if credential_matches:
            findings.append(Finding(
                id="AG-017",
                title="Browser Agent: Credential Store Access",
                severity=Severity.CRITICAL,
                description=(
                    f"Browser agent '{agent.name}' has tool '{tool.name}' with "
                    f"potential access to browser credential stores. Matched patterns: "
                    f"{credential_matches[:3]}.\n\n"
                    f"A browser agent with credential access can steal ALL saved "
                    f"passwords, session tokens, and autofill data."
                ),
                agent_name=agent.name,
                tool_name=tool.name,
                attack_scenario=(
                    "1. Browser agent navigates to a malicious page\n"
                    "2. Page content contains indirect prompt injection\n"
                    "3. Agent accesses browser's saved passwords/cookies\n"
                    "4. Credentials exfiltrated to attacker\n\n"
                    "Or: Agent reads autofill data (credit cards, addresses, passwords) "
                    "and includes it in responses."
                ),
                blast_radius="ALL saved credentials in the browser profile.",
                owasp_ref="A04 - Identity & Access Failures",
                fix_suggestion=(
                    "1. Browser agents should NEVER have access to credential stores\n"
                    "2. Use isolated browser profiles with no saved credentials\n"
                    "3. Block access to Chrome/Firefox profile directories\n"
                    "4. Disable autofill and password manager access for agent sessions"
                ),
                source_file=agent.source_file,
                source_line=tool.source_line,
            ))

    return findings


def _check_sensitive_path_access(agent: Agent) -> list[Finding]:
    """Check if any tool's description OR MCP server config mentions sensitive file paths."""
    findings = []

    # Check tool descriptions (existing logic)
    for tool in agent.tools:
        if not tool.description:
            continue

        combined = tool.description + " " + str(tool.parameters)

        for path, description in SENSITIVE_PATHS:
            # Keep the leading slash/tilde — stripping it creates substrings
            # that match inside normal identifiers (e.g. ".env" ⊂ "os.environ").
            path_variants = [path, path.replace("~/", "/home/user/"),
                             path.replace("~/", "/Users/")]
            for variant in path_variants:
                if variant in combined:
                    findings.append(Finding(
                        id="AG-016",
                        title=f"Sensitive Path Referenced: {path}",
                        severity=Severity.HIGH,
                        description=(
                            f"Tool '{tool.name}' references sensitive path '{path}' "
                            f"({description}). This suggests the agent can access "
                            f"credential files or system configuration."
                        ),
                        agent_name=agent.name,
                        tool_name=tool.name,
                        attack_scenario=f"Agent can read {description} at {path}.",
                        blast_radius=f"Contents of {path} ({description}).",
                        owasp_ref="A04 - Identity & Access Failures",
                        fix_suggestion=f"Block access to {path}. Use path allowlisting.",
                        source_file=agent.source_file,
                        source_line=tool.source_line,
                    ))
                    break  # One per path per tool

    # Check MCP filesystem server configured paths
    findings.extend(_check_mcp_filesystem_paths(agent))

    return findings


def _arg_grants_sensitive_path(arg: str, sensitive_path: str) -> bool:
    """Return True if an MCP filesystem-server arg grants access to a sensitive
    path, using PATH-SEGMENT matching instead of a raw substring (E3).

    The old code stripped `~/.ssh` down to the bare token `ssh` and did
    `"ssh" in arg`, which matched incidental substrings inside unrelated
    directory names (`~/.env` → `env` matched `/srv/environment`; `ssh` matched
    `/opt/gssh-cache`). We now match either (a) the arg IS or is UNDER the
    expanded sensitive path, or (b) the sensitive path's segments appear as a
    contiguous run of WHOLE path segments in the arg.
    """
    arg_norm = (arg or "").rstrip("/").replace("\\", "/")
    for form in (sensitive_path,
                 sensitive_path.replace("~/", "/home/user/"),
                 sensitive_path.replace("~/", "/Users/")):
        form_norm = form.rstrip("/")
        if arg_norm == form_norm or arg_norm.startswith(form_norm + "/"):
            return True

    seg = sensitive_path.replace("~/", "").strip("/")
    seg_parts = [p for p in seg.split("/") if p]
    arg_parts = [p for p in arg_norm.split("/") if p]
    if not seg_parts or len(seg_parts) > len(arg_parts):
        return False
    n = len(seg_parts)
    return any(arg_parts[i:i + n] == seg_parts
               for i in range(len(arg_parts) - n + 1))


def _check_mcp_filesystem_paths(agent: Agent) -> list[Finding]:
    """Check MCP filesystem server arguments for sensitive paths.

    Real-world pattern: developers configure MCP filesystem servers with:
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/dev/.ssh", "/"]

    This grants the agent access to SSH keys, AWS credentials, etc.
    """
    findings = []

    if not agent.source_file:
        return findings

    # Read the raw config file to inspect server args
    try:
        import json
        content = Path(agent.source_file).read_text(encoding="utf-8")
        data = json.loads(content)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        return findings

    servers_data = data.get("mcpServers", data.get("servers", {}))
    if not isinstance(servers_data, dict):
        return findings

    for server_name, server_config in servers_data.items():
        if not isinstance(server_config, dict):
            continue

        args = server_config.get("args", [])
        if not isinstance(args, list):
            continue

        # Check if this is a filesystem-related server
        is_filesystem_server = any(
            "filesystem" in str(a).lower() or "server-filesystem" in str(a).lower()
            for a in args
        )
        if not is_filesystem_server:
            continue

        # Check each arg for sensitive paths
        for arg in args:
            if not isinstance(arg, str):
                continue

            # Root filesystem access
            if arg == "/":
                findings.append(Finding(
                    id="AG-016",
                    title="MCP Filesystem Server: Root Access (/)",
                    severity=Severity.CRITICAL,
                    description=(
                        f"MCP filesystem server '{server_name}' is configured with root "
                        f"filesystem access ('/'). This grants the agent access to EVERY file "
                        f"on the system: SSH keys, credentials, system files, all user data."
                    ),
                    agent_name=agent.name,
                    attack_scenario=(
                        "With root filesystem access, a prompt injection can read any file:\n"
                        "1. /etc/shadow (password hashes)\n"
                        "2. ~/.ssh/id_rsa (SSH private keys)\n"
                        "3. ~/.aws/credentials (cloud access keys)\n"
                        "4. /var/lib/docker (container secrets)\n"
                        "5. Any database files, env files, or config with secrets"
                    ),
                    blast_radius="ENTIRE filesystem. All data on the machine.",
                    owasp_ref="A01 - Excessive Agency / A04 - Identity & Access Failures",
                    fix_suggestion=(
                        "Restrict to specific project directories:\n"
                        "  \"args\": [\"-y\", \"@modelcontextprotocol/server-filesystem\", "
                        "\"/Users/dev/projects/myproject\"]\n\n"
                        "NEVER configure filesystem access to '/' or '~'"
                    ),
                    source_file=agent.source_file,
                ))
                continue

            # Check for sensitive path segments
            for sensitive_path, description in SENSITIVE_PATHS:
                if _arg_grants_sensitive_path(arg, sensitive_path):
                    findings.append(Finding(
                        id="AG-016",
                        title=f"MCP Filesystem Server: Access to {sensitive_path}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"MCP filesystem server '{server_name}' is configured with access "
                            f"to '{arg}' which includes {description}.\n\n"
                            f"This means the agent can read/write {description} through "
                            f"the filesystem MCP tools."
                        ),
                        agent_name=agent.name,
                        attack_scenario=(
                            f"A prompt injection could instruct the agent to read files from "
                            f"'{arg}', exposing {description} to the attacker."
                        ),
                        blast_radius=f"All {description} accessible at {arg}.",
                        owasp_ref="A04 - Identity & Access Failures",
                        fix_suggestion=(
                            f"Remove '{arg}' from filesystem server access.\n"
                            f"Only grant access to project-specific directories."
                        ),
                        source_file=agent.source_file,
                    ))
                    break  # One finding per arg per sensitive path

    return findings
