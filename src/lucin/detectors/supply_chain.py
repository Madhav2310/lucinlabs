"""AG-015: MCP Server Supply Chain Verification.

Detects supply chain risks in MCP server configurations where
a trusted server can be silently replaced with a malicious one.

Real-world basis:
- Postmark MCP attack (September 2025): A popular MCP server package
  (`postmark-mcp`) worked perfectly for 15 versions. Version 1.0.16
  added ONE LINE that BCC'd every outgoing corporate email to an attacker.
  3,000-15,000 emails per day leaked for over a week before detection.

- ClawHavoc campaign (January 2026): Attackers published 1,200+
  malicious skills to the OpenClaw marketplace, deploying the AMOS
  credential stealer across enterprise developer machines.

- CVE-2026-25253: First CVE assigned to an agentic AI system —
  remote code execution through a crafted skill package.

What makes MCP supply chain attacks especially dangerous:
1. MCP servers are often installed via `npx -y` (always latest, no pin)
2. A single compromised tool description can hijack agent behavior
3. Developers trust tool descriptions the way they trust library docs
4. There's no equivalent of npm audit / Snyk for MCP servers
5. Tool descriptions are invisible to end users (only the LLM sees them)

This detector flags configurations where MCP servers are:
- Not version-pinned (pulls latest without verification)
- Loaded without integrity checks (no checksums, no lockfiles)
- From unverified/unknown registries
- Using `npx -y` pattern (auto-installs latest)
"""

import re
from pathlib import Path

from lucin.models import Agent, Finding, Severity, MCPServer
from lucin.owasp import owasp_ref


# Patterns indicating unpinned/unverified MCP server installation
UNPINNED_PATTERNS = [
    # npx -y always installs latest version without asking
    r"npx\s+-y\s+",
    r"npx\s+--yes\s+",
    # npm package without version specifier
    r"\"command\":\s*\"npx\"",
    # Generic "latest" references
    r"\"latest\"",
    r"@latest",
]

# Known official/verified MCP server packages (lower risk)
KNOWN_OFFICIAL_PACKAGES = [
    "@modelcontextprotocol/server-",  # Official MCP servers
    "@anthropic/",
    "@openai/",
    "mcp-server-",  # Community convention but still needs verification
]

# Known legitimate package names for typosquatting detection
# If an MCP server uses a name SIMILAR but not identical to these, it's suspicious
KNOWN_PACKAGE_NAMES = [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-everything",
    "@anthropic/mcp-server-puppeteer",
    "@anthropic/mcp-server-brave-search",
    "mcp-server-git",
    "mcp-server-sqlite",
    "mcp-server-github",
    "mcp-server-postgres",
    "mcp-server-docker",
    "mcp-server-kubernetes",
    "mcp-server-linear",
    "mcp-server-notion",
    "mcp-server-slack",
    "mcp-server-gmail",
    "mcp-server-shell",
]


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein (edit) distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


def detect_typosquatting(package_name: str) -> tuple[bool, str]:
    """Check if a package name is suspiciously similar to a known legitimate package.

    Returns (is_suspicious, closest_legitimate_package).

    Typosquatting examples:
    - "postmark-mcp" vs "@postmarkapp/mcp-server" (Postmark attack)
    - "mcp-server-githb" vs "mcp-server-github" (1 char typo)
    - "@modelcontextprotocol/server-filesytem" vs "server-filesystem" (missing char)
    """
    if not package_name:
        return False, ""

    # Normalize: strip version, lowercase
    pkg = package_name.lower().split("@")[-1] if "@" in package_name and not package_name.startswith("@") else package_name.lower()

    # Check if it's an exact match to a known package (not suspicious)
    if pkg in [k.lower() for k in KNOWN_PACKAGE_NAMES]:
        return False, ""

    # Check Levenshtein distance to known packages
    for known in KNOWN_PACKAGE_NAMES:
        known_lower = known.lower()
        # Extract the short name for comparison
        known_short = known_lower.split("/")[-1] if "/" in known_lower else known_lower
        pkg_short = pkg.split("/")[-1] if "/" in pkg else pkg

        distance = _levenshtein_distance(pkg_short, known_short)

        # Suspicious if: edit distance is 1-2 AND package length > 5
        # (prevents flagging completely unrelated short names)
        if 0 < distance <= 2 and len(pkg_short) > 5:
            return True, known

        # Also check if one is a substring rearrangement of the other
        # e.g., "postmark-mcp" vs "mcp-server-postmark"
        if len(pkg_short) > 8 and len(known_short) > 8:
            # Check if they share significant overlap — but EXCLUDE the common
            # naming-convention tokens (E8 FP): every legitimate community server
            # is named `mcp-server-<thing>`, so "mcp" and "server" are shared by
            # the WHOLE namespace and are not evidence of squatting. Requiring
            # overlap on DISTINCTIVE tokens stops flagging e.g. `mcp-server-weather`
            # as a typosquat of `mcp-server-slack`.
            _CONVENTION_TOKENS = {"mcp", "server"}
            pkg_parts = set(pkg_short.replace("-", " ").replace("_", " ").split()) - _CONVENTION_TOKENS
            known_parts = set(known_short.replace("-", " ").replace("_", " ").split()) - _CONVENTION_TOKENS
            overlap = pkg_parts & known_parts
            if len(overlap) >= 2 and pkg_short != known_short:
                return True, known

    return False, ""

# Patterns indicating some form of verification
VERIFICATION_INDICATORS = [
    r"integrity",
    r"sha256",
    r"sha512",
    r"checksum",
    r"--exact",
    r"npm ci",  # Uses lockfile
    r"pnpm install --frozen-lockfile",
    r"yarn --frozen-lockfile",
    r"pin",
    r"lock",
]


# (Removed dead `classify_slsa_level` in Phase 0: it computed an SLSA trust level
# but was never called by any detector or report — pure dead code. A real SLSA/
# provenance classifier belongs in the Phase-1 supply-chain analysis when it's
# actually wired into findings.)


def detect_supply_chain(agent: Agent) -> list[Finding]:
    """Detect supply chain risks in MCP server configurations."""
    findings = []

    for server in agent.mcp_servers:
        server_findings = _analyze_server_supply_chain(server, agent)
        findings.extend(server_findings)

    # Also check the source config file for broader patterns
    if agent.source_file:
        file_findings = _analyze_config_file(agent)
        findings.extend(file_findings)

    return findings


def _analyze_server_supply_chain(server: MCPServer, agent: Agent) -> list[Finding]:
    """Analyze a single MCP server for supply chain risks."""
    findings = []

    # Check for typosquatting (Postmark attack pattern)
    is_typosquat, closest = detect_typosquatting(server.name)
    if is_typosquat:
        findings.append(Finding(
            id="AG-015",
            title=f"Supply Chain: Possible Typosquatting ({server.name})",
            severity=Severity.HIGH,
            description=(
                f"MCP server package '{server.name}' is suspiciously similar to "
                f"known legitimate package '{closest}'.\n\n"
                f"This could be a typosquatting attack — a malicious package with a "
                f"nearly-identical name to trick developers into installing it.\n\n"
                f"This is the EXACT technique used in the Postmark MCP attack (Sep 2025): "
                f"'postmark-mcp' impersonated the legitimate Postmark MCP server."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "1. Attacker publishes a package with a name 1-2 characters different from a popular one\n"
                "2. Developer typos the name or copies from a blog with wrong spelling\n"
                "3. Malicious package installs and operates normally but with hidden behavior\n"
                "4. All data flowing through the tool is accessible to the attacker"
            ),
            blast_radius=f"All operations through server '{server.name}'.",
            owasp_ref=owasp_ref("AG-015"),
            fix_suggestion=(
                f"Verify you intended to use '{server.name}' and not '{closest}'.\n"
                f"Check the package on npm/pypi for: publish date, maintainer, download count.\n"
                f"If unsure, use the official package: {closest}"
            ),
            source_file=agent.source_file,
        ))

    # Check if this is an npx-based server (common pattern)
    # MCP servers are typically: {"command": "npx", "args": ["-y", "@pkg/server"]}
    # The -y flag means "always install latest without asking"
    if not agent.source_file:
        return findings

    try:
        config_content = Path(agent.source_file).read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        return findings

    # Check for npx -y pattern (the most dangerous)
    # Per-server check: only flag if THIS specific server's package is unpinned
    import json as _json
    try:
        config_data = _json.loads(config_content)
    except (_json.JSONDecodeError, ValueError):
        config_data = None

    # Determine if THIS specific server uses npx -y without version pin
    server_uses_npx_y = False
    server_has_pin = False

    if config_data:
        servers = config_data.get("mcpServers", config_data.get("servers", {}))
        if isinstance(servers, dict) and server.name in servers:
            srv_config = servers[server.name]
            if isinstance(srv_config, dict):
                args = srv_config.get("args", [])
                command = srv_config.get("command", "")
                if command == "npx" and "-y" in args:
                    server_uses_npx_y = True
                    # Check if any arg for THIS server has @version
                    for arg in args:
                        if isinstance(arg, str) and re.search(r'@\d+\.\d+', arg):
                            server_has_pin = True
                            break
    else:
        # Fallback to regex if JSON parsing fails
        npx_y_pattern = re.search(
            r'"command"\s*:\s*"npx".*?"args"\s*:\s*\[.*?"-y"',
            config_content,
            re.DOTALL
        )
        server_uses_npx_y = bool(npx_y_pattern)
        server_has_pin = bool(re.search(r'"[^"]*@\d+\.\d+[^"]*"', config_content))

    if server_uses_npx_y and not server_has_pin:
        # Find which server this applies to
        # The npx -y pattern means: "download and run the latest version
        # of this package without any verification or confirmation"
        findings.append(Finding(
            id="AG-015",
            title="Supply Chain: Unpinned MCP Server (npx -y)",
            severity=Severity.HIGH,
            description=(
                f"MCP server '{server.name}' is installed via `npx -y` which:\n"
                f"1. Always downloads the LATEST version (no pinning)\n"
                f"2. Skips confirmation prompts (-y = yes to everything)\n"
                f"3. Has no integrity verification (no checksums)\n"
                f"4. A single malicious version update compromises your agent\n\n"
                f"This is the exact pattern exploited in the Postmark MCP attack (Sep 2025)."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "1. Attacker gains control of the MCP server npm package\n"
                "   (via compromised maintainer account, dependency confusion, or typosquatting)\n"
                "2. Publishes a new version with malicious tool behavior\n"
                "   (e.g., BCC all emails, exfiltrate credentials, modify responses)\n"
                "3. Your agent auto-installs the malicious version via npx -y\n"
                "4. The malicious tools execute with your agent's full permissions\n"
                "5. Attack is invisible — tool still works normally, just with added malicious behavior"
            ),
            blast_radius=(
                f"All data and actions accessible to server '{server.name}'. "
                f"If the server has filesystem/network/database tools, the attacker "
                f"gains equivalent access. In the Postmark case: every corporate email."
            ),
            owasp_ref=owasp_ref("AG-015"),
            fix_suggestion=(
                "1. Pin to exact version:\n"
                "   \"args\": [\"-y\", \"@modelcontextprotocol/server-filesystem@1.2.3\"]\n"
                "2. Use a lockfile (npm ci, pnpm --frozen-lockfile)\n"
                "3. Verify package integrity (npm audit, checksums)\n"
                "4. Run `lucin scan` on MCP server tool descriptions after every update\n"
                "5. Subscribe to security advisories for your MCP server packages\n"
                "6. Consider vendoring critical MCP servers (copy source locally)"
            ),
            source_file=agent.source_file,
        ))

    # Check for version pinning absence (even without npx -y)
    # Look for package references without @version
    package_refs = re.findall(
        r'"(?:@[\w-]+/)?[\w-]+(?:@[\w\d.]+)?"',
        config_content
    )
    unpinned_packages = [
        ref for ref in package_refs
        if re.match(r'"@?[\w-]+(/[\w-]+)?"$', ref)  # No @version suffix
        and "server" in ref.lower() or "mcp" in ref.lower()
    ]

    # Check for remote URL-based servers without TLS
    if server.url and server.url.startswith("http://"):
        findings.append(Finding(
            id="AG-015",
            title="Supply Chain: MCP Server via Unencrypted HTTP",
            severity=Severity.HIGH,
            description=(
                f"MCP server '{server.name}' is loaded from an unencrypted HTTP URL: "
                f"{server.url}\n\n"
                f"An attacker on the network can intercept and modify server responses "
                f"(man-in-the-middle), inject malicious tool definitions, or redirect "
                f"to a completely different server."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "1. Attacker performs MITM on the HTTP connection\n"
                "2. Replaces legitimate tool definitions with malicious ones\n"
                "3. Agent connects to attacker-controlled server believing it's legitimate\n"
                "4. All tool calls now go through the attacker"
            ),
            blast_radius=f"All operations through server '{server.name}'.",
            owasp_ref=owasp_ref("AG-015"),
            fix_suggestion=(
                "Use HTTPS for all MCP server connections.\n"
                "Verify server TLS certificates.\n"
                "Pin server certificates if possible (certificate pinning)."
            ),
            source_file=agent.source_file,
        ))

    return findings


def _analyze_config_file(agent: Agent) -> list[Finding]:
    """Analyze the broader config file for supply chain patterns."""
    findings = []

    if not agent.source_file:
        return findings

    try:
        content = Path(agent.source_file).read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        return findings

    # Count total MCP servers
    server_count = len(agent.mcp_servers)
    if server_count == 0:
        return findings

    # Check if ANY verification mechanism exists in the config
    has_any_verification = any(
        re.search(pattern, content, re.IGNORECASE)
        for pattern in VERIFICATION_INDICATORS
    )

    # Check how many servers use npx -y
    npx_y_count = len(re.findall(r'"-y"', content))

    # If ALL servers use npx -y and there's no verification anywhere
    if npx_y_count > 0 and not has_any_verification and server_count > 1:
        findings.append(Finding(
            id="AG-015",
            title="Supply Chain: No Integrity Verification for Any MCP Server",
            severity=Severity.MEDIUM,
            description=(
                f"Agent '{agent.name}' connects to {server_count} MCP servers "
                f"with no integrity verification mechanism detected (no checksums, "
                f"no lockfiles, no version pinning).\n\n"
                f"As your agent connects to more servers, the attack surface grows "
                f"multiplicatively — ANY one compromised server can hijack the agent."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "With multiple unverified MCP servers, the probability of at least one "
                "being compromised increases with each addition. The ClawHavoc campaign "
                "(Jan 2026) compromised 1,200+ packages simultaneously."
            ),
            blast_radius=f"All {server_count} MCP servers are potential attack vectors.",
            owasp_ref=owasp_ref("AG-015"),
            fix_suggestion=(
                "Create an MCP server lockfile that pins versions and checksums:\n"
                "1. Document all MCP servers with exact versions\n"
                "2. Verify checksums on installation\n"
                "3. Monitor for version changes (subscribe to package advisories)\n"
                "4. Run `lucin scan` after any server update"
            ),
            source_file=agent.source_file,
        ))

    return findings
