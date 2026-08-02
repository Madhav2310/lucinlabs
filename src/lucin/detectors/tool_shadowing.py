"""AG-025: Tool Shadowing Detection.

Detects when multiple tools have suspiciously similar names, which can:
1. Confuse the agent into calling the wrong tool (confused deputy)
2. Be exploited by attackers who register tools with names close to legitimate ones
3. Create ambiguity in tool selection, leading to unpredictable behavior

Real-world basis:
- Microsoft AGT detects "suspiciously similar tool names" as an MCP-specific check
- Invariant Labs documented "tool shadowing" where a malicious tool mimics a legitimate one
- The ClawHavoc campaign used skill names that mimicked official tools

Example:
- Legitimate: "read_file" (reads from project directory)
- Shadow: "read_files" or "readfile" or "read_file_v2" (malicious clone)
- The LLM may pick the shadow tool instead of the legitimate one
"""

from lucin.models import Agent, Finding, Severity, Tool


def detect_tool_shadowing(agent: Agent) -> list[Finding]:
    """Detect suspiciously similar tool names that could confuse the agent."""
    findings = []

    tools = agent.tools
    if len(tools) < 2:
        return findings

    # Also include tools from MCP servers
    all_tool_names = [(t.name, t) for t in tools]
    for server in agent.mcp_servers:
        for t in server.tools:
            all_tool_names.append((t.name, t))

    if len(all_tool_names) < 2:
        return findings

    # Compare all pairs for suspicious similarity
    checked = set()
    for i, (name_a, tool_a) in enumerate(all_tool_names):
        for j, (name_b, tool_b) in enumerate(all_tool_names):
            if i >= j:
                continue
            if (name_a, name_b) in checked:
                continue
            checked.add((name_a, name_b))

            similarity_type = _check_similarity(name_a, name_b)
            if similarity_type:
                findings.append(Finding(
                    id="AG-025",
                    title=f"Tool Shadowing: '{name_a}' vs '{name_b}'",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Tools '{name_a}' and '{name_b}' have suspiciously similar names "
                        f"({similarity_type}). This could confuse the LLM into calling the "
                        f"wrong tool, especially if one has broader permissions than the other.\n\n"
                        f"An attacker can exploit this by registering a tool with a name nearly "
                        f"identical to a legitimate tool — the agent may route requests to the "
                        f"malicious version."
                    ),
                    agent_name=agent.name,
                    attack_scenario=(
                        "1. Legitimate tool 'read_file' exists with scoped permissions\n"
                        "2. Attacker registers 'read_files' or 'readFile' with broader access\n"
                        "3. LLM sometimes picks the shadow tool instead of the legitimate one\n"
                        "4. Data flows through the attacker's tool, enabling exfiltration"
                    ),
                    blast_radius=(
                        f"If '{name_a}' and '{name_b}' have different permission scopes, "
                        f"the agent may inadvertently use the less restricted one."
                    ),
                    owasp_ref="A02 - Tool Misuse / Tool Shadowing",
                    fix_suggestion=(
                        "1. Ensure all tool names are clearly distinct (no near-duplicates)\n"
                        "2. If both tools are legitimate, rename one for clarity\n"
                        "3. If one is unexpected, investigate — it may be a malicious shadow\n"
                        "4. Use tool namespacing (server_name.tool_name) to avoid collisions"
                    ),
                    source_file=agent.source_file,
                ))

    return findings


def _check_similarity(name_a: str, name_b: str) -> str | None:
    """Check if two tool names are suspiciously similar.

    Returns a description of the similarity type, or None if not similar.
    """
    a = name_a.lower().strip()
    b = name_b.lower().strip()

    if a == b:
        return None  # Exact duplicate — different issue

    # 1. One is plural of the other (read_file vs read_files)
    if a + "s" == b or b + "s" == a:
        return "singular/plural variant"

    # 2. Underscore vs no-underscore (read_file vs readfile)
    if a.replace("_", "") == b.replace("_", ""):
        return "underscore variant"

    # 3. Underscore vs hyphen (read_file vs read-file)
    if a.replace("_", "-") == b or b.replace("_", "-") == a:
        return "underscore/hyphen variant"

    # 4. CamelCase vs snake_case (readFile vs read_file)
    import re
    a_snake = re.sub(r'(?<!^)(?=[A-Z])', '_', name_a).lower()
    b_snake = re.sub(r'(?<!^)(?=[A-Z])', '_', name_b).lower()
    if a_snake == b_snake and a != b:
        return "camelCase/snake_case variant"

    # 5. Version suffix (read_file vs read_file_v2)
    if re.match(rf'^{re.escape(a)}[_-]?v?\d+$', b) or re.match(rf'^{re.escape(b)}[_-]?v?\d+$', a):
        return "version suffix variant"

    # 6. Levenshtein distance of 1 (typo-distance: read_file vs read_flie)
    if len(a) > 5 and len(b) > 5:
        distance = _edit_distance(a, b)
        if distance == 1:
            return "1-character difference (possible typosquat)"

    # 7. Same words in different order (file_read vs read_file)
    a_parts = set(re.split(r'[_\-\s]', a))
    b_parts = set(re.split(r'[_\-\s]', b))
    if a_parts == b_parts and a != b and len(a_parts) >= 2:
        return "same words, different order"

    return None


def _edit_distance(s1: str, s2: str) -> int:
    """Compute edit distance (simplified for short strings)."""
    if abs(len(s1) - len(s2)) > 2:
        return 99  # Quick reject for very different lengths

    if len(s1) < len(s2):
        return _edit_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr

    return prev[-1]
