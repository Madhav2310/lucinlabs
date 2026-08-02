"""AG-019: Context Window Overflow Risk.

Detects when agent tools can return unbounded data that may:
1. Overflow the LLM context window (causing truncation/lost instructions)
2. Inject massive amounts of adversarial content into the context
3. Consume excessive tokens (cost attack)
4. Push safety instructions out of the attention window

This is a subtle but real attack vector:
- An attacker stuffs a data source with adversarial content
- Agent retrieves it via a tool (database query, file read, web fetch)
- The massive response fills the context window
- The LLM's attention to its system prompt weakens
- Injected instructions in the data become dominant

Real-world basis:
- "Many-shot jailbreaking" (Anthropic, 2024): Large contexts dilute safety
- Context overflow attacks via RAG (academic, 2025)
- Token-level DoS against agents (OWASP #5: Resource Overload)
"""

from lucin.models import Agent, Finding, Severity, Tool, ToolCapability
from lucin.owasp import owasp_ref


# Tools that can potentially return very large amounts of data
UNBOUNDED_RETURN_PATTERNS = [
    # Database tools without LIMIT
    ("sql_query", "database query without explicit LIMIT"),
    ("query", "database query potentially unbounded"),
    ("search", "search results potentially unbounded"),
    ("fetch", "web fetch with no size limit"),
    ("read_file", "file read with no size limit"),
    ("web_search", "search results potentially large"),
    ("scrape", "web scraping can return entire pages"),
    ("list_directory", "directory listing can be very large"),
    ("get_records", "record retrieval potentially unbounded"),
    ("download", "download with no size limit"),
]


def detect_context_overflow(agent: Agent) -> list[Finding]:
    """Detect tools that could return unbounded data (context overflow risk)."""
    findings = []

    # Find tools with read/network capability (can return large data)
    data_tools = [
        t for t in agent.tools
        if ToolCapability.READ_DATA in t.capabilities
        or ToolCapability.NETWORK_ACCESS in t.capabilities
    ]

    if not data_tools:
        return findings

    # Check if any data-returning tool has size constraints mentioned
    unbounded_tools = []
    for tool in data_tools:
        tool_lower = tool.name.lower()
        desc_lower = tool.description.lower()

        # Check if the tool description mentions size limits
        has_limit = any(word in desc_lower for word in [
            "limit", "max", "truncate", "first", "top",
            "maximum", "bounded", "paginate", "page_size",
        ])

        if not has_limit:
            # Check against known unbounded patterns
            for pattern, reason in UNBOUNDED_RETURN_PATTERNS:
                if pattern in tool_lower:
                    unbounded_tools.append((tool, reason))
                    break

    if len(unbounded_tools) >= 2:
        # Multiple unbounded tools = compounding risk
        tool_names = ", ".join(t.name for t, _ in unbounded_tools[:5])
        findings.append(Finding(
            id="AG-019",
            title="Context Overflow: Multiple Unbounded Data Tools",
            severity=Severity.MEDIUM,
            description=(
                f"Agent '{agent.name}' has {len(unbounded_tools)} tool(s) that can "
                f"return potentially unbounded data: {tool_names}.\n\n"
                f"Without output size limits, these tools can overflow the LLM's "
                f"context window, causing: loss of system prompt adherence, "
                f"token cost explosion, or injection of adversarial content that "
                f"dominates the context."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "1. Attacker populates a data source with large adversarial content\n"
                "2. Agent's tool retrieves the data (e.g., SQL query returns 10K rows)\n"
                "3. Massive response fills the context window\n"
                "4. System prompt and safety instructions get pushed out of attention\n"
                "5. Adversarial instructions embedded in the data become dominant\n\n"
                "Also enables token-based DoS: each tool call costs thousands of tokens."
            ),
            blast_radius=(
                "Context window filled with adversarial content → "
                "safety instructions ineffective → agent follows injected instructions."
            ),
            owasp_ref=owasp_ref("AG-019"),
            fix_suggestion=(
                "Add output size limits to all data-returning tools:\n"
                "  → SQL tools: add LIMIT clause (max 100 rows)\n"
                "  → File tools: truncate to first N bytes (e.g., 10KB)\n"
                "  → Web tools: limit response size\n"
                "  → Search tools: limit to top K results\n\n"
                "Example:\n"
                "  result = tool_call(...)\n"
                "  if len(result) > MAX_TOOL_OUTPUT:\n"
                "      result = result[:MAX_TOOL_OUTPUT] + '\\n[TRUNCATED]'\n"
                "  return result"
            ),
            source_file=agent.source_file,
        ))

    return findings
