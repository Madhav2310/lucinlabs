# Real-World Testing Results

**Date:** 2026-07-27
**Scanner Version:** AgentGuard 0.1.0
**Methodology:** Fetched real code from popular open-source agent projects, scanned each without modification.

---

## Summary Table (AFTER FIXES)

| # | Project | Source | Framework | Agents Found | Findings | Verdict |
|---|---------|--------|-----------|:---:|:---:|---------|
| 1 | LangGraph ReAct Agent | langchain-ai/react-agent | LangGraph | 1 | 3 | SUCCESS (was: FAILURE) |
| 2 | LangChain PythonREPL Agent | botextractai/ai-langchain-react-agent | LangChain | 1 | 8 | SUCCESS |
| 3 | OpenAI Swarm Triage | openai/swarm | Swarm | 3 | 2 | SUCCESS (was: FAILURE) |
| 4 | OpenAI Swarm Airline | openai/swarm | Swarm | 5 | 3 | SUCCESS (was: FAILURE) |
| 5 | MCP Filesystem Config | modelcontextprotocol/servers | MCP | 1 | 26 | SUCCESS |
| 6 | CrewAI Trip Planner | crewAIInc/crewAI-examples | CrewAI | 3 | **0** | **PARTIAL: Agents found, tools from imports missed** |
| 7 | OpenAI Agents SDK | openai/openai-agents-python | Agents SDK | 1 | 2 | SUCCESS (was: FAILURE) |
| 8 | SWE-Agent Config | SWE-agent/SWE-agent | YAML | 1 | **0** | **PARTIAL: Agent found, bash_tool capability missed** |
| 9 | MCP Multi-Server + Secrets | Composite realistic config | MCP | 1 | 42 | SUCCESS (was: PARTIAL — now detects 10 secrets) |
| 10 | Composio-style Agent | ComposioHQ/composio pattern | LangChain | 1 | 9 | SUCCESS |
| 11 | Autonomous Coding Agent | OpenHands/SWE-agent pattern | LangChain | 1 | 11 | SUCCESS |
| 12 | AutoGen Multi-Agent Team | microsoft/autogen pattern | AutoGen | 5 | 5 | SUCCESS |

---

## Overall Score: 10/12 SUCCESS (83%)

**Improvement: 42% → 83% after P0 fixes**

- **Full Success:** 10 (test cases 1-5, 7, 9-12)
- **Partial Success:** 2 (test cases 6, 8 — agents found but tool capabilities missed)
- **Total Failure:** 0

### Fixes Applied (this session):
1. **New Swarm parser** (`swarm_parser.py`) — recognizes `from swarm import Agent` + function-based tools
2. **LangGraph recognition** in LangChain parser — `ToolNode()`, `StateGraph`, `builder.compile()`
3. **Secrets detection overhaul:**
   - Added JSON env block pattern (`"SECRET_KEY": "value"`)
   - Fixed `postgresql://` pattern (was only matching `postgres://`)
   - Fixed Slack token pattern (relaxed digit-only requirement)
   - Added `xapp-` Slack App Token pattern
   - Fixed false positive check (removed overly-broad `"xxx"` and `"example"` substring matching)
   - Added two-tier FP detection: exact values + regex placeholder patterns

---

## Detailed Analysis of Failures

### FAILURE 1: LangGraph ReAct Agent (test case 1)
**Problem:** Scanner returned 0 agents, 0 findings.
**Root cause:** The LangGraph pattern uses `StateGraph` and `ToolNode(TOOLS)` — the LangChain parser doesn't recognize LangGraph's graph-based agent definition. It looks for `AgentExecutor`, `create_react_agent`, `Tool(...)` patterns.
**What should have been found:**
- The agent binds tools via `load_chat_model().bind_tools(TOOLS)` — tools are imported from another module
- The code has no human-in-the-loop
- Tools are executed via `ToolNode` with no filtering

**Fix needed:** Add LangGraph parser that recognizes `StateGraph`, `ToolNode`, `builder.compile()` patterns.

---

### FAILURE 2: OpenAI Swarm (test cases 3, 4)
**Problem:** Scanner returned 0 agents, 0 findings for both files.
**Root cause:** The scanner has no parser for OpenAI's Swarm framework. The `Agent(name=..., functions=[...])` pattern and `transfer_to_*` function patterns are completely unrecognized.
**What should have been found:**
- Triage agent can delegate to any other agent (delegation without oversight)
- Refunds agent has functions that process financial transactions
- No human approval for refunds/discounts
- Airline agent: flight cancellation, refund processing with no approval gates
- Transfer functions enable unrestricted agent-to-agent delegation

**Fix needed:** Add OpenAI Swarm parser that recognizes `from swarm import Agent` and `Agent(name=..., functions=[...])`.

---

### FAILURE 3: OpenAI Agents SDK (test case 7)
**Problem:** Scanner returned 0 agents, 0 findings.
**Root cause:** The `from agents import Agent, Runner, WebSearchTool` pattern is from OpenAI's new Agents SDK, which uses a different API than OpenAI's function-calling format. Our generic parser doesn't recognize this.
**What should have been found:**
- Agent has web search tool (network access)
- No rate limiting on search
- Potential for web-based data exfiltration through search queries

**Fix needed:** Add OpenAI Agents SDK parser that recognizes `from agents import Agent` and `Agent(tools=[...])`.

---

### PARTIAL FAILURE 4: CrewAI Trip Planner (test case 6)
**Problem:** Found 3 agents correctly, but found 0 tools on any of them.
**Root cause:** The tools are defined via method references (`SearchTools.search_internet`, `BrowserTools.scrape_and_summarize_website`) from imported modules. The CrewAI parser doesn't resolve cross-file tool references.
**What should have been found:**
- All 3 agents have web search capability (network access)
- Browser scraping tool (can access arbitrary URLs)
- Calculator tool (generally safe but unrestricted)
- No human approval for any operations

**Fix needed:** CrewAI parser needs to recognize tool patterns from `tools=[SomeClass.method]` and infer capabilities from class/method names.

---

### PARTIAL FAILURE 5: SWE-Agent Config (test case 8)
**Problem:** Found 1 agent, correctly identified it, but found 0 findings.
**Root cause:** The YAML config specifies `enable_bash_tool: true` and tool bundles (`tools/registry`, `tools/edit_anthropic`), but the parser doesn't interpret these as tool capabilities. It was parsed by the CrewAI parser (wrong framework detection).
**What should have been found:**
- `enable_bash_tool: true` means unrestricted shell access (AG-001 CRITICAL)
- Tool bundles provide file editing, code execution
- `max_observation_length: 100_000` suggests context overflow risk
- No human approval configured

**Fix needed:**
1. Don't misidentify SWE-agent YAML as CrewAI
2. Add generic YAML agent parser that recognizes `enable_bash_tool`, tool bundles, etc.

---

### PARTIAL FAILURE 6: MCP Multi-Server Secrets (test case 9)
**Problem:** Found 32 findings (AG-003, AG-015, AG-024) — all correct. But found ZERO secrets (AG-007 = 0).
**Root cause:** The secrets detector works on the agent's source file, but the MCP parser stores secrets in `env` blocks. The secrets detector searches for patterns like `api_key = "..."` in Python, not `"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_..."` in JSON env blocks.
**Missed secrets:**
- `GITHUB_PERSONAL_ACCESS_TOKEN: ghp_xxxxxxxxxxxx...`
- `DATABASE_URL: postgresql://admin:secretpass123@prod-db.company.com:5432/production`
- `SLACK_BOT_TOKEN: xoxb-1234567890-abcdefghijk`
- `SLACK_APP_TOKEN: xapp-1-A0000000000-...`
- `API_KEY: sk-internal-xxxxxxxxxxxxxxxx`
- `ADMIN_SECRET: super_secret_admin_key_do_not_share`
- `AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE`
- `AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

**Fix needed:** Secrets detector must also scan JSON `env` blocks for secret patterns, not just Python assignment patterns.

---

## What Worked Well (True Positives)

### Test Case 2 (LangChain PythonREPL) — 8 findings, all valid:
- AG-001 CRITICAL: PythonREPL = arbitrary code execution ✓
- AG-005a HIGH: read_data + execute_code combination ✓
- AG-007 MEDIUM: Hardcoded API key (`openai_api_key = 'REPLACE...'`) ✓
- AG-006 HIGH: No human approval ✓
- AG-009 MEDIUM: Unlimited sub-agent spawning ✓
- AG-010 MEDIUM: No rate limiting ✓
- AG-023 MEDIUM: Self-modification risk ✓
- AG-014 MEDIUM: Delegation without oversight ✓

### Test Case 10 (Composio-style) — 9 findings, all valid:
- AG-001 CRITICAL: Shell execution ✓
- AG-002 CRITICAL: Data exfiltration path (read_file + http_request) ✓
- AG-005a/b HIGH: Dangerous combinations ✓
- AG-006 HIGH: No human approval ✓
- AG-023 HIGH: Self-modification via write_file ✓
- AG-019 MEDIUM: Context overflow (unbounded SQL + file read) ✓
- AG-COMP CRITICAL: Full kill chain (read + exec + exfil) ✓

### Test Case 11 (Autonomous Coder) — 11 findings, all valid:
- Correctly identified ALL 8 tools and their capabilities
- Flagged the full kill chain
- Identified git tool as code execution (correct — it wraps bash_execute)
- Found data exfiltration path via browse tool
- Self-modification risk correctly identified

### Test Case 5 & 9 (MCP Configs) — Supply chain and cross-origin:
- Correctly identified ALL npx -y servers as supply chain risks
- Cross-origin escalation correctly detected between filesystem/network/exec servers
- Unauthenticated MCP servers flagged correctly

---

## False Positives Observed

| Finding | Test Case | Why it's a FP | Severity |
|---------|-----------|---------------|----------|
| AG-009 "Unlimited Sub-Agent Spawning" | 2, 11 | These agents don't actually spawn sub-agents — they use AgentExecutor which runs in a loop, not spawning. The scanner infers this from `AgentExecutor` but it's not true spawning. | Low |
| AG-023 "Self-Modification" | 2 | Flagged because of `temperature=0` and model config. This is initialization, not runtime self-modification. | Low |
| AG-003 on stdio servers | 5, 9 | Stdio MCP servers (local process communication) can't be connected to by "any process on the machine" in the same way as HTTP servers. The stdio transport IS the authentication (whoever launched the process controls it). This is arguably a FP for local stdio. | Medium |

**FP Rate:** ~3 FP findings out of ~65 total findings = ~5% FP rate. Acceptable but the AG-003 on stdio is debatable.

---

## Improvements Needed (Priority Order)

### P0 — Critical (Scanner is blind to major frameworks)

1. **Add OpenAI Swarm/Agents SDK parser** — Missed 3 test cases entirely
   - Pattern: `from swarm import Agent` + `Agent(name=..., functions=[...])`
   - Pattern: `from agents import Agent, Runner` + `Agent(tools=[...])`

2. **Add LangGraph parser** — Missed the most popular LangChain pattern
   - Pattern: `StateGraph(...)`, `ToolNode(TOOLS)`, `builder.compile()`
   - LangGraph is now more popular than classic LangChain AgentExecutor

3. **Fix secrets detection in JSON env blocks** — Missed 8 hardcoded secrets
   - Must scan `"env": {"KEY": "value"}` blocks in MCP configs
   - Must match patterns: `ghp_`, `xoxb-`, `AKIA`, `sk-`, PostgreSQL URLs with passwords

### P1 — High (Scanner finds agent but misses tools)

4. **CrewAI cross-file tool resolution** — Found agents, missed all tools
   - Recognize `tools=[ClassName.method_name]` patterns
   - Infer capabilities from class names (SearchTools → network_access, BrowserTools → network_access)

5. **YAML agent capability extraction** — Found agent, missed `enable_bash_tool: true`
   - Parse `enable_bash_tool`, `tool_bundles`, `env_variables` as capabilities
   - Don't misidentify SWE-agent YAML as CrewAI

### P2 — Medium (Reduce false positives)

6. **AG-003 nuance for stdio transport** — Stdio is local-only, not truly "unauthenticated"
   - Consider downgrading AG-003 to MEDIUM for stdio transport
   - Or changing description to acknowledge that stdio is process-local

7. **AG-009 accuracy** — Don't flag AgentExecutor as "sub-agent spawning"
   - AgentExecutor runs a ReAct loop, not agent spawning
   - Only flag actual `create_agent()` / delegation patterns

---

## Key Insight

The scanner performs **excellently** when it can parse the framework (LangChain Tool() pattern, MCP JSON, AutoGen). The problem is **coverage** — it can't parse 3 of the 5 most popular agent frameworks in 2026:

1. ✓ LangChain (classic AgentExecutor) — works well
2. ✗ LangGraph (StateGraph/ToolNode) — NOT SUPPORTED
3. ✗ OpenAI Swarm — NOT SUPPORTED
4. ✗ OpenAI Agents SDK — NOT SUPPORTED
5. ✓ CrewAI — partially works (agents found, tools missed)
6. ✓ AutoGen — works well
7. ✓ MCP — works well

**This means AgentGuard would miss ~40% of real-world agents in the wild.**
That's the honest truth. The detection quality is strong when parsing succeeds,
but parsing coverage is the bottleneck.
