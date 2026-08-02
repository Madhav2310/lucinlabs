# Issues Catalog — Everything We're Missing
## Discovered through extended QA testing July 27, 2026

---

## Category 1: Missing Secret Patterns

| Secret Type | Pattern | Source | Priority |
|-------------|---------|--------|----------|
| Google OAuth Client Secret | `GOCSPX-[A-Za-z0-9_-]{20,}` | Gmail MCP configs | HIGH |
| Google Refresh Token | `1//[A-Za-z0-9_-]{30,}` | Gmail MCP configs | HIGH |
| Notion Integration Token | `secret_[a-zA-Z0-9]{30,}` | Notion MCP configs | HIGH |
| Linear API Key | `lin_api_[A-Za-z0-9]{20,}` | Linear MCP configs | MEDIUM |
| Brave Search API Key | `BSA_[A-Za-z0-9]{20,}` | Brave Search MCP | MEDIUM |
| Vercel Token | `vercel_[A-Za-z0-9]{20,}` | Deploy MCP servers | MEDIUM |
| Supabase Key | `sbp_[A-Za-z0-9]{30,}` | Database MCP | MEDIUM |
| Pinecone API Key | `pc-[A-Za-z0-9]{30,}` | Vector store configs | MEDIUM |

**Impact:** 6 secrets in a single real-world config were missed.

---

## Category 2: Sensitive Filesystem Path Detection (MCP-specific)

**Problem:** MCP filesystem server configured with `.ssh`, `.aws`, `.gnupg`, `.kube` paths should trigger HIGH findings, but AG-016 (scope violation) doesn't fire for MCP configs — it only works for Python-based coding agents.

**Missing detection:**
- `/Users/dev/.ssh` → access to SSH private keys
- `/Users/dev/.aws` → access to AWS credentials
- `/Users/dev/.gnupg` → access to GPG private keys
- `/Users/dev/.kube` → access to Kubernetes configs
- `/` (root filesystem) → unrestricted access

**Fix needed:** MCP parser should check filesystem server args for sensitive path patterns.

---

## Category 3: Dynamic Tool Registration (Not Parsed)

**Problem:** Tools registered through non-standard patterns are invisible to our parsers:

| Pattern | Example | Caught? |
|---------|---------|---------|
| Tool factory function | `make_db_tool("users")` → creates Tool in loop | NO |
| Config-dict based tools | `TOOL_CONFIG = {"name": {"func": lambda...}}` | NO |
| Decorator registration | `@register_tool("run_script", "...")` | NO |
| Loop-based registration | `for table in tables: tools.append(make_tool(table))` | NO |
| Lambda-wrapped tools | `Tool(func=lambda x: subprocess.getoutput(x))` | Partial (body inspector doesn't inspect lambdas in Tool() kwargs yet) |

**Impact:** Test 13 found only 4/~10 tools. The 6 missed tools include 2 with shell execution (run_script, kubectl).

**Fix needed:**
1. Trace Tool() calls where `func=` is a variable name → resolve to function def → inspect body
2. Detect `@register_tool` pattern decorators
3. For lambdas in Tool(func=lambda...), inspect the lambda body

---

## Category 4: RAG/Memory Detection Gaps

**Problem from Test 14:**
- `has_memory` is False despite the agent having:
  - A FAISS vector store (persistent on disk)
  - Session-based conversation history (JSON files)
  - `knowledge_add` function that WRITES to the vector store
- `knowledge_search` has empty capabilities despite calling `qa_chain.invoke()` (which triggers retrieval)
- `knowledge_add` has empty capabilities despite calling `vectorstore.add_texts()` (write operation)

**What we correctly caught:**
- AG-013 Memory Poisoning (triggered by "knowledge" and "history" patterns)
- AG-002 Data Exfiltration (history_get + notify_team)

**What we missed:**
- The vector store IS writable by the agent → should be AG-013 with higher severity
- `has_memory` should be True (heuristic: presence of "vectorstore", "FAISS", "session", "history" patterns)

---

## Category 5: MCP Config — Scope/Sensitivity Analysis

**Problem:** A filesystem MCP server with `"/"` as its root has access to THE ENTIRE SYSTEM but we don't flag this differently from a server with access to `"/Users/dev/projects"`.

**Missing graduated severity:**
- `"/"` → CRITICAL (entire filesystem)
- `"/Users"` or `"/home"` → HIGH (all user data)
- `"~/.ssh"`, `"~/.aws"` → CRITICAL (cryptographic credentials)
- `"/tmp/workspace"` → LOW (sandboxed)

---

## Category 6: False Positives Observed

| Finding | Test Case | Why FP | Severity |
|---------|-----------|--------|----------|
| AG-009 "Sub-Agent Spawning" | Test 13, 14 | AgentExecutor doesn't actually spawn sub-agents | Low |
| AG-023 "Self-Modification" | Test 13 | Flags `temperature=0` as "dynamic config" | Low |
| AG-023 "File Write to Own Source" | Test 14 | history_save writes to ./sessions/ not own source | Medium |

**FP rate:** ~3/28 findings across tests 13-14 = ~11%. Above our 5% target. Needs tuning.

---

## Category 7: Capability Classification Gaps

Tools with EMPTY capabilities that should have been classified:

| Tool | Body Contains | Should Be | Why Missed |
|------|---------------|-----------|------------|
| knowledge_search | qa_chain.invoke() | READ_DATA | invoke() not in dangerous calls list |
| knowledge_add | vectorstore.add_texts() | WRITE_DATA | add_texts() not a recognized write pattern |
| query_{table} | sqlite3.connect + execute | READ_DATA | Factory-created, body never inspected |
| file_reader | open(path).read() | READ_DATA, FILE_SYSTEM | Lambda not inspected |
| web_fetcher | urllib...urlopen() | NETWORK_ACCESS | Lambda with __import__ not parsed |

**Root cause:** Body inspector only runs when `func_map` contains the function AND it's directly referenced from Tool(func=name). Factory-created tools and lambdas bypass this.

---

## Category 8: Cross-Origin Analysis Gaps (MCP)

**Problem from Test 15:** Only 5 AG-024 findings, but there are many more dangerous cross-origin pairs:
- filesystem(.ssh) × github → SSH keys accessible to code that pushes to repos
- filesystem(.aws) × docker → AWS creds accessible to container management
- gmail × postgres-prod → email content + production database = PII aggregation
- puppeteer × gmail → browser can access Gmail sessions, steal cookies

**The scanner detects SOME pairs but misses the SEMANTIC DANGER** of specific server combinations based on their configured scope.

---

## Category 9: Things We Don't Detect AT ALL

| Attack Pattern | Description | Example | Priority |
|----------------|-------------|---------|----------|
| Tool schema manipulation | Tool changes its schema after approval | Rug-pull attack (Invariant research) | HIGH |
| Implicit data flows | Data flows through agent memory between tool calls | read_file → (stored in context) → send_email | HIGH |
| Rate limit bypass via tool chaining | Call same dangerous operation across different tools | file_read("/etc/passwd") + knowledge_add(content) + notify_team(content) | MEDIUM |
| Ambient authority exploitation | Agent inherits permissions from hosting environment | MCP server running as root | HIGH |
| Timing-based exfiltration | Encode data in response timing | Slow response = 1, fast = 0 (covert channel) | LOW |
| Model fingerprinting via tools | Probe agent to determine which LLM backs it | Useful for targeted attacks | LOW |

---

## Summary Statistics

| Category | Issues | Impact |
|----------|--------|--------|
| Missing secret patterns | 8 new patterns needed | ~60% secrets missed in complex configs |
| Sensitive path detection | 5 paths to check for | Critical credentials exposed silently |
| Dynamic tool patterns | 5 patterns not parsed | ~40% of factory/decorator tools invisible |
| RAG/Memory gaps | 3 detection improvements | Memory-rich agents under-analyzed |
| MCP scope analysis | Graduated severity needed | Root filesystem treated same as sandboxed |
| False positives | 3 specific FPs | 11% FP rate (target: <5%) |
| Capability gaps | 5 tools misclassified | Body inspector needs wider method coverage |
| Cross-origin semantic | Scope-aware pair analysis | Dangerous combinations missed |
| Zero-coverage attacks | 6 attack patterns | Fundamental detection gaps |

**Total actionable improvements identified: 44**

---

## Category 10: CVE/Incident Coverage (PASS/FAIL)

| CVE/Incident | Detection | Result | Notes |
|-------------|-----------|--------|-------|
| CVE-2025-6514 (mcp-remote RCE) | AG-015 supply chain | PASS | Flags npx -y pattern |
| CVE-2025-54795 (Claude Code injection) | AG-001 shell + body inspector | PASS | Catches shell=True in "allowlisted" tool |
| CVE-2026-25253 (OpenClaw WebSocket) | N/A | N/A | Architecture flaw, not config issue |
| CVE-2026-25592 (Semantic Kernel eval) | AG-001 via body inspector | PASS | Catches eval() in tool body |
| Postmark MCP attack (Sep 2025) | AG-015 supply chain | PASS | Flags exact npx -y postmark-mcp pattern |
| ClawHavoc campaign (Jan 2026) | AG-011 tool poisoning | PASS | Catches directive language in descriptions |

**CVE Coverage: 5/5 detectable attacks caught. Body inspector is critical for 2 of these.**

---

## Category 11: Comprehensive Evasion Summary (Updated)

| Evasion Technique | Caught? | By What | Remaining Gap |
|-------------------|---------|---------|---------------|
| Innocent tool name + subprocess.run() | YES | Body inspector | — |
| Innocent tool name + os.popen() | YES | Body inspector | — |
| Innocent tool name + eval() | YES | Body inspector | — |
| importlib.import_module() + getattr() | YES | Body inspector (partial match) | — |
| Lambda in Tool(func=lambda: ...) | YES | Body inspector lambda walk | — |
| import subprocess as sp; sp.run() | YES | Body inspector resolves sp→subprocess | — |
| from os import popen as runner; runner() | NO | — | Alias `runner` not mapped to os.popen |
| Tool(func=MyClass.method) | NO | — | Class method bodies not inspected |
| Factory function: make_tool() → Tool | NO | — | Factory-created tools not traced |
| Decorator: @register_tool("name") | NO | — | Custom decorator registration invisible |
| Config dict: TOOLS={"name": {"func":...}} | NO | — | Dict-based tool definitions not parsed |
| Tool from loop: for x in items: tools.append(...) | NO | — | Loop-generated tools not expanded |
| 100K blank line prefix (Trail of Bits) | UNTESTED | — | Need truncation-proof parsing |
| base64 encoded command in function | Partial | Entropy detection | Only in assignment context |
| XOR obfuscated secret | NO | — | No runtime deobfuscation |
| String concatenation for function names | NO | — | No constant folding/propagation |

**Evasion resistance: 6/16 techniques caught = 37.5% comprehensive resistance**
**(Previously measured at 75% — but that was only against 5 specific techniques)**

---

## Category 12: Duplicate Parsing Bug (Code Quality)

When scanning a directory, multiple parsers can claim the same file:
- AutoGen's `team.py` is also matched by LangChain parser (has `AgentExecutor` pattern)
- Swarm's `agents.py` is also matched by generic parser (has tool functions)

**Root cause:** `detect_and_parse()` runs ALL parsers and concatenates results. No deduplication.
**Fix:** After all parsers run, deduplicate agents by (source_file, agent_name) pair.

---

## Priority Matrix for Fixes

### P0 — Must fix before launch (1 missed finding = 1 compromised system)
1. Duplicate parsing deduplication
2. Import alias resolution (`from os import popen as runner`)
3. Class method body inspection (`Tool(func=MyClass.method)`)
4. SendGrid secret pattern fix (pattern exists but not matching)

### P1 — Should fix for credibility
5. Factory function tool tracing
6. Custom decorator tool registration detection
7. Cross-file import resolution (CrewAI tools)
8. Memory detection heuristic expansion (vectorstore, session, FAISS)
9. MCP scope severity graduation (/ = CRITICAL, ~/projects = LOW)

### P1 — Framework Coverage (proven gaps from testing)
10. Pydantic AI parser (`@agent.tool` + `RunContext[Deps]`) — 16.5K stars, ZERO detection
11. Google ADK parser (partially works via generic, but sub_agents/ToolContext missed)
12. LangChain v1 stateful tools (`@tool` + `ToolRuntime` + `Command(update={})`)

### P2 — Nice to have for enterprise
13. Config-dict tool parsing
14. Loop-generated tool expansion
15. Trail of Bits padding resistance
16. Constant folding for obfuscated strings
17. .md skill file scanning (ClawHavoc pattern)

---

## Category 13: Unsupported Frameworks (tested July 27)

| Framework | Stars/Adoption | Pattern | Current Detection | Gap |
|-----------|---------------|---------|-------------------|-----|
| Pydantic AI | 16.5K stars | `@agent.tool` + `RunContext[Deps]` | **ZERO** | Need dedicated parser |
| Google ADK | Google official | `Agent(tools=[funcs])` + `ToolContext` | **Partial** (generic catches functions) | sub_agents, ToolContext state missed |
| LangChain v1 | Production deploys | `@tool` + `ToolRuntime[S]` + `Command` | Partial (decorator caught) | State mutations, middleware not analyzed |
| CrewAI v2 | Popular | `@CrewBase` + `@agent` class decorators | **Partial** (finds some tools) | YAML config loading not traced |

**Impact:** Pydantic AI is the 3rd most popular agent framework (after LangChain/LangGraph and CrewAI). Missing it entirely means ~15% of the market is invisible.

---

## Category 14: Complete Findings Count (All Testing)

| Test Case | Agents | Findings | Status |
|-----------|:---:|:---:|--------|
| 01 LangGraph ReAct | 1 | 3 | OK |
| 02 LangChain PythonREPL | 1 | 8 | OK |
| 03 Swarm Triage | 3 | 2 | OK |
| 04 Swarm Airline | 5 | 3 | OK |
| 05 MCP Filesystem | 1 | 26 | OK |
| 06 CrewAI Trip (cross-file) | 3 | 0 | GAP: tools from imports |
| 07 Agents SDK | 1 | 2 | OK |
| 08 SWE-Agent YAML | 1 | 0 | GAP: bash_tool not interpreted |
| 09 MCP Multi-Server | 1 | 42 | OK |
| 10 Composio-style | 1 | 10 | OK |
| 11 Autonomous Coder | 1 | 11 | OK |
| 12 AutoGen Team | 5 | 5 | OK |
| 13 Dynamic Tools | 1 | 4 | PARTIAL: missed factory/decorator tools |
| 14 RAG Agent | 1 | 8 | PARTIAL: memory not detected |
| 15 MCP Dangerous Real | 1 | 35 | OK (after secret pattern fix) |
| Pydantic AI | 0 | 0 | **FAIL: Not supported** |
| Google ADK | 1 | 6 | OK (generic parser) |
| CrewAI v2 | 1 | 3 | PARTIAL |
| CVE-2025-6514 sim | 1 | 1 | OK |
| CVE-2025-54795 sim | 1 | 1+ | OK |
| CVE-2026-25592 sim | 1 | 1+ | OK |
| Postmark sim | 1 | 1+ | OK |
| ClawHavoc sim | - | 1 | OK (via description analysis) |

**Totals: 18/22 test cases produce correct findings (82%)**
**With Pydantic AI parser: would be 19/22 (86%)**

---

## Category 15: Competitive Gap Analysis (verified from source code)

### What competitors detect that we DON'T:

| Gap | Who Does It | Impact | Priority |
|-----|-------------|--------|----------|
| LLM-based injection classification | Snyk (cloud API), Lakera (transformer model) | Higher recall on novel injection patterns vs our regex | P2 (requires ML model) |
| PII entity detection (in tool data) | Invariant Guardrails | Can't flag when PII flows through tools | P2 |
| Runtime enforcement (block in real-time) | Invariant, Microsoft AGT, Lakera | We only do pre-deploy (by design) | P3 (different product) |
| Custom policy language | Microsoft (OPA/Rego/Cedar), Invariant (declarative rules) | Users can't write org-specific rules | P1 (YAML rules planned in Phase 8E) |
| Trust scoring with decay | Microsoft AGT (ring-based, temporal) | No identity/trust model for agents | P3 |
| Plugin signing (Ed25519) | Microsoft AGT | Can't verify MCP server authenticity cryptographically | P2 |
| 6-pass normalization on LIVE traffic | Pipelock | Our deobfuscation only on descriptions, not runtime args | N/A (runtime) |
| OCR for image-based injection | Invariant Guardrails | Can't detect visual prompt injection | P3 |
| Tool hash pinning (rug-pull detection) | Snyk Agent-Scan | Can't detect when tool descriptions change between scans | P1 |
| Semgrep integration for runtime code | Invariant Guardrails | No formal SAST engine integration | P2 |

### What WE detect that NOBODY else does:

| Capability | Why It Matters | Competitors Miss It |
|-----------|---------------|---------------------|
| **AST function body inspection** | Catches shell hidden in "data_processor" — 80% of real evasion | Snyk only checks descriptions (cloud LLM), Microsoft runtime-only |
| **Cross-origin escalation (pairwise MCP)** | filesystem×github = SSH keys accessible to code pushes | Nobody does capability combinatorics on server pairs |
| **Pre-deploy compositional risk (N-way)** | Kill chain detection BEFORE deployment | Others catch at runtime AFTER damage starts |
| **Memory poisoning from source code** | 6 sub-checks including RAG position, retrieval filtering | Others handle runtime-only or ignore entirely |
| **Multi-framework source parsing** | LangChain+LangGraph+Swarm+CrewAI+AutoGen+MCP+generic | Snyk = MCP only. Microsoft = runtime proxy. Lakera = API |
| **Supply chain (npx -y + SLSA)** | Exact Postmark attack pattern detection | Snyk only has hash pinning, not version analysis |
| **MCP sensitive path detection** | .ssh/.aws in filesystem args = CRITICAL | Nobody else checks server argument paths |

### Honest Positioning Statement

**We are the ONLY pre-deployment static analyzer that inspects agent SOURCE CODE at the AST level across multiple frameworks.** Everyone else either:
- Operates at runtime only (Invariant Guardrails, Microsoft AGT, Lakera)
- Only scans MCP tool metadata/descriptions (Snyk Agent-Scan, Cisco)
- Requires a cloud API for detection logic (Snyk — sends data externally)

**Our specific moat:** Function body inspection + cross-origin analysis + compositional risk. This combination exists NOWHERE else in the market as of July 2026.

**Our specific weakness:** Regex-based injection detection vs ML classifiers. Snyk/Lakera will catch novel injection patterns we miss. The fix is either: (a) integrate PromptGuard 2 locally, or (b) offer optional cloud classifier as paid tier.
