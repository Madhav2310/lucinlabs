# Detection Completeness Map
## Every capability in the market — do we have it?

**Principle:** We must detect everything every competitor detects, PLUS our unique capabilities.
**One missed detection = one compromised system.**

---

## MASTER DETECTION MATRIX

### A. Tool/Prompt Injection Detection

| Detection | Snyk | Invariant | Microsoft | Lakera | Cisco | Pipelock | **AgentGuard** | Gap? |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|------|
| "Ignore previous instructions" pattern | Y | Y | Y | Y | Y | Y | **Y** (AG-011) | — |
| Hidden `<instructions>` tags | Y | Y | Y | Y | Y | Y | **Y** (AG-011) | — |
| Role override ("you are now...") | Y | Y | Y | Y | - | Y | **Y** (AG-011) | — |
| Authority claims ("as admin...") | Y | Y | Y | Y | - | Y | **Y** (AG-011) | — |
| Base64-encoded instructions | - | Y | Y | - | - | Y | **Y** (AG-021 + deobfuscate) | — |
| Unicode/homoglyph obfuscation | - | Y | Y | - | - | - | **Y** (AG-021) | — |
| Zero-width character injection | - | Y | Y | - | - | - | **Y** (AG-021) | — |
| URL-encoded injection | - | - | - | - | - | Y | **Y** (AG-021) | — |
| Hex-encoded injection | - | - | - | - | - | Y | **Y** (AG-021 deobfuscate) | — |
| Leetspeak obfuscation | - | - | - | - | - | Y | **NO** | **GAP** |
| Vowel folding obfuscation | - | - | - | - | - | Y | **NO** | **GAP** |
| Novel/fuzzy injection (ML-based) | Y (LLM) | Y (ML) | - | Y (ML) | - | - | **NO** | **GAP** |
| Multi-language injection (100+ langs) | - | - | - | Y | - | - | **NO** | **GAP** |
| Image-based injection (OCR) | - | Y | - | - | - | - | **NO** | **GAP (P3)** |
| Indirect injection via tool output | Y | Y | Y | Y | - | - | **Y** (red team) | — |
| Jailbreak patterns (role-play, DAN) | - | Y | - | Y | - | - | **PARTIAL** (red team only) | **GAP** |
| Prompt extraction attempts | - | - | - | Y | - | - | **NO** | **GAP** |

**Score: 10/17 covered = 59%. Need 7 more for completeness.**

---

### B. Supply Chain / Package Security

| Detection | Snyk | Invariant | Microsoft | Lakera | Cisco | Pipelock | **AgentGuard** | Gap? |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|------|
| Unpinned version (npx -y pattern) | - | - | - | - | - | - | **Y** (AG-015) | — |
| Tool hash pinning (rug-pull detection) | Y | - | - | - | - | Y | **NO** | **GAP** |
| Version change alert | Y | - | - | - | Y | Y | **NO** | **GAP** |
| Registry source verification | - | - | - | - | - | - | **PARTIAL** (known packages list) | — |
| Plugin signing (Ed25519/Sigstore) | - | - | Y | - | - | - | **NO** | **GAP (P2)** |
| HTTP without TLS | - | - | - | - | - | - | **Y** (AG-015) | — |
| SLSA level classification | - | - | - | - | - | - | **Y** (AG-015) | — |
| No integrity verification detected | - | - | - | - | - | - | **Y** (AG-015) | — |
| Typosquatting detection | - | - | - | - | - | - | **NO** | **GAP** |
| Binary/archive payload scanning | - | - | - | - | Y (VT) | - | **NO** | **GAP** |

**Score: 5/10 covered = 50%. Need 5 more.**

---

### C. Secrets Detection

| Detection | Snyk | Invariant | Microsoft | Lakera | Cisco | Pipelock | **AgentGuard** | Gap? |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|------|
| AWS Access Key (AKIA) | Y | - | Y | - | - | Y | **Y** | — |
| AWS Secret Key | Y | - | Y | - | - | Y | **Y** | — |
| GitHub Token (ghp_/gho_/ghs_) | Y | - | Y | - | - | Y | **Y** | — |
| OpenAI Key (sk-) | Y | - | - | - | - | Y | **Y** | — |
| Anthropic Key (sk-ant-) | Y | - | - | - | - | Y | **Y** | — |
| Slack Token (xoxb/xoxp) | Y | - | - | - | - | Y | **Y** | — |
| Google OAuth (GOCSPX-) | Y | - | - | - | - | Y | **Y** (added today) | — |
| Stripe (sk_live) | Y | - | - | - | - | Y | **Y** | — |
| SendGrid (SG.) | Y | - | - | - | - | Y | **Y** (pattern exists) | — |
| Database URLs (postgres/mysql/mongo) | Y | - | Y | - | - | Y | **Y** | — |
| Private Keys (PEM) | Y | - | Y | - | - | Y | **Y** | — |
| Shannon entropy (unknown formats) | Y | - | - | - | - | - | **Y** | — |
| JWT tokens | Y | - | - | - | - | Y | **NO** | **GAP** |
| Bearer tokens in headers | Y | - | - | - | - | Y | **NO** | **GAP** |
| Azure connection strings | Y | - | Y | - | - | Y | **NO** | **GAP** |
| Twilio tokens | Y | - | - | - | - | Y | **NO** | **GAP** |
| Mailgun keys | Y | - | - | - | - | Y | **NO** | **GAP** |
| PII: Credit card numbers | - | Y | - | - | - | Y | **NO** | **GAP** |
| PII: Email addresses in data | - | Y | - | - | - | - | **NO** | **GAP** |
| PII: Phone numbers | - | Y | - | - | - | - | **NO** | **GAP** |
| PII: SSN/national IDs | - | Y | - | - | - | - | **NO** | **GAP** |
| JSON env block secrets | - | - | - | - | - | - | **Y** (added today) | — |
| Base64-encoded secrets | Y | - | - | - | - | - | **NO** (only entropy) | **GAP** |
| Split/obfuscated secrets | Y | - | - | - | - | - | **NO** | **GAP** |

**Score: 13/24 covered = 54%. Need 11 more.**

---

### D. Architecture / Configuration Analysis

| Detection | Snyk | Invariant | Microsoft | Lakera | Cisco | Pipelock | **AgentGuard** | Gap? |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|------|
| Unauthenticated MCP server | - | - | - | - | - | - | **Y** (AG-003) | — |
| Unencrypted transport | - | - | - | - | - | - | **Y** (AG-012) | — |
| No human-in-the-loop | - | - | Y | - | - | - | **Y** (AG-006) | — |
| No rate limiting | - | - | Y | - | - | - | **Y** (AG-010) | — |
| Unrestricted shell access | - | - | Y | - | - | - | **Y** (AG-001) | — |
| Data exfiltration path | - | - | Y | - | - | - | **Y** (AG-002) | — |
| Dangerous tool combinations | - | - | Y | - | - | - | **Y** (AG-005) | — |
| Cross-origin escalation | - | - | - | - | - | - | **Y** (AG-024) | — |
| Compositional kill chain | - | - | - | - | - | - | **Y** (AG-COMP) | — |
| Memory poisoning risk | - | - | Y | - | - | - | **Y** (AG-013) | — |
| Context overflow risk | - | - | - | - | - | - | **Y** (AG-019) | — |
| Self-modification capability | - | - | - | - | - | - | **Y** (AG-023) | — |
| Delegation without oversight | - | - | Y | - | - | - | **Y** (AG-014) | — |
| Unlimited sub-agent spawning | - | - | - | - | - | - | **Y** (AG-009) | — |
| Sensitive filesystem paths | - | - | - | - | - | - | **Y** (AG-016) | — |
| Browser credential access | - | - | - | - | - | - | **Y** (AG-017) | — |
| Tool shadowing (similar names) | - | - | Y | - | - | - | **NO** | **GAP** |
| Schema fields requesting secrets | - | - | Y | - | - | - | **PARTIAL** (schema classification) | — |
| Ambient authority (runs as root) | - | - | Y | - | - | - | **NO** | **GAP** |
| Overly broad permissions (IAM) | - | - | Y | - | - | - | **NO** | **GAP** |

**Score: 16/20 covered = 80%. Need 4 more.**

---

### E. Code Analysis (Static)

| Detection | Snyk | Invariant | Microsoft | Lakera | Cisco | Pipelock | **AgentGuard** | Gap? |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|------|
| Function body dangerous calls | - | - | - | - | - | - | **Y** (body_inspector) | — |
| subprocess/os.system/eval in tool | - | - | - | - | - | - | **Y** (body_inspector) | — |
| shell=True detection | - | - | - | - | - | - | **Y** (body_inspector) | — |
| getattr with dangerous methods | - | - | - | - | - | - | **Y** (body_inspector) | — |
| Import alias resolution | - | - | - | - | - | - | **PARTIAL** (sp.run works, aliased imports don't) | **GAP** |
| Class method body inspection | - | - | - | - | - | - | **NO** | **GAP** |
| Cross-function call resolution | - | - | - | - | - | - | **NO** | **GAP** |
| Taint tracking (source→sink) | - | Y (semgrep) | - | - | - | - | **NO** | **GAP** |
| Cross-file analysis | - | Y (semgrep) | - | - | - | - | **NO** | **GAP** |
| Data flow graph | - | Y (semgrep) | - | - | - | - | **NO** | **GAP** |

**Score: 4/10 covered = 40%. Need 6 more.**

---

### F. Framework / Platform Coverage

| Framework | Snyk | Invariant | Microsoft | Lakera | Cisco | Pipelock | **AgentGuard** | Gap? |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|------|
| MCP JSON configs | Y | - | Y | - | Y | Y | **Y** | — |
| LangChain (Tool/AgentExecutor) | - | - | Y (runtime) | - | - | - | **Y** | — |
| LangGraph (StateGraph/ToolNode) | - | - | Y (runtime) | - | - | - | **Y** | — |
| CrewAI (YAML + Python) | - | - | Y (runtime) | - | - | - | **Y** | — |
| AutoGen (AssistantAgent) | - | - | Y (runtime) | - | - | - | **Y** | — |
| OpenAI Swarm | - | - | - | - | - | - | **Y** | — |
| OpenAI Agents SDK | - | - | Y (runtime) | - | - | - | **Y** | — |
| Pydantic AI | - | - | - | - | - | - | **NO** | **GAP** |
| Google ADK | - | - | - | - | - | - | **PARTIAL** (generic) | **GAP** |
| Semantic Kernel | - | - | Y | - | - | - | **NO** | **GAP** |
| Cursor configs | Y | - | - | - | - | - | **NO** | **GAP** |
| Windsurf configs | Y | - | - | - | - | - | **NO** | **GAP** |
| Claude Desktop auto-discovery | Y | - | - | - | - | - | **PARTIAL** (manual path) | — |

**Score: 7/13 covered = 54%. Need 6 more.**

---

### G. Behavioral / Runtime (our Phase 3 — design exists, needs deployment)

| Capability | Snyk | Invariant | Microsoft | Lakera | Cisco | Pipelock | **AgentGuard** | Gap? |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|------|
| Anomaly scoring per action | - | Y | Y | - | - | - | **Y** (behavioral/scoring.py) | — |
| Baseline learning | - | Y | Y | - | - | - | **Y** (online learning) | — |
| Drift detection | - | - | Y | - | - | - | **Y** (Page-Hinkley) | — |
| Peer comparison | - | - | Y | - | - | - | **Y** (peer_comparison.py) | — |
| Sequence anomaly | - | - | - | - | - | - | **Y** (5th model) | — |
| Runtime blocking | - | Y | Y | Y | - | Y | **NO (by design — static scanner)** | N/A |
| Multi-step flow tracking | - | Y (-> ~>) | Y | - | - | - | **NO** | **GAP** |
| Rollback/compensating actions | - | - | Y | - | - | - | **NO** | **GAP (P3)** |

**Score: 5/8 = 62.5%. 2 gaps (flow tracking is P1, rollback is P3).**

---

## SUMMARY SCORECARD

| Category | Have | Need | Coverage | Priority Gaps |
|----------|:---:|:---:|:---:|---|
| A. Injection Detection | 10 | 17 | 59% | Leetspeak, ML classifier, multi-lang, jailbreak static, prompt extraction |
| B. Supply Chain | 5 | 10 | 50% | Hash pinning, version alerts, typosquatting, binary scan |
| C. Secrets | 13 | 24 | 54% | JWT, Azure, Twilio, PII (4 types), base64 secrets |
| D. Architecture | 16 | 20 | 80% | Tool shadowing, ambient authority, broad IAM |
| E. Code Analysis | 4 | 10 | 40% | Class methods, cross-function, taint, cross-file, aliases |
| F. Framework Coverage | 7 | 13 | 54% | Pydantic AI, Google ADK, Semantic Kernel, Cursor/Windsurf |
| G. Behavioral | 5 | 8 | 63% | Multi-step flow, rollback |

**OVERALL: 60/102 = 59% completeness vs market.**
**Target: 90%+ (need 32 more capabilities)**

---

## PHASE-BY-PHASE BUILD PLAN (to reach 90%)

### Phase 8A: Detection Depth (Code Analysis → 80%)
Items: 6
1. Import alias full resolution (from X import Y as Z)
2. Class method body inspection (Tool(func=MyClass.method))
3. Cross-function call resolution (tool → helper → dangerous_call)
4. Lambda in kwargs inspection (Tool(func=lambda: ...))
5. Taint tracking v1 (argument flows to dangerous call within same function)
6. Cross-file basic (resolve imports from same directory)

### Phase 8B: Injection Completeness (→ 80%)
Items: 5
1. Jailbreak patterns in static descriptions (DAN, role-play, "pretend you are")
2. Prompt extraction pattern detection ("show me your system prompt", "repeat instructions")
3. Leetspeak normalization (1337 → "leet", 3x3c → "exec")
4. Vowel folding normalization ("exct" → "execute")
5. Multi-language injection keywords (top 10 languages: Spanish, Chinese, Arabic, Hindi, etc.)

### Phase 8C: Supply Chain Completeness (→ 80%)
Items: 4
1. Tool hash pinning + rug-pull detection (hash descriptions, alert on change)
2. Version change monitoring (compare current vs previous scan)
3. Typosquatting detection (Levenshtein distance from known packages)
4. Binary payload detection (scan archives/binaries in skill files)

### Phase 8D: Secrets & PII Completeness (→ 80%)
Items: 8
1. JWT token pattern
2. Azure connection string pattern
3. Twilio auth token pattern
4. Mailgun API key pattern
5. Base64-encoded secret detection (decode and re-scan)
6. PII: Credit card (Luhn validation)
7. PII: Email addresses in configuration data
8. PII: Phone number patterns (E.164)

### Phase 8E: Framework Coverage (→ 80%)
Items: 4
1. Pydantic AI parser (@agent.tool + RunContext[Deps])
2. Google ADK full parser (Agent + sub_agents + ToolContext)
3. Cursor/Windsurf config auto-discovery
4. Semantic Kernel pattern recognition

### Phase 8F: Architecture Analysis (→ 90%)
Items: 3
1. Tool shadowing detection (similar tool names that could confuse agent)
2. Ambient authority detection (agent running as root/admin, broad IAM)
3. Custom policy rules (YAML format — user-defined detection)

### Phase 8G: Quality & Polish (→ 90%)
Items: 4
1. Duplicate parsing deduplication (bug fix)
2. Multi-step flow tracking in behavioral (-> and ~> operators)
3. FP rate measurement and published benchmark
4. Adversarial regression CI gate

**TOTAL NEW ITEMS: 34 (to go from 59% → 90% market coverage)**

---

## WHAT THIS MEANS FOR THE DEVELOPMENT PLAN

Current Phase 8 has 24 items. This analysis adds 10 more specific items.
Total Phase 8: **34 items** across 7 sub-phases (8A-8G).

After Phase 8 completion:
- Detection coverage: 59% → 90%+ of market capabilities
- Unique capabilities maintained: 5 things nobody else has
- Framework coverage: 54% → 80%+
- Evasion resistance: 37.5% → target 70%+
- Secret completeness: 54% → 80%+

**We will be strictly better than every competitor on static analysis,
while also having capabilities none of them offer.**
