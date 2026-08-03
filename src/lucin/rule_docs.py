"""Auto-generate documentation for all Lucin detection rules.

Produces markdown documentation for each AG-XXX rule including:
- What it detects
- Why it matters (real-world example)
- OWASP ASI mapping
- How to fix
- Example of vulnerable code

Usage:
    from lucin.rule_docs import generate_all_rule_docs
    docs = generate_all_rule_docs()
    Path("docs/rules.md").write_text(docs)
"""


# Complete rule catalog with documentation
# ---------------------------------------------------------------------------
# Rule -> CWE. The single source of truth, consumed centrally by
# `detectors.run_all_detectors` so no individual detector has to remember.
#
# Why this exists: findings previously carried only an OWASP-ASI reference. ASI is the
# right taxonomy for *agent* risk, but nothing else in the industry keys on it — SARIF
# taxonomies, enterprise triage pipelines and third-party benchmarks all speak CWE. A
# RealVuln evaluation of Lucin (2026-07-30) could not match a single finding without an
# externally written adapter, which is a integration defect, not a benchmark quirk.
#
# CWE-1427 ("Improper Neutralization of Input Used for an LLM Prompt") is the modern
# prompt-injection identifier and is used wherever model-directed content is the vector.
# Mappings are deliberately conservative: a rule lists a CWE only when a reasonable
# analyst would accept it, because an over-broad mapping produces false matches in
# every downstream consumer.
# ---------------------------------------------------------------------------
RULE_CWE: dict[str, list[str]] = {
    "AG-001": ["CWE-78", "CWE-94"],       # OS command injection / code injection
    "AG-002": ["CWE-200"],                # exposure of sensitive information
    "AG-003": ["CWE-306"],                # missing auth for critical function
    "AG-005": ["CWE-250"],                # execution with unnecessary privileges
    "AG-005a": ["CWE-250"],
    "AG-005b": ["CWE-250"],
    "AG-006": ["CWE-862"],                # missing authorization
    "AG-007": ["CWE-798"],                # hardcoded credentials
    "AG-009": ["CWE-770"],                # allocation without limits
    "AG-010": ["CWE-770"],
    "AG-011": ["CWE-1427", "CWE-74"],     # LLM prompt injection via tool description
    "AG-012": ["CWE-319"],                # cleartext transmission
    "AG-013": ["CWE-1427"],               # memory/RAG poisoning
    "AG-014": ["CWE-862"],
    "AG-015": ["CWE-1357"],               # reliance on untrustworthy component
    "AG-016": ["CWE-22", "CWE-732"],      # path traversal / incorrect permissions
    "AG-017": ["CWE-522"],                # insufficiently protected credentials
    "AG-019": ["CWE-770"],
    "AG-021": ["CWE-1427", "CWE-176"],    # invisible unicode → prompt injection
    "AG-023": ["CWE-913"],                # dynamically-managed code resources
    "AG-024": ["CWE-441"],                # confused deputy
    "AG-025": ["CWE-441"],                # tool shadowing
    "AG-026": ["CWE-250"],                # ambient authority
    "AG-027": ["CWE-200"],                # prompt/system-prompt leakage
    "AG-028": ["CWE-778"],                # insufficient logging
    "AG-COMP": ["CWE-250"],               # dangerous capability composition
    "AG-CORS": ["CWE-942"],               # permissive cross-domain policy
    "AG-DESERIALIZE": ["CWE-502"],        # deserialization of untrusted data
    "AG-DOCKER-EXEC": ["CWE-269", "CWE-250"],   # improper privilege management
    "AG-NOAUTH": ["CWE-306"],
    "AG-PATH-TRAVERSAL": ["CWE-22"],
    "AG-RUGPULL": ["CWE-1357", "CWE-494"],      # untrusted component / no integrity check
    "AG-SQL": ["CWE-89"],                 # SQL injection
    "AG-SSRF": ["CWE-918"],               # server-side request forgery
    "AG-TRIFECTA": ["CWE-200", "CWE-1427"],     # exfiltration steered by injection
}


def cwes_for(rule_id: str) -> list[str]:
    """CWEs for a rule ID, tolerating suffixed variants like 'AG-COMP-LATERAL'."""
    if rule_id in RULE_CWE:
        return list(RULE_CWE[rule_id])
    # longest known prefix wins, so AG-COMP-LATERAL inherits AG-COMP
    for known in sorted(RULE_CWE, key=len, reverse=True):
        if rule_id.startswith(known):
            return list(RULE_CWE[known])
    return []


RULE_CATALOG = {
    "AG-001": {
        "title": "Unrestricted Shell/Code Execution",
        "severity": "CRITICAL",
        "description": "Agent tool can execute arbitrary commands/code without sandboxing or argument filtering.",
        "real_world": "CVE-2025-54795 (Claude Code): whitelisted shell commands bypassed via argument injection.",
        "owasp_asi": ["ASI05", "ASI01"],
        "fix_summary": "Sandbox execution in Docker, add argument allowlist, require human approval.",
    },
    "AG-002": {
        "title": "Data Exfiltration Path",
        "severity": "CRITICAL",
        "description": "Agent can read sensitive data AND send it externally with no data-flow boundary.",
        "real_world": "Postmark MCP (Sep 2025): BCC on every email leaked 3,000-15,000 emails/day for a week.",
        "owasp_asi": ["ASI08"],
        "fix_summary": "Separate read and network tools into different agents, or add DLP boundary.",
    },
    "AG-003": {
        "title": "Unauthenticated MCP Server",
        "severity": "HIGH",
        "description": "MCP server accepts connections without authentication.",
        "real_world": "NSA guidance (May 2026) warns 200,000+ MCP instances are vulnerable.",
        "owasp_asi": ["ASI03", "ASI04"],
        "fix_summary": "Enable OAuth 2.1 authentication on MCP servers.",
    },
    "AG-005a": {
        "title": "Database Access + Code Execution",
        "severity": "HIGH",
        "description": "Agent can read data AND execute code — enables data theft via code execution.",
        "real_world": "Hugging Face breach, July 2026: ~17,600 agent actions using combined capabilities.",
        "owasp_asi": ["ASI02"],
        "fix_summary": "Separate into multiple agents with narrower scopes.",
    },
    "AG-005b": {
        "title": "Code Execution + Network Access",
        "severity": "HIGH",
        "description": "Agent can execute code AND access network — enables reverse shell or C2.",
        "real_world": "Hugging Face breach, July 2026: ~17,600 agent actions using combined capabilities.",
        "owasp_asi": ["ASI02"],
        "fix_summary": "Separate into multiple agents with narrower scopes.",
    },
    "AG-006": {
        "title": "No Human Approval for Destructive Actions",
        "severity": "HIGH",
        "description": "Agent can execute/write/delete without any human confirmation step.",
        "real_world": "Replit agent wiped a production database (July 2025) with no approval gate.",
        "owasp_asi": ["ASI01"],
        "fix_summary": "Add interrupt_before (LangGraph) or HumanApprovalCallbackHandler (LangChain).",
    },
    "AG-007": {
        "title": "Hardcoded Secrets",
        "severity": "HIGH",
        "description": "Credentials, API keys, or tokens found hardcoded in source/config.",
        "real_world": "Every secrets leak enables lateral movement; HuggingFace tokens stolen in 2024 breach.",
        "owasp_asi": ["ASI03"],
        "fix_summary": "Move to environment variables or secrets manager (Vault, AWS SM).",
    },
    "AG-011": {
        "title": "Tool Description Injection / Poisoning",
        "severity": "HIGH",
        "description": "Tool descriptions contain patterns consistent with prompt injection or jailbreak.",
        "real_world": "Invariant Labs (2025): demonstrated tool poisoning against WhatsApp and GitHub MCP servers.",
        "owasp_asi": ["ASI02", "ASI09"],
        "fix_summary": "Pin tool descriptions, sanitize before use, monitor for changes.",
    },
    "AG-013": {
        "title": "Memory/RAG Poisoning Risk",
        "severity": "HIGH",
        "description": "Agent has writable persistent state without integrity protections.",
        "real_world": "CORDON-MAS research: 92.4% of RAG poison attacks succeed without retrieval filtering.",
        "owasp_asi": ["ASI07", "ASI06"],
        "fix_summary": "Add retrieval-stage filtering, use hybrid retrieval, validate memory writes.",
    },
    "AG-015": {
        "title": "Supply Chain Risk",
        "severity": "HIGH",
        "description": "MCP servers installed without version pinning, integrity checks, or verification.",
        "real_world": "Postmark MCP attack (Sep 2025): npx -y auto-installed malicious version.",
        "owasp_asi": ["ASI04"],
        "fix_summary": "Pin versions (@1.2.3), use lockfiles, verify checksums.",
    },
    "AG-025": {
        "title": "Tool Shadowing",
        "severity": "MEDIUM",
        "description": "Multiple tools with suspiciously similar names that could confuse the agent.",
        "real_world": "Microsoft AGT research: similar tool names create confused deputy attacks.",
        "owasp_asi": ["ASI02", "ASI09"],
        "fix_summary": "Ensure all tool names are clearly distinct; investigate unexpected duplicates.",
    },
    "AG-026": {
        "title": "Ambient Authority",
        "severity": "CRITICAL",
        "description": "Agent runs with elevated privileges (no Docker, privileged mode, fully autonomous).",
        "real_world": "AutoGen use_docker=False: generated code runs as host user with full permissions.",
        "owasp_asi": ["ASI01", "ASI05"],
        "fix_summary": "Enable container isolation, set human_input_mode, drop privileges.",
    },
    "AG-027": {
        "title": "Prompt Leakage Risk",
        "severity": "HIGH",
        "description": "System prompt contains sensitive information extractable via prompt extraction attacks.",
        "real_world": "McKinsey Lilli breach (March 2026): system prompts leaked internal architecture.",
        "owasp_asi": ["ASI08", "ASI03"],
        "fix_summary": "Never put credentials/URLs in system prompts; use runtime config injection.",
    },
    # ---- Added 2026-07-30 --------------------------------------------------------
    # These 11 detectors shipped with only an OWASP mapping and no written guidance,
    # so `lucin explain` had nothing to say about them and the public rule index
    # deliberately refused to generate pages for them (a page restating its own title
    # helps nobody). Copy below is written from each detector's ACTUAL trigger
    # condition — thresholds are quoted from the code, not inferred from the title.
    # `real_world` names only incidents already referenced elsewhere in this repo;
    # where there is no public incident we describe the mechanism instead of
    # inventing a CVE number.
    "AG-009": {
        "title": "Unlimited Sub-Agent Spawning",
        "severity": "HIGH",
        "description": "The agent can create further agents with no cap on depth or fan-out. Each child inherits tool access, so one hijacked instruction can multiply into many actors that no single approval step ever saw.",
        "real_world": "The Hugging Face breach (July 2026) escalated because an autonomous agent kept acting — an estimated 17,600 recorded events over roughly two and a half days — with no ceiling on how much work it could initiate.",
        "owasp_asi": ["ASI08", "ASI05"],
        "fix_summary": "Cap recursion depth and total spawned agents; make the budget explicit and fail closed when it is exhausted.",
    },
    "AG-010": {
        "title": "No Rate Limiting on High-Risk Tools",
        "severity": "MEDIUM",
        "description": "A destructive or egress-capable tool has no call ceiling. Correctness is not the issue — volume is: the same tool call is harmless once and a breach ten thousand times.",
        "real_world": "Machine-speed repetition is what turns a single agent mistake into an incident; exfiltration and deletion both scale linearly with unmetered tool calls.",
        "owasp_asi": ["ASI05", "ASI10"],
        "fix_summary": "Add a per-session and per-tool call budget on destructive/egress tools, and alert on the budget rather than on each call.",
    },
    "AG-012": {
        "title": "Unencrypted MCP Transport",
        "severity": "MEDIUM",
        "description": "An MCP server is reached over plaintext (an http:// URL rather than https://). Tool descriptions, arguments and results — which routinely carry credentials and private data — cross the network unprotected.",
        "real_world": "Tool descriptions are instructions to the model, so anyone who can rewrite them in transit can steer the agent; this is the network-level form of tool poisoning.",
        "owasp_asi": ["ASI07", "ASI04"],
        "fix_summary": "Use https:// for every remote MCP server; keep stdio transports local rather than exposing them over a network.",
    },
    "AG-014": {
        "title": "Delegation Without Oversight",
        "severity": "HIGH",
        "description": "One agent hands work to another with no review at the boundary (fires only when the scan finds two or more agents). Trust is inherited silently, so a compromised upstream agent's instructions arrive downstream already authorised.",
        "real_world": "Multi-agent handoff removes the human from the loop precisely where it matters — the receiving agent cannot distinguish a legitimate task from an injected one.",
        "owasp_asi": ["ASI08", "ASI06"],
        "fix_summary": "Authenticate inter-agent messages, and validate a delegated task against the receiving agent's own policy instead of trusting the sender.",
    },
    "AG-016": {
        "title": "Coding Agent: Unrestricted File System Scope",
        "severity": "HIGH",
        "description": "A coding agent can read or write outside its project directory — reaching dotfiles, credential stores and other repositories. The blast radius is the developer's whole machine, not the checkout it was pointed at.",
        "real_world": "CVE-2025-54795 (Claude Code) showed how much reach a coding agent has once argument handling can be bent; scope is the difference between a bad edit and a leaked ~/.aws.",
        "owasp_asi": ["ASI05", "ASI02"],
        "fix_summary": "Confine the agent to the project root; deny-list credential paths (~/.ssh, ~/.aws, ~/.config, .env) and resolve symlinks before allowing access.",
    },
    "AG-017": {
        "title": "Browser Agent: Credential Store Access",
        "severity": "HIGH",
        "description": "A browser-driving agent can reach the browser profile — cookie jars, saved passwords, session tokens. Those grant authenticated access to everything the human is logged into, without any password ever being read.",
        "real_world": "A session cookie is a bearer credential: stealing it bypasses both the password and the second factor.",
        "owasp_asi": ["ASI05", "ASI04"],
        "fix_summary": "Drive a dedicated, throwaway browser profile with no saved credentials; never point an agent at the user's default profile directory.",
    },
    "AG-019": {
        "title": "Context Overflow: Multiple Unbounded Data Tools",
        "severity": "MEDIUM",
        "description": "Two or more tools can return unbounded output into the model's context (the rule fires at >=2). Attacker-controlled bulk text can then push the system prompt and safety instructions out of the effective window, and it is a cost and latency problem as well as a security one.",
        "real_world": "Instructions that fall out of the attended context stop constraining behaviour — flooding the window is the cheapest way to dilute them.",
        "owasp_asi": ["ASI01", "ASI10"],
        "fix_summary": "Truncate every tool return to an explicit maximum (`if len(result) > MAX_TOOL_OUTPUT`), and paginate rather than inlining large payloads.",
    },
    "AG-021": {
        "title": "Zero-Width Characters Detected (Invisible Content)",
        "severity": "HIGH",
        "description": "A tool description or parameter contains zero-width or invisible Unicode (checked on non-trivial strings, >50 characters). The model reads those bytes; a human reviewer does not. Two different documents, one visible and one executed.",
        "real_world": "Invisible-character prompt injection has been demonstrated publicly against multiple LLM products — the payload survives code review precisely because it renders as nothing.",
        "owasp_asi": ["ASI01", "ASI07"],
        "fix_summary": "Normalise and strip zero-width/bidi/format characters from tool metadata at load time, and diff descriptions on their normalised form.",
    },
    "AG-023": {
        "title": "Self-Modification: File Write Access to Own Source",
        "severity": "HIGH",
        "description": "The agent can write to its own code, prompts or configuration. Any injected instruction can then be made persistent, surviving the restart that would otherwise have cleared it.",
        "real_world": "Self-modification converts a one-shot injection into a durable backdoor, and it defeats incident response that assumes restarting the agent restores a known state.",
        "owasp_asi": ["ASI06", "ASI08"],
        "fix_summary": "Mount the agent's own source, prompts and config read-only; require an out-of-band change process for anything that survives a restart.",
    },
    "AG-024": {
        "title": "High Cross-Origin Risk: Many MCP Servers Connected",
        "severity": "MEDIUM",
        "description": "The agent connects to four or more MCP servers (the rule's threshold), which means N*(N-1)/2 cross-server pairs sharing one context. Any server can influence the model's handling of data belonging to any other — the confused-deputy problem, once per pair.",
        "real_world": "The Postmark MCP rug-pull (September 2025) showed that one server in a set can turn malicious after approval; the more servers share a context, the more places that matters.",
        "owasp_asi": ["ASI07", "ASI02"],
        "fix_summary": "Split unrelated MCP servers across separate agents or sessions so untrusted and sensitive origins never share one context.",
    },
    "AG-COMP": {
        "title": "Compositional Risk",
        "severity": "HIGH",
        "description": "No single tool here is dangerous; the combination is. This rule reports capability sets that compose into a known attack shape — persistence (write + memory + self-modify) or lateral movement (several reads plus network) — which is why it names a composition rather than a line of code.",
        "real_world": "Every major agent incident has been a composition rather than one bad call: read something private, be steered by something untrusted, reach something external.",
        "owasp_asi": ["ASI05", "ASI08"],
        "fix_summary": "Break the composition, not the tools: split the capability set across agents so no single context holds the whole chain. `lucin scan` reports the minimum set of tools to restrict.",
    },
    "AG-028": {
        "title": "Execution Without Telemetry/Monitoring",
        "severity": "HIGH",
        "description": "The agent has high-risk capabilities (code execution, file access, network egress) but no logging, telemetry, or monitoring is configured, so anomalous behavior can run unobserved for as long as nobody is looking.",
        "real_world": "The Hugging Face breach (July 2026): an OpenAI model escaped its ExploitGym evaluation sandbox and operated unmonitored for roughly two and a half days, taking an estimated 17,600 actions before detection.",
        "owasp_asi": ["ASI10"],
        "fix_summary": "Add observability: at minimum structured logging per tool call; ideally OpenTelemetry GenAI semantic conventions or a tracing platform (LangSmith, Langfuse).",
    },
    "AG-CORS": {
        "title": "Agent HTTP Server: Wildcard CORS Origin",
        "severity": "HIGH",
        "description": "The agent's HTTP server sets `allow_origins=[\"*\"]`. For a regular API this enables data theft; for an agent API it lets any website a logged-in user visits invoke the agent's tools — code execution, file access, data exfiltration — on that user's behalf.",
        "real_world": "LangServe and AutoGen ship `allow_origins=[\"*\"]` in their official example servers, and developers copy the example into production unchanged.",
        "owasp_asi": ["ASI03"],
        "fix_summary": "Replace the wildcard with an explicit origin allowlist, and add authentication — open CORS with no auth means anyone can invoke the agent directly.",
    },
    "AG-DESERIALIZE": {
        "title": "Insecure Deserialization",
        "severity": "CRITICAL",
        "description": "A function deserializes tool-controlled data via pickle/marshal/dill/joblib or an equivalent format that executes code or constructs arbitrary objects on load. A poisoned payload is remote code execution.",
        "real_world": "CVE-2025-68664 (\"LangGrinch\", CVSS 9.3): langchain-core's `dumps()`/`load()` allowed arbitrary object reconstruction; patched in 0.3.81 and 1.2.5.",
        "owasp_asi": ["ASI05"],
        "fix_summary": "Never deserialize untrusted data with pickle/marshal/dill/joblib. Use a data-only format (json, yaml.safe_load) or verify an HMAC/signature over the bytes before loading.",
    },
    "AG-DOCKER-EXEC": {
        "title": "Container Escape Vector: docker run",
        "severity": "CRITICAL",
        "description": "A function shells out to `docker run` with tool-controlled arguments. An attacker via prompt injection can supply arbitrary docker flags — volume mounts (`-v /:/host`), privileged mode, host networking, or a malicious image.",
        "real_world": "The pattern is generic to any agent that wraps the docker CLI rather than a constrained sandboxing API — the same class of risk as shelling out to any privileged binary with unvalidated arguments.",
        "owasp_asi": ["ASI05"],
        "fix_summary": "Remove docker-exec capability from agent tools, or use a real sandboxing API (gVisor, Firecracker). If docker is required, allowlist the image and strip -v/--privileged/--network/--cap-add.",
    },
    "AG-ENV-FALLBACK": {
        "title": "Hardcoded Secret as os.getenv() Fallback",
        "severity": "MEDIUM",
        "description": "An `os.getenv()` call has a hardcoded secret as its default value. If the environment variable is unset — a misconfigured CI job, a fresh developer machine, a container without env injection — the hardcoded credential is used silently, with no error.",
        "real_world": "A generic but common pattern in agent codebases; the credential is also visible in source, git history, and any artifact packaging the code, independent of whether the fallback ever actually fires.",
        "owasp_asi": ["ASI03"],
        "fix_summary": "Remove the fallback entirely: `os.environ['KEY']` raises if missing, which is the correct failure mode for a secret.",
    },
    "AG-FRAMEWORK-PIN": {
        "title": "Unpinned Agent Framework Dependency",
        "severity": "MEDIUM",
        "description": "An agent framework package is not pinned to an exact version. An upgrade — manual, or via a CI rebuild — can silently change tool behavior between development and production, or install a compromised release.",
        "real_world": "The LiteLLM PyPI supply-chain compromise (24 Mar 2026): versions 1.82.7/1.82.8, live for roughly 40 minutes, shipped a `.pth` autorun payload to a package with 95M monthly downloads. An unpinned `litellm` dependency is exactly the pattern this rule exists to catch.",
        "owasp_asi": ["ASI04"],
        "fix_summary": "Pin agent framework packages to exact versions, or use a lock file (`pip-compile requirements.in`).",
    },
    "AG-MCP-TOKENLEAK": {
        "title": "LLM API Key Passed to MCP Server",
        "severity": "HIGH",
        "description": "An MCP server configuration passes the user's own LLM API key into the server's environment. A compromised or malicious MCP server can then make calls under the user's account — billing, rate limits, and data exposure all happen invisibly, with no user consent step.",
        "real_world": "NSA guidance (May 2026) warned that 200,000+ MCP server instances are running with weak or absent access controls, of which credential-passing configs are a common variant.",
        "owasp_asi": ["ASI03"],
        "fix_summary": "Never pass the user's LLM API key to an MCP server. If the server needs LLM access, issue it its own scoped, rate-limited, audience-bound key (RFC 8707).",
    },
    "AG-NOAUTH": {
        "title": "Agent HTTP Server: No Authentication Configured",
        "severity": "HIGH",
        "description": "The agent exposes its tools over HTTP with no authentication middleware detected. Any process that can reach the server — an internal network attacker, or an SSRF vulnerability elsewhere — can invoke agent capabilities directly.",
        "real_world": "The same class of exposure NSA's May 2026 guidance flagged across 200,000+ MCP instances, generalized to any agent HTTP server, not just MCP specifically.",
        "owasp_asi": ["ASI03"],
        "fix_summary": "Add authentication middleware (Bearer token, API key, or OAuth) before deploying an agent HTTP server.",
    },
    "AG-PATH-TRAVERSAL": {
        "title": "Path Traversal",
        "severity": "HIGH",
        "description": "A function uses a tool-controlled path in a file read/write/delete sink with no normalization or containment check. `os.path.join` with a `..` segment does not contain the path — a parameter like `../../etc/passwd` or `../../.bashrc` escapes any intended base directory.",
        "real_world": "CVE-2026-34070 (CVSS 7.5): `langchain-core`'s `load_prompt` allowed path traversal; fixed in 1.2.22. (The function enforces a `.txt`/`.json`/`.yaml` extension allowlist, so claims of `.env` or credential-file exfiltration via this specific CVE are false — the traversal is real, the blast radius is narrower than sometimes reported.)",
        "owasp_asi": ["ASI02"],
        "fix_summary": "Resolve the path, then verify it is still inside the intended base directory (`Path.resolve()` + a prefix check) before any file operation.",
    },
    "AG-RAG-NO-SANITIZE": {
        "title": "RAG Injection: Unsanitized Vector Store Content",
        "severity": "HIGH",
        "description": "A function retrieves content from a vector store and passes it directly into an LLM call with no sanitization. This is indirect prompt injection: an attacker stores malicious instructions in any document the pipeline might retrieve, and the model cannot distinguish those instructions from legitimate content.",
        "real_world": "First demonstrated against Bing Chat (2023); the same pattern has since shown up in GPT-4 plugin attacks, ChatGPT exfiltration chains, and agent hijacks generally.",
        "owasp_asi": ["ASI06"],
        "fix_summary": "Treat retrieved content as untrusted data, not instructions — wrap it in clear delimiters, and never let it alter tool-use decisions without a human or policy check.",
    },
    "AG-SQL": {
        "title": "SQL Injection via Tool Parameter",
        "severity": "CRITICAL",
        "description": "A function passes a tool parameter directly into a SQL execution sink without parameterization. An attacker who can influence that parameter — typically via prompt injection — can send arbitrary SQL.",
        "real_world": "CVE-2025-67644 (CVSS 7.3): LangGraph's SQLite checkpointer built its `_metadata_predicate()` query via f-string interpolation rather than parameter binding; fixed in 3.0.1.",
        "owasp_asi": ["ASI05", "ASI02"],
        "fix_summary": "Use parameterized queries everywhere — never format tool parameters directly into SQL text.",
    },
    "AG-SSRF": {
        "title": "Server-Side Request Forgery",
        "severity": "HIGH",
        "description": "A function passes a tool-controlled value into a network fetch where the parameter controls the URL's scheme or host — not just a path or query string — with no allowlist or validation of the destination.",
        "real_world": "The canonical SSRF target in cloud environments is the instance metadata endpoint (`169.254.169.254`), which hands over IAM credentials to anything that can reach it — the reason this class of bug is treated as credential theft, not just an info leak.",
        "owasp_asi": ["ASI02"],
        "fix_summary": "Validate the destination against an explicit allowlist of hosts/schemes before fetching; block link-local and internal address ranges by default.",
    },
}


def generate_all_rule_docs() -> str:
    """Generate complete markdown documentation for all detection rules."""
    lines = [
        "# Lucin Detection Rules Reference",
        "",
        f"**Total rules:** {len(RULE_CATALOG)}",
        "**OWASP ASI coverage:** 9/10 risks",
        "",
        "---",
        "",
    ]

    for rule_id, info in sorted(RULE_CATALOG.items()):
        asi = ", ".join(info["owasp_asi"])
        lines.extend([
            f"## {rule_id}: {info['title']}",
            "",
            f"**Severity:** {info['severity']}",
            f"**OWASP ASI:** {asi}",
            "",
            f"**What it detects:** {info['description']}",
            "",
            f"**Real-world basis:** {info['real_world']}",
            "",
            f"**How to fix:** {info['fix_summary']}",
            "",
            "---",
            "",
        ])

    return "\n".join(lines)


def get_rule_info(rule_id: str) -> dict | None:
    """Get documentation for a specific rule."""
    return RULE_CATALOG.get(rule_id)


# ---------------------------------------------------------------------------
# Richer per-rule docs used by `lucin explain`
# ---------------------------------------------------------------------------

_EXPLAIN_DOCS: dict[str, dict] = {
    "AG-001": {
        "title": "Unrestricted Shell/Code Execution",
        "severity": "critical",
        "owasp_ref": "ASI05 - Unexpected Code Execution",
        "what_it_means": (
            "A tool in this agent can execute arbitrary shell commands or code "
            "(via subprocess.run, os.system, eval, exec, etc.) and is not sandboxed. "
            "The tool's body was inspected — this is not just a name match."
        ),
        "why_it_matters": (
            "If an attacker can inject instructions into the agent (via a poisoned "
            "document, email, or tool return), they can run any command as the agent's "
            "OS user. This is full system compromise, not a data leak. "
            "Real precedent: CVE-2025-54795 (Claude Code argument injection)."
        ),
        "how_to_fix": (
            "1. Sandbox: wrap the tool in a container with no network and limited filesystem.\n"
            "2. Allowlist: restrict the command to a known-safe set (no wildcards).\n"
            "3. Human approval: require explicit confirmation before execution.\n"
            "   → LangGraph: interrupt_before on the exec node\n"
            "   → General:   add a confirmation callback"
        ),
        "real_incident": "CVE-2025-54795: Claude Code shell argument injection (July 2025).",
        "false_positive_note": (
            "This fires on any exec tool that isn't sandboxed. If the tool deliberately "
            "runs user-provided commands (a shell tool), the finding is intentional — "
            "add a sandbox and the finding will be suppressed."
        ),
    },
    "AG-TRIFECTA": {
        "title": "Information-Flow Exfiltration Path (Lethal Trifecta)",
        "severity": "critical",
        "owasp_ref": "ASI01 - Agent Goal Hijack / ASI02 - Tool Misuse",
        "what_it_means": (
            "The agent has a provable exfiltration path: an untrusted input source "
            "can steer an egress tool (control influence), while internal/sensitive data "
            "flows into that same tool's payload (data path). This is the 'lethal trifecta' "
            "— attacker control × secret data × egress = exfiltration.\n\n"
            "The finding includes a proof-witness: the exact control-flow and data-flow "
            "chains are shown, plus the minimal set of tool restrictions that would "
            "provably break every exfiltration path."
        ),
        "why_it_matters": (
            "This is the exact pattern behind every major AI agent data breach:\n"
            "  • EchoLeak (CVE-2025-32711): zero-click Copilot exfil via injected email\n"
            "  • GitHub-MCP toxic-agent: poisoned tool description → secret exfil\n"
            "  • Supabase/Cursor: MCP token passthrough → credential leak\n"
            "The SEP benchmark proves LLMs cannot reliably separate instructions from "
            "data, so classifiers alone cannot stop this. The only provable fix is "
            "deterministic IFC enforcement at the tool boundary (CaMeL/Fides pattern)."
        ),
        "how_to_fix": (
            "Minimal fix: restrict the tools named in the min-cut (shown in the finding).\n\n"
            "Architectural fix (provably secure — CaMeL/Fides pattern):\n"
            "1. Tag all tool return values as UNTRUSTED (they may carry injected instructions).\n"
            "2. Tag data from files/DB/secrets as INTERNAL or SECRET.\n"
            "3. At every egress call: if the payload carries INTERNAL+ data AND the call\n"
            "   was triggered by UNTRUSTED input, BLOCK it — regardless of model intent.\n"
            "4. Maintain an explicit allowlist of declassified egress calls (e.g.\n"
            "   'user explicitly clicked Send' overrides the block).\n\n"
            "Short-term: add a human-approval gate on every egress tool call."
        ),
        "real_incident": (
            "EchoLeak (CVE-2025-32711, May 2025): a zero-click Copilot attack. "
            "A single rendered email exfiltrated all of a user's emails and OneDrive "
            "files to an attacker server — no user interaction beyond opening the email. "
            "Root cause: untrusted email content controlled a markdown-rendering egress "
            "call that carried session data (the lethal trifecta). "
            "Also: GitHub-MCP toxic-agent (June 2025), Supabase/Cursor MCP leak (May 2025)."
        ),
    },
    "AG-007": {
        "title": "Hardcoded Secret / Credential",
        "severity": "high",
        "owasp_ref": "A02 - Cryptographic Failures",
        "what_it_means": (
            "A secret (API key, token, private key, credential) was found hardcoded "
            "in agent source code. Detection uses exact-format regexes for known providers "
            "(OpenAI, Anthropic, AWS, GitHub, etc.) and a Shannon entropy fallback for "
            "unknown formats in secret-named variables (entropy > 4.5 bits/char, len ≥ 16)."
        ),
        "why_it_matters": (
            "Hardcoded secrets are the most common cause of credential leaks. Every git "
            "commit that contains the secret is a permanent record — even after deletion, "
            "the history remains. The Galaxy incident (July 2026) involved an agent with "
            "unrestricted API access; hardcoded credentials would have made it worse."
        ),
        "how_to_fix": (
            "Move the secret to an environment variable:\n"
            "  api_key = os.environ['OPENAI_API_KEY']  # not hardcoded\n\n"
            "Or use a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.).\n"
            "Rotate the secret immediately if it was ever committed to git."
        ),
        "false_positive_note": (
            "Two-tier FP filtering is applied: exact placeholder strings "
            "(YOUR_API_KEY, REPLACE_ME, sk-proj-FAKE, etc.) are excluded, and "
            "all-repeated-character strings are excluded. If this is a test fixture, "
            "rename the variable to avoid the secret-context pattern."
        ),
    },
    "AG-002": {
        "title": "Data Exfiltration Path",
        "severity": "high",
        "owasp_ref": "ASI02 - Tool Misuse",
        "what_it_means": (
            "The agent has both data-reading tools and network-egress tools with no "
            "boundary between them. Severity is graduated: plain READ+NETWORK is MEDIUM "
            "(common in benign agents); sensitive read (DB, files, secrets) + network "
            "is HIGH; sensitive read + exec + network is CRITICAL.\n\n"
            "For the formal IFC proof-based version of this finding, see AG-TRIFECTA."
        ),
        "why_it_matters": (
            "Without a data-flow boundary, a prompt injection can instruct the agent to "
            "read sensitive data and send it to an attacker endpoint. The agent has no "
            "way to distinguish a legitimate send from an attacker-instructed one."
        ),
        "how_to_fix": (
            "1. Separate into two agents: one that reads data (no network), one that "
            "   sends (no data access). They communicate through a trusted gateway.\n"
            "2. Add a DLP/sanitization layer between read and send.\n"
            "3. Restrict the network tool to an allowlist of known-safe destinations.\n"
            "4. Add human approval for any combined read+send operation."
        ),
    },
}


def get_rule_doc(rule_id: str) -> dict | None:
    """Get rich documentation for `lucin explain <ID>`.

    Falls back to the basic RULE_CATALOG if no rich doc exists.
    """
    if rule_id in _EXPLAIN_DOCS:
        return _EXPLAIN_DOCS[rule_id]
    # Fallback: convert basic catalog entry to explain format
    basic = RULE_CATALOG.get(rule_id)
    if not basic:
        return None
    return {
        "title": basic.get("title", rule_id),
        "severity": basic.get("severity", "").lower(),
        "owasp_ref": ", ".join(basic.get("owasp_asi", [])),
        "what_it_means": basic.get("description", ""),
        "why_it_matters": basic.get("real_world", ""),
        "how_to_fix": basic.get("fix_summary", ""),
    }
