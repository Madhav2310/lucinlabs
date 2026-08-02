"""Core data models for Lucin."""

from enum import Enum
from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ToolCapability(str, Enum):
    """What a tool can do."""

    READ_DATA = "read_data"
    WRITE_DATA = "write_data"
    EXECUTE_CODE = "execute_code"
    NETWORK_ACCESS = "network_access"
    FILE_SYSTEM = "file_system"
    SPAWN_PROCESS = "spawn_process"
    MODIFY_AGENT = "modify_agent"


class Tool(BaseModel):
    """Normalized representation of an agent's tool."""

    name: str
    description: str = ""
    capabilities: list[ToolCapability] = []
    parameters: dict = {}
    has_argument_filtering: bool = False
    has_sandbox: bool = False
    has_rate_limit: bool = False
    has_human_approval: bool = False
    # True when body inspection confirms ONLY read-network calls (GET/HEAD) —
    # not POST/PUT/DELETE. These tools are data sources (fetch), not egress sinks.
    # Corpus-derived (smolagents 2026-07-28): convert_currency/get_weather use
    # requests.get() — tagging them as egress sinks causes trifecta FPs.
    is_fetch_only: bool = False
    # EVIDENCE GRADE for EXECUTE_CODE — drives SEVERITY, never detection.
    #   True  = an exec sink was seen in the tool's own body (or a local/self.*
    #           callee) -> a CRITICAL claim is earned.
    #   False = the body is readable and shows NO exec -> the capability was
    #           inferred from the tool's NAME/description, so the finding is a
    #           capability suspicion, not demonstrated execution (report lower).
    #   None  = unknown (no body available: MCP/remote/description-only tools, or
    #           a parser that does not compute this) -> keep legacy severity.
    # Measured driver (81 real agent repos, 2026-07-30): name-inferred exec made
    # AG-001 the largest FP source (92/429), firing CRITICAL on
    # `printable_shell_command` (body: `oslex.join` — shell ESCAPING).
    exec_body_confirmed: bool | None = None
    source_file: str = ""
    source_line: int = 0


class MCPServer(BaseModel):
    """An MCP server connection."""

    name: str
    url: str = ""
    transport: str = "stdio"  # stdio | sse | streamable_http
    has_authentication: bool = False
    has_tls: bool = False
    tools: list[Tool] = []
    env_vars: dict[str, str] = {}   # raw env block from the MCP config (for secret scanning)


class Agent(BaseModel):
    """Normalized representation of an AI agent's capability surface."""

    name: str
    framework: str = "unknown"  # langchain | crewai | autogen | mcp | custom
    tools: list[Tool] = []
    mcp_servers: list[MCPServer] = []
    has_memory: bool = False
    can_spawn_subagents: bool = False
    has_human_in_loop: bool = False
    # Why we believe this file defines an agent (`@tool` decorator, a Tool base
    # class, an LLM client call, a tool registry, MCP config...). EMPTY means the
    # only signal was a function whose NAME looked tool-ish — the generic parser is
    # deliberately aggressive, so it "finds" an agent in build scripts, benchmark
    # harnesses, pydantic schema modules, prompt-string files and `fake_tools/`.
    # Measured on 81 real agent repos (2026-07-30): findings on such files carried
    # NO witness and scored 3 TP / 28 FP (9.7%) with 38 unadjudicable. Consumed by
    # `run_all_detectors`, which requires an evidence path before it will report a
    # HIGH/CRITICAL finding on a no-evidence "agent".
    agent_evidence: list[str] = []
    # Does this file construct an HTTP server? A SEPARATE question from "is it an
    # agent": it licenses the server-posture rules (AG-NOAUTH/AG-CORS, which judge an
    # exposed server) without claiming an agent exists. Treating them as one signal
    # made every Flask/FastAPI app an "agent" — the mislabelling a third-party
    # benchmark caught on 13 of 22 pure web apps.
    server_surface: bool = False
    source_file: str = ""

    @property
    def is_evidence_backed(self) -> bool:
        """May findings be reported here at full severity?

        Agent evidence OR a real server surface. Used by the finding gate, which asks
        "is there anything here worth judging", NOT "is this an agent".
        """
        return bool(self.agent_evidence) or self.server_surface

    @property
    def is_agent(self) -> bool:
        """Is this actually an AI agent? Used for LABELLING, never for suppression."""
        return bool(self.agent_evidence)


class Finding(BaseModel):
    """A security finding from scanning."""

    id: str  # e.g., "AG-001"
    title: str
    severity: Severity
    description: str
    agent_name: str = ""
    tool_name: str = ""
    attack_scenario: str = ""
    blast_radius: str = ""
    owasp_ref: str = ""
    fix_suggestion: str = ""
    source_file: str = ""
    source_line: int = 0
    # Proof-witness: the evidence chain that produced this finding.
    # Format depends on the finding type:
    #   - AG-TRIFECTA: ["control: src → ... → sink", "data: src → ... → sink"]
    #   - AG-001/005:  ["tool:<name> calls <sig> at line <n>"]
    #   - AG-007:      ["<var_name> matches <pattern> at line <n>"]
    # Empty for findings without a precise chain (e.g. pure capability-set checks).
    witness: list[str] = []

    # CWE identifiers, e.g. ["CWE-78", "CWE-94"]. Populated CENTRALLY in
    # `run_all_detectors` from `rule_docs.RULE_CWE`, so an individual detector cannot
    # forget to set it. Added 2026-07-30: findings carried only an OWASP-ASI
    # reference, which blocks every CWE-keyed consumer — SARIF taxonomies, most
    # enterprise pipelines, and third-party benchmarks. A RealVuln evaluation could
    # not match our findings at all without writing an external rule→CWE adapter.
    cwe: list[str] = []

    @property
    def owasp_asi(self) -> list[str]:
        """Map this finding to OWASP Agentic AI Top 10 (ASI01-ASI10) risks.

        OWASP Agentic Security Initiative Top 10 (December 2025):
        ASI01: Excessive Agency — agent acts beyond intended scope
        ASI02: Tool Misuse — tools used in unintended/harmful ways
        ASI03: Privilege Escalation — agent gains unauthorized access
        ASI04: Supply Chain — malicious tools, packages, MCP servers
        ASI05: Unexpected Code Execution — arbitrary code execution
        ASI06: Context Manipulation — poisoning context/memory/RAG
        ASI07: Memory Poisoning — corrupting persistent state
        ASI08: Data Exfiltration — unauthorized data extraction
        ASI09: Human-Agent Trust Exploitation — social engineering via agent
        ASI10: Resource Overload — DoS via resource consumption
        """
        return _map_finding_to_asi(self.id, self.owasp_ref)


# Mapping from our rule IDs to OWASP ASI risks
_RULE_TO_ASI = {
    "AG-001": ["ASI05", "ASI01"],  # Shell = Unexpected Code Exec + Excessive Agency
    "AG-002": ["ASI08"],            # Data Exfiltration
    "AG-003": ["ASI03", "ASI04"],   # Unauth MCP = Privilege Escalation + Supply Chain
    "AG-005": ["ASI01", "ASI02"],   # Dangerous combos = Excessive Agency + Tool Misuse
    "AG-006": ["ASI01"],            # No HITL = Excessive Agency
    "AG-007": ["ASI03"],            # Secrets = Privilege Escalation (credential access)
    "AG-009": ["ASI10", "ASI01"],   # Sub-agent spawning = Resource Overload + Excessive Agency
    "AG-010": ["ASI10"],            # No rate limit = Resource Overload
    "AG-011": ["ASI02", "ASI09"],   # Tool poisoning = Tool Misuse + Trust Exploitation
    "AG-012": ["ASI04"],            # Unencrypted = Supply Chain (MITM)
    "AG-013": ["ASI07", "ASI06"],   # Memory poisoning + Context Manipulation
    "AG-014": ["ASI01", "ASI03"],   # Delegation = Excessive Agency + Privilege Escalation
    "AG-015": ["ASI04"],            # Supply chain
    "AG-016": ["ASI01", "ASI03"],   # Scope violation = Excessive Agency + Privilege Escalation
    "AG-017": ["ASI03", "ASI08"],   # Credential access = Privilege Escalation + Exfil
    "AG-019": ["ASI06", "ASI10"],   # Context overflow = Context Manipulation + Resource
    "AG-021": ["ASI02", "ASI06"],   # Encoding = Tool Misuse + Context Manipulation
    "AG-023": ["ASI01", "ASI03"],   # Self-modification = Excessive Agency + Privilege Escalation
    "AG-024": ["ASI03", "ASI08"],   # Cross-origin = Privilege Escalation + Exfil
    "AG-025": ["ASI02", "ASI09"],   # Tool shadowing = Tool Misuse + Trust Exploitation
    "AG-026": ["ASI01", "ASI05"],   # Ambient authority = Excessive Agency + Code Exec
    "AG-027": ["ASI08", "ASI03"],   # Prompt leakage = Data Exfil + Privilege Escalation
    "AG-COMP": ["ASI01", "ASI08"],  # Compositional = Excessive Agency + Exfil
}


def _map_finding_to_asi(rule_id: str, owasp_ref: str) -> list[str]:
    """Map a finding to OWASP ASI risks."""
    if rule_id in _RULE_TO_ASI:
        return _RULE_TO_ASI[rule_id]
    # Fallback: parse from owasp_ref text
    mapping = []
    ref_lower = owasp_ref.lower()
    if "excessive agency" in ref_lower:
        mapping.append("ASI01")
    if "tool misuse" in ref_lower:
        mapping.append("ASI02")
    if "privilege" in ref_lower:
        mapping.append("ASI03")
    if "supply chain" in ref_lower:
        mapping.append("ASI04")
    if "code exec" in ref_lower or "unexpected" in ref_lower:
        mapping.append("ASI05")
    if "context" in ref_lower or "manipulation" in ref_lower:
        mapping.append("ASI06")
    if "memory" in ref_lower:
        mapping.append("ASI07")
    if "exfiltration" in ref_lower or "cascading" in ref_lower:
        mapping.append("ASI08")
    if "resource" in ref_lower or "overload" in ref_lower:
        mapping.append("ASI10")
    return mapping or ["ASI02"]  # Default to Tool Misuse if no mapping


class ScanMetadata(BaseModel):
    """Scan metadata — provides transparency about what was analyzed."""

    scanner_version: str = "0.2.0"
    frameworks_detected: list[str] = []
    parsers_used: int = 0
    # These three are populated by the scanner from the LIVE detector/pattern
    # registries (H4) — the defaults here are only a fallback for direct
    # construction and are intentionally 0 so a stale hardcoded number can never
    # be mistaken for a measured one.
    detection_rules_active: int = 0
    secret_patterns_active: int = 0
    injection_patterns_active: int = 0
    body_inspection_enabled: bool = True
    import_alias_resolution: bool = True
    one_hop_call_following: bool = True
    # Non-fatal errors collected during crash-isolated parsing/detection (E1).
    diagnostics: list[str] = []


class ScanResult(BaseModel):
    """Complete scan result."""

    target: str
    agents: list[Agent] = []
    findings: list[Finding] = []

    @property
    def has_evidence_backed_agent(self) -> bool:
        """Did we actually find an AI agent, or just Python that looks tool-ish?

        The generic parser is deliberately aggressive: a function merely NAMED
        `execute`/`query` makes a file look like an agent, which is right for recall
        and wrong for labelling. Measured on a third-party benchmark (2026-07-30),
        Lucin reported "agents" in 13 of 22 pure Flask/Django/FastAPI repositories
        containing no agent code at all.

        We do NOT suppress those findings — a hardcoded credential is a hardcoded
        credential, and requiring evidence before creating an agent would have cost 37
        findings across 35 of 50 recall fixtures (measured, not assumed). What we stop
        doing is *claiming an agent we cannot evidence*. Framework-parsed agents
        (langchain/crewai/mcp/...) matched on a framework import and are evidence-backed
        by construction.
        """
        return any(a.framework != "generic" or a.is_agent for a in self.agents)
    scan_duration_ms: float = 0
    metadata: ScanMetadata = ScanMetadata()

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)
