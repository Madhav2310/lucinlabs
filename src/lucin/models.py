"""Core data models for Lucin."""

import hashlib
import re
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

    # Set by --baseline comparison in the CLI; not part of detection itself.
    # None = no baseline was used this run. True/False = new vs. previously accepted.
    is_new: bool | None = None

    @property
    def owasp_asi(self) -> list[str]:
        """Map this finding to OWASP Top 10 for Agentic Applications (ASI01-ASI10) risks.

        See `lucin.owasp` for the authoritative code -> category table (single
        source of truth, also used to render `owasp_ref` on every Finding).
        """
        return _map_finding_to_asi(self.id, self.owasp_ref)


def _map_finding_to_asi(rule_id: str, owasp_ref: str) -> list[str]:
    """Map a finding to OWASP ASI risks, via the shared `lucin.owasp` table."""
    from lucin.owasp import RULE_TO_ASI

    if rule_id in RULE_TO_ASI:
        return list(RULE_TO_ASI[rule_id])
    # AG-005 fires with a sub-id (AG-005a / AG-005b) not tracked on Finding.id.
    if rule_id == "AG-005":
        return ["ASI02"]
    # Fallback: parse from owasp_ref text, in case a rule ID isn't in the table yet.
    mapping = []
    ref_lower = owasp_ref.lower()
    if "goal hijack" in ref_lower:
        mapping.append("ASI01")
    if "tool misuse" in ref_lower:
        mapping.append("ASI02")
    if "identity" in ref_lower or "privilege" in ref_lower:
        mapping.append("ASI03")
    if "supply chain" in ref_lower:
        mapping.append("ASI04")
    if "code execution" in ref_lower:
        mapping.append("ASI05")
    if "memory" in ref_lower or "context" in ref_lower:
        mapping.append("ASI06")
    if "inter-agent" in ref_lower:
        mapping.append("ASI07")
    if "cascading" in ref_lower:
        mapping.append("ASI08")
    if "trust exploitation" in ref_lower:
        mapping.append("ASI09")
    if "rogue" in ref_lower:
        mapping.append("ASI10")
    return mapping or ["ASI02"]  # Default to Tool Misuse if no mapping


# Back-compat alias — some modules still import this name directly.


def fingerprint(finding: Finding) -> str:
    """Stable identity for a finding across unrelated edits, for --baseline mode.

    Deliberately excludes line numbers — any edit above a finding would otherwise
    invalidate it. That includes line numbers embedded IN the witness text itself
    (e.g. "...body inspection (agent.py:10)", "...(line 18)") — several detectors
    write the line number into the witness string, not just into source_line, so
    those are stripped too before hashing.

    Includes title: several detectors (e.g. AG-007, AG-015, AG-024) emit multiple
    distinct findings for the same (id, file, tool, agent) with an empty witness —
    without the title those would collide onto one fingerprint, and a genuinely
    new one of them could be silently waved through as "accepted." Also includes
    the (line-stripped) witness so a genuinely different data-flow path in the
    same function still counts as new.
    """
    witness = " ".join(finding.witness)
    witness = re.sub(r":\d+", "", witness)              # "file.py:10" -> "file.py"
    witness = re.sub(r"\bline\s+\d+\b", "line", witness, flags=re.IGNORECASE)
    witness = " ".join(witness.split())                  # collapse whitespace
    parts = [
        finding.id,
        finding.source_file or "",
        finding.tool_name or "",
        finding.agent_name or "",
        finding.title,
        witness,
    ]
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()[:16]


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
