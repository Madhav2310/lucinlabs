"""AG-ENV-FALLBACK: Hardcoded secret as default value in os.getenv().

Corpus-derived detector (2026-07-28). Pattern found in AgentOps examples:
    os.environ["AGENTOPS_API_KEY"] = os.getenv("AGENTOPS_API_KEY", "your_api_key_here")
    openai.api_key = os.getenv("OPENAI_API_KEY", "sk-real-looking-key-here")

The fallback value in os.getenv() is functionally identical to hardcoding:
if the environment variable is absent (e.g., in a developer's local machine
or a misconfigured CI pipeline), the hardcoded value is used silently.

Why this escapes AG-007 (plain hardcoded secrets):
  AG-007 scans for secrets in direct assignment: `API_KEY = "sk-..."`
  This pattern wraps the secret as a function argument — AG-007's regex
  matches `sk-` in variable assignments, not inside function calls.

Severity: MEDIUM (lower than direct hardcode — the env var takes precedence
if set, so production environments may be fine; but it's still a code secret).
"""

import ast
import re
from pathlib import Path

from lucin.detectors.secrets import SECRET_PATTERNS, _is_false_positive, _mask_secret
from lucin.models import Agent, EvidenceClass, Finding, Severity
from lucin.owasp import owasp_ref


def _scan_file_for_env_fallbacks(filepath: str, agent_name: str) -> list[Finding]:
    findings = []
    try:
        source = Path(filepath).read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return findings

    for node in ast.walk(tree):
        # Pattern: os.getenv("KEY", "fallback") or os.environ.get("KEY", "fallback")
        if not isinstance(node, ast.Call):
            continue

        is_getenv = False
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("getenv", "get"):
                # os.getenv or os.environ.get
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    is_getenv = True
                elif isinstance(node.func.value, ast.Attribute):
                    # os.environ.get
                    if (isinstance(node.func.value.value, ast.Name) and
                            node.func.value.value.id == "os"):
                        is_getenv = True

        if not is_getenv:
            continue

        # Check if there's a default value (2nd positional arg or `default=` kwarg)
        default_val = None
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            default_val = str(node.args[1].value)
        for kw in node.keywords:
            if kw.arg == "default" and isinstance(kw.value, ast.Constant):
                default_val = str(kw.value.value)

        if not default_val or _is_false_positive(default_val):
            continue
        if len(default_val) < 8:
            continue  # too short to be a real secret

        # Check if the default value looks like a real secret
        matched_pattern = None
        for pat in SECRET_PATTERNS:
            if re.search(pat["pattern"], default_val):
                matched_pattern = pat
                break

        if not matched_pattern:
            continue

        masked = _mask_secret(default_val)
        findings.append(Finding(
            id="AG-ENV-FALLBACK",
            title=f"Hardcoded Secret as os.getenv() Fallback: {matched_pattern['name']}",
            severity=Severity.MEDIUM,
            description=(
                f"os.getenv() call has a hardcoded {matched_pattern['name']} as its "
                f"default value: {masked}\n\n"
                f"If the environment variable is not set (misconfigured CI, "
                f"developer's local machine, Docker container without env injection), "
                f"the hardcoded secret is used silently."
            ),
            agent_name=agent_name,
            attack_scenario=(
                "1. Developer deploys to a new environment without setting the env var\n"
                "2. os.getenv() silently returns the hardcoded fallback\n"
                "3. The hardcoded credential is used without any error or warning\n"
                "4. The credential is also visible in source code, git history, and "
                "any artifact that packages the code"
            ),
            blast_radius=(
                "Full access to whatever service the credential authenticates with. "
                "Exacerbated because failure is silent — no error, just wrong credential."
            ),
            owasp_ref=owasp_ref("AG-ENV-FALLBACK"),
            fix_suggestion=(
                "Remove the fallback entirely — fail loudly if the secret is missing:\n\n"
                "  # BAD:  api_key = os.getenv('OPENAI_API_KEY', 'sk-hardcoded-...')\n"
                "  # GOOD: api_key = os.environ['OPENAI_API_KEY']  # raises if missing\n\n"
                "Or validate at startup:\n"
                "  api_key = os.getenv('OPENAI_API_KEY')\n"
                "  if not api_key: raise ValueError('OPENAI_API_KEY not set')"
            ),
            source_file=filepath,
            source_line=node.lineno,
            evidence_class=EvidenceClass.WITNESSED,
            witness=[f"os.getenv() fallback matches {matched_pattern['name']} at line {node.lineno}"],
        ))

    return findings


def detect_secrets_fallback(agent: Agent) -> list[Finding]:
    findings = []
    scanned: set[str] = set()
    sources = set()
    if agent.source_file:
        sources.add(agent.source_file)
    for tool in agent.tools:
        if tool.source_file:
            sources.add(tool.source_file)
    for srv in agent.mcp_servers:
        # MCP configs won't be Python files — skip
        pass
    for fp in sources:
        if fp in scanned or not fp.endswith(".py"):
            continue
        scanned.add(fp)
        findings.extend(_scan_file_for_env_fallbacks(fp, agent.name))
    return findings
