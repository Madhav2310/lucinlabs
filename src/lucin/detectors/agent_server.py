"""AG-CORS / AG-NOAUTH: Security misconfigurations in agent HTTP servers.

Corpus-derived detector (2026-07-28). Found in 4+ repos:
  - LangServe examples: allow_origins=["*"] in every server.py
  - AutoGen FastAPI: allow_origins=["*"] + no authentication

Two patterns:
  AG-CORS:   allow_origins=["*"] exposes the agent to cross-origin requests
             from any website — CSRF attacks, exfiltration via browser.
  AG-NOAUTH: An agent HTTP server with no authentication middleware configured.

Why this matters for agents specifically:
  - Regular web apps: CORS lets any site read API responses (bad).
  - Agent APIs: CORS lets any site INVOKE agent tools on behalf of the user —
    the agent can execute code, read files, send emails on the victim's behalf.
  - Combined with prompt injection: attacker site → open CORS → agent API →
    agent executes attacker's instructions with victim's credentials.

Real pattern: LangServe and AutoGen both ship with allow_origins=["*"] in
their official examples, and developers copy-paste this into production.
"""

import ast
import re
from pathlib import Path

from lucin.models import Agent, EvidenceClass, Finding, Severity
from lucin.owasp import owasp_ref

# Tight, single-list fallback used only when the file is not parseable Python.
# NON-greedy, NO DOTALL, and bounded to ONE bracketed list ([^\]]*) so it cannot
# span the whole file the way the old `\[.*\*.*\]` + re.DOTALL pattern did.
_CORS_WILDCARD_REGEX_FALLBACK = re.compile(
    r'allow_origins\s*=\s*\[([^\]]*)\]'
)
_STAR_LITERAL = re.compile(r'["\']\*["\']')


def _list_has_star(value: "ast.AST | None") -> bool:
    """True if an AST list literal contains a bare "*" string element."""
    return (isinstance(value, ast.List)
            and any(isinstance(e, ast.Constant) and e.value == "*"
                    for e in value.elts))


def _has_wildcard_cors(content: str) -> bool:
    """Detect `allow_origins=["*"]` precisely (E3 — replaces the greedy DOTALL
    regex that fired whenever ANY `*` sat anywhere between an `allow_origins=[`
    and a later `]` elsewhere in the file).

    AST-based: match the `allow_origins` KEYWORD argument (CORSMiddleware call)
    or a direct `allow_origins = [...]` assignment whose list literally contains
    "*". Falls back to a tight, single-list regex only when the file does not
    parse as Python.
    """
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        for m in _CORS_WILDCARD_REGEX_FALLBACK.finditer(content):
            if _STAR_LITERAL.search(m.group(1)):
                return True
        return False

    # Names bound to a list literal containing "*" (origins = ["*"]).
    star_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _list_has_star(node.value):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    star_names.add(tgt.id)

    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "allow_origins":
            if _list_has_star(node.value):
                return True
            if isinstance(node.value, ast.Name) and node.value.id in star_names:
                return True
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if (isinstance(tgt, ast.Name) and tgt.id == "allow_origins"
                        and _list_has_star(node.value)):
                    return True
    return False

_AUTH_INDICATORS = [
    "OAuth", "oauth", "Bearer", "bearer", "api_key", "APIKey",
    "HTTPBearer", "HTTPBasic", "Security(", "Depends(get_",
    "authenticate", "Authorization", "x-api-key",
    "jwt", "JWT", "token_required", "login_required",
    # Corpus-derived: AutoGen Studio uses AuthManager/AuthMiddleware in companion files
    "AuthManager", "AuthMiddleware", "AuthConfig",
    "auth_manager", "get_auth_manager",
    "from .auth", "from auth import",
]

# Indicators that a file actually CONSTRUCTS an HTTP server exposing routes.
# NOTE: bare "FastAPI"/"Flask" were REMOVED (corpus batch-5, 2026-07-29): substring
# matching fired on prose/comments ("the FastAPI server", "e.g. FastAPI to return a
# 429") and on instrumentation classes (`FastAPIInstrumentor`) in files that are NOT
# servers (nemoguardrails/telemetry.py, async_work_queue.py) — manufacturing AG-NOAUTH
# FPs. We now require an actual construction/route pattern: `FastAPI(`/`Flask(`
# instantiation, `APIRouter(`, a route decorator, or LangServe `add_routes`. Genuine
# example servers in the corpus (LangServe/AutoGen/PydanticAI/OpenAI/MetaGPT/Dify) all
# instantiate `FastAPI(`/`Flask(` or register routes, so recall on real servers holds.
_SERVER_INDICATORS = [
    "FastAPI(", "Flask(", "APIRouter(",
    "@app.post", "@app.get", "@app.put", "@app.delete",
    "@router.post", "@router.get", "@router.put", "@router.delete",
    "add_route", "add_api_route", "add_routes", "LangServe",
]


def _scan_server_file(filepath: str, agent_name: str) -> list[Finding]:
    findings = []
    path = Path(filepath)
    if not path.exists() or path.suffix != ".py":
        return findings

    try:
        content = path.read_text(encoding="utf-8")
    except Exception:
        return findings

    # Only scan files that look like HTTP server files
    is_server = any(ind in content for ind in _SERVER_INDICATORS)
    if not is_server:
        return findings

    # Check for auth in companion files (auth may be in deps.py, auth.py, middleware.py)
    # This prevents FPs when auth is correctly separated into its own module.
    has_sibling_auth = False
    for sibling_name in ("auth.py", "deps.py", "middleware.py", "security.py", "authentication.py"):
        sibling = path.parent / sibling_name
        if sibling.exists():
            try:
                sibling_content = sibling.read_text(encoding="utf-8")
                if any(ind in sibling_content for ind in _AUTH_INDICATORS):
                    has_sibling_auth = True
                    break
            except Exception:
                pass

    # AG-CORS: wildcard origin
    if _has_wildcard_cors(content):
        has_auth = any(ind in content for ind in _AUTH_INDICATORS) or has_sibling_auth
        severity = Severity.HIGH if has_auth else Severity.CRITICAL

        findings.append(Finding(
            id="AG-CORS",
            title="Agent HTTP Server: Wildcard CORS Origin",
            severity=severity,
            description=(
                f"The agent server in '{path.name}' uses `allow_origins=[\"*\"]`, "
                f"allowing any website to make cross-origin requests to the agent API.\n\n"
                f"For a regular API, open CORS enables data theft. For an agent API, "
                f"it enables any malicious website to invoke agent tools (code execution, "
                f"file access, data exfiltration) on behalf of a visiting user."
            ),
            agent_name=agent_name,
            attack_scenario=(
                "1. User visits a malicious website while logged into an app using this agent\n"
                "2. Malicious page sends requests to the agent API (CORS allows it)\n"
                "3. Agent executes tool calls with the user's session/credentials\n"
                "4. Combined with stored prompt injection: attacker can pre-plant "
                "   instructions that execute when the user's agent next runs\n\n"
                "Corpus evidence: LangServe and AutoGen ship allow_origins=[\"*\"] "
                "in their official example servers. Developers copy this to production."
            ),
            blast_radius=(
                "Any authenticated user of the agent application can have agent tools "
                "invoked on their behalf by any website. If tools include file access "
                "or code execution, this is equivalent to remote code execution on the "
                "victim's machine."
            ),
            owasp_ref=owasp_ref("AG-CORS"),
            fix_suggestion=(
                "Replace wildcard with explicit origins:\n\n"
                '  allow_origins=["https://your-app.example.com"]  # explicit allowlist\n\n'
                "Or use environment-based config:\n"
                '  allow_origins=[os.environ["ALLOWED_ORIGIN"]]\n\n'
                "Also add authentication — an open-CORS agent API with no auth is "
                "directly invocable by anyone:"
                "  app.add_middleware(HTTPSRedirectMiddleware)\n"
                "  # + add Bearer token or API key middleware"
            ),
            source_file=filepath,
            evidence_class=EvidenceClass.WITNESSED,
            witness=[f"allow_origins=[\"*\"] in {path.name}"],
        ))

    # AG-NOAUTH: server file with no auth indicators (including sibling files)
    elif is_server and not any(ind in content for ind in _AUTH_INDICATORS) and not has_sibling_auth:
        findings.append(Finding(
            id="AG-NOAUTH",
            title="Agent HTTP Server: No Authentication Configured",
            severity=Severity.HIGH,
            description=(
                f"The agent server in '{path.name}' exposes agent tools over HTTP "
                f"with no authentication middleware detected. Any process that can "
                f"reach this server can invoke agent capabilities."
            ),
            agent_name=agent_name,
            attack_scenario=(
                "Internal network attacker or SSRF vulnerability → unauthenticated "
                "agent API → invoke tools without credentials."
            ),
            blast_radius="All agent tools accessible without authentication.",
            owasp_ref=owasp_ref("AG-NOAUTH"),
            fix_suggestion=(
                "Add authentication middleware before deploying:\n"
                "  from fastapi.security import HTTPBearer\n"
                "  security = HTTPBearer()\n"
                "  @app.post('/invoke')\n"
                "  async def invoke(token: str = Depends(security)): ..."
            ),
            source_file=filepath,
        ))

    return findings


def detect_agent_server(agent: Agent) -> list[Finding]:
    """Detect CORS and auth misconfigurations in agent HTTP server files."""
    findings = []
    scanned: set[str] = set()

    sources = set()
    if agent.source_file:
        sources.add(agent.source_file)
        # Scan sibling files in the same directory (server.py often alongside agent.py)
        source_dir = Path(agent.source_file).parent
        if source_dir.exists():
            for py_file in source_dir.glob("*.py"):
                sources.add(str(py_file))

    for filepath in sources:
        if filepath in scanned:
            continue
        scanned.add(filepath)
        findings.extend(_scan_server_file(filepath, agent.name))

    return findings
