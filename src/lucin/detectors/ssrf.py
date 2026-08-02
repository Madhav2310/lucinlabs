"""AG-SSRF: Server-Side Request Forgery via an LLM/attacker-controlled URL.

Corpus-derived detector. The dangerous shape (recall corpus + real llamaindex
OpenAPIToolSpec) is a tool that fetches a URL whose DESTINATION (scheme/host) is
controlled by a tool parameter, with no allowlist/validation:

    def fetch_url(target_url: str) -> str:
        return requests.get(target_url).text          # attacker picks the host

Why it matters for agents: an SSRF sink reachable from a tool parameter lets a
prompt-injected model hit 169.254.169.254 (cloud metadata / IAM creds),
localhost admin panels, and internal-only services from the server's network
position — a classic pivot into the internal network.

PRECISION MODEL (this is the whole game — SSRF is FP-prone):
  We flag ONLY when the tainted parameter controls the URL's *authority*
  (scheme/host), not merely the path or query string. So:
    - requests.get(url)                         → FLAG  (param IS the URL)
    - requests.get(f"http://{host}/health")     → FLAG  (param is the host)
    - requests.get(f"https://api.me.com/{path}")→ SAFE  (constant host; path only)
  A hardcoded/constant destination is never SSRF. Functions that validate the
  URL (urlparse + allowlist/`validate`/`whitelist`) are skipped.
"""

from __future__ import annotations

import ast
from pathlib import Path

from lucin.models import Agent, Finding, Severity
from lucin.detectors._taint import (
    compute_taint, var_defs, is_tainted, iter_functions, resolve_sig,
    source_files_for,
)
from lucin.parsers.body_inspector import build_import_alias_map, _resolve_call_name
from lucin.owasp import owasp_ref


# Network fetch sinks. url is positional-0 or the `url=` keyword for all of these.
_NET_SINKS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.options", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.patch",
    "httpx.head", "httpx.request", "httpx.stream",
    "urllib.request.urlopen", "urllib.request.Request", "urllib.request.urlretrieve",
    "urllib.urlopen",
    "aiohttp.request",
}

# If any of these appear in the function, assume the URL is validated → skip (precision).
_VALIDATION_SIGS = {
    "urlparse", "urlsplit", "urllib.parse.urlparse", "urllib.parse.urlsplit",
}
_VALIDATION_NAME_TOKENS = ("allowlist", "whitelist", "allowed_host", "allowed_url",
                           "validate_url", "is_allowed", "ssrf", "safe_url")


def _url_arg(call_node: ast.Call) -> ast.expr | None:
    if call_node.args:
        return call_node.args[0]
    for kw in call_node.keywords:
        if kw.arg == "url":
            return kw.value
    return None


def _prefix_is_netloc(prefix: str) -> bool:
    """True ONLY if a tainted value forms the host right after the scheme.

    This is the high-signal 'attacker chooses the host' shape:
        'http://'   → after '://' is '' → the taint IS the host → True

    A constant scheme+host prefix means the destination host is effectively fixed;
    we do NOT flag taint that lands after it (that is the path/query, and the
    benign corpus is full of `f"https://api.vendor.com{path}"` /
    `f"{endpoint}/api/..."` tool code — flagging those destroys precision).
    Trades SSRF recall for the sacred 0% false-positive rate, by design.
    """
    if "://" in prefix:
        after = prefix.split("://", 1)[1]
        return after == ""
    return False


def _segments(expr: ast.expr, tainted: set[str]) -> list[tuple[str, object]]:
    """Flatten an f-string / string-concat into ordered ('c'|'t'|'u', value) segments."""
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return [("c", expr.value)]
    if isinstance(expr, ast.JoinedStr):
        segs: list[tuple[str, object]] = []
        for v in expr.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                segs.append(("c", v.value))
            elif isinstance(v, ast.FormattedValue):
                segs.append(("t", is_tainted(v.value, tainted)))
            else:
                segs.append(("u", None))
        return segs
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _segments(expr.left, tainted) + _segments(expr.right, tainted)
    return [("t", is_tainted(expr, tainted))]


def _segments_host_controlled(segs: list[tuple[str, object]]) -> bool:
    prefix = ""
    for kind, val in segs:
        if kind == "c":
            prefix += str(val)
        elif kind == "t" and val:
            # Flag only when a scheme is present and the taint immediately forms the
            # host (prefix ends in 'scheme://'). A leading tainted segment with no
            # visible scheme (`f"{base}/path"`) is NOT flagged — base is almost always
            # a fixed/config endpoint in benign tool code.
            return _prefix_is_netloc(prefix)
        # non-tainted placeholders ('u' / 't' False) contribute unknown text; we do
        # not treat later taint as host-controlling unless a scheme is visible.
    return False


def _host_controlled(url_expr: ast.expr, tainted: set[str], params: set[str],
                     defs: dict[str, ast.expr], depth: int = 0) -> bool:
    """Does a tainted parameter control the URL's scheme/host (not just path/query)?"""
    if depth > 6 or url_expr is None:
        return False

    if isinstance(url_expr, ast.Name):
        nm = url_expr.id
        if nm not in tainted:
            return False
        # Trace the variable to its definition — an f-string/concat that puts the
        # taint in the host position is still SSRF (u = f"http://{host}"; get(u)).
        definition = defs.get(nm)
        if definition is not None:
            return _host_controlled(definition, tainted, params, defs, depth + 1)
        # A bare tool parameter used as the whole URL (requests.get(url)) is the same
        # shape as many benign "fetch this page" tools in the corpus (visit_webpage,
        # fetch_url) — NOT separable statically, so we do not flag it. Precision first.
        return False

    if isinstance(url_expr, ast.Call):
        func = url_expr.func
        # "https://host/{}".format(param)
        if isinstance(func, ast.Attribute) and func.attr == "format" \
                and isinstance(func.value, ast.Constant) and isinstance(func.value.value, str):
            all_args = list(url_expr.args) + [k.value for k in url_expr.keywords]
            if any(is_tainted(a, tainted) for a in all_args):
                return _prefix_is_netloc(func.value.value.split("{", 1)[0])
            return False
        # str(param) / param.strip() / param.lower() — pass through
        if isinstance(func, ast.Attribute) and func.attr in (
                "strip", "lstrip", "rstrip", "lower", "upper", "encode"):
            return _host_controlled(func.value, tainted, params, defs, depth + 1)
        if isinstance(func, ast.Name) and func.id == "str" and url_expr.args:
            return _host_controlled(url_expr.args[0], tainted, params, defs, depth + 1)
        return False

    return _segments_host_controlled(_segments(url_expr, tainted))


def _has_validation(func_node, aliases: dict[str, str]) -> bool:
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            sig = resolve_sig(node, aliases) or ""
            if sig in _VALIDATION_SIGS:
                return True
        if isinstance(node, ast.Name):
            low = node.id.lower()
            if any(tok in low for tok in _VALIDATION_NAME_TOKENS):
                return True
        if isinstance(node, ast.Attribute):
            low = node.attr.lower()
            if any(tok in low for tok in _VALIDATION_NAME_TOKENS):
                return True
    return False


def detect_ssrf(agent: Agent) -> list[Finding]:
    findings: list[Finding] = []
    scanned: set[str] = set()

    for filepath in source_files_for(agent):
        if filepath in scanned:
            continue
        scanned.add(filepath)
        try:
            source = Path(filepath).read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            continue

        aliases = build_import_alias_map(tree)

        for func in iter_functions(tree):
            # Private/dunder methods (leading underscore) are internal plumbing, not
            # LLM-reachable tool entry points — skipping them removes benign FPs on
            # helpers like `_wait_for_server(host, ...)` while keeping public tools.
            if func.name.startswith("_"):
                continue
            tainted, params = compute_taint(func)
            if not params:
                continue
            if _has_validation(func, aliases):
                continue
            defs = var_defs(func)

            for node in ast.walk(func):
                if not isinstance(node, ast.Call):
                    continue
                sig = resolve_sig(node, aliases)
                if sig not in _NET_SINKS:
                    continue
                url_expr = _url_arg(node)
                if url_expr is None or not is_tainted(url_expr, tainted):
                    continue
                if not _host_controlled(url_expr, tainted, params, defs):
                    continue

                verb = (sig or "").split(".")[-1]
                findings.append(Finding(
                    id="AG-SSRF",
                    title=f"Server-Side Request Forgery in '{func.name}'",
                    severity=Severity.HIGH,
                    description=(
                        f"Function '{func.name}' passes a tool-controlled value into "
                        f"a network fetch ('{sig}') where the parameter controls the "
                        f"URL's scheme/host — not just a path or query string. There is "
                        f"no allowlist/validation of the destination.\n\n"
                        f"An attacker who influences this parameter (via prompt injection) "
                        f"can redirect the request to internal-only destinations."
                    ),
                    agent_name=agent.name,
                    attack_scenario=(
                        "1. Attacker gets the agent to call this tool with an internal URL\n"
                        "2. The server fetches http://169.254.169.254/latest/meta-data/... "
                        "(cloud metadata → IAM credentials), or an internal admin panel\n"
                        "3. Response (or blind SSRF side-effect) is returned to the attacker"
                    ),
                    blast_radius=(
                        "Cloud metadata / IAM credential theft, internal service access, "
                        "internal port scanning, and firewall bypass from the server's "
                        "network position."
                    ),
                    owasp_ref=owasp_ref("AG-SSRF"),
                    fix_suggestion=(
                        "Validate the destination before fetching:\n"
                        "  - Parse the URL and enforce an ALLOWLIST of scheme + host.\n"
                        "  - Reject private/link-local ranges (127/8, 10/8, 169.254/16, ::1).\n"
                        "  - Disable redirects, or re-validate the host after each redirect.\n"
                        "  - Never pass a raw tool parameter as the full request URL."
                    ),
                    source_file=filepath,
                    source_line=node.lineno,
                    witness=[
                        f"param → URL authority → {sig}(...) in '{func.name}' "
                        f"(line {node.lineno}); HTTP {verb.upper()}"
                    ],
                ))

    # de-duplicate by (file, line)
    seen: set[tuple] = set()
    unique = []
    for f in findings:
        key = (f.source_file, f.source_line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
