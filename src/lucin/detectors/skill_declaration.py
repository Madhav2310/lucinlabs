"""Capability-declaration reconciliation for skills.

Replaces `skill_chain.py`'s original `_is_declared`, which had three confirmed
bugs (PHASE_6_PLAN.md §2.3, §2.13.3, §5.2.3):

1. An unscoped/wildcard declaration (bare `Bash`, or `*`/`all`/`full`/`any`)
   silently counted as declaring EVERY capability — an attacker-controlled
   escape hatch that made the whole rule launder-able with one word.
2. Listing a dependency in `requirements.txt`/`package.json` counted as
   "declaring" the capability that dependency implies — so honestly declaring
   your dependencies suppressed findings instead of informing them.
3. The `compatibility` field was never actually checked, despite the old
   detector's own `fix_suggestion` text telling authors to use it.

Model, following NVIDIA/SkillSpector's LP1-LP4 split (Apache-2.0,
nodes/analyzers/mcp_least_privilege.py) rather than one tangled function:
a wildcard declaration is now its OWN finding, not a free pass on everything
else, and `compatibility` is a real (soft) channel instead of dead code.
"""
from dataclasses import dataclass, field

from lucin.models import SkillCapability

WILDCARD_TOKENS = {"*", "all", "full", "any", "bash"}

# Token (from `allowed-tools`) -> capabilities it genuinely grants. Deliberately
# does NOT include a dependency-name or stdlib-import escape hatch — those
# conflated "capability exists" with "capability was declared," which is
# circular (see module docstring point 2).
_ALLOWED_TOOLS_KEYWORDS: dict[SkillCapability, list[str]] = {
    SkillCapability.REMOTE_FETCH: ["curl", "wget", "network", "http", "fetch", "webfetch", "websearch", "axios", "request"],
    SkillCapability.EXEC: ["python", "exec", "shell", "node", "child_process"],
    SkillCapability.EGRESS: ["curl", "network", "internet", "fetch", "upload", "aws", "gcp"],
    SkillCapability.FILESYSTEM_WRITE: ["write", "edit", "file", "fs", "path", "disk"],
    SkillCapability.CREDENTIAL_READ: ["env", "secret", "credential", "dotenv", "token"],
    SkillCapability.DECODE: ["decode", "deserialize", "parse", "yaml", "pickle", "json"],
    SkillCapability.DESERIALIZE: ["decode", "deserialize", "parse", "yaml", "pickle", "json"],
}

# The `compatibility` field (spec: <=500 chars, "network access needs" etc.) is
# coarser prose, not a scoped grant — same keyword lexicon, but callers should
# treat a compatibility-only hit as weaker evidence than an allowed-tools hit
# (COVERAGE_AND_BUILD_PLAN.md §8.4/§9.3: "matching compatibility prose should
# downgrade severity, never suppress the finding").
_COMPATIBILITY_KEYWORDS = _ALLOWED_TOOLS_KEYWORDS


@dataclass
class DeclarationReport:
    """What a skill's manifest actually says, per capability, and by which channel."""
    declared_via_allowed_tools: set = field(default_factory=set)
    declared_via_compatibility: set = field(default_factory=set)
    undeclared: set = field(default_factory=set)
    has_wildcard: bool = False
    wildcard_tokens: list = field(default_factory=list)


def _has_wildcard(declared_tokens: list[str]) -> tuple[bool, list[str]]:
    hits = [t for t in declared_tokens if t.strip().lower() in WILDCARD_TOKENS]
    return bool(hits), hits


def _keyword_hit(cap: SkillCapability, text: str, table: dict) -> bool:
    keywords = table.get(cap, [])
    if any(k in text for k in keywords):
        return True
    # A *scoped* Bash grant (`Bash(git:*)`, `Bash(curl:*)`) genuinely declares
    # EXEC for that command — unlike a bare unscoped `Bash`, which is the
    # wildcard case handled separately in `_has_wildcard`/`WILDCARD_TOKENS`.
    # Without this, an author who correctly used the spec's scoped syntax
    # would be penalized relative to one who wrote nothing at all.
    if cap == SkillCapability.EXEC and "bash(" in text:
        return True
    return False


def reconcile(observed_capabilities, declared_capabilities: list[str], compatibility_text: str) -> DeclarationReport:
    """Compare observed capabilities against the two real declaration channels.

    `declared_capabilities` is the already-tokenized `allowed-tools` list
    (parsers/skill_parser.py::_parse_allowed_tools handles the spec's
    space-separated-string format). `compatibility_text` is the raw
    `compatibility` frontmatter field, or "".
    """
    report = DeclarationReport()
    has_wc, wc_tokens = _has_wildcard(declared_capabilities)
    report.has_wildcard = has_wc
    report.wildcard_tokens = wc_tokens

    at_text = " ".join(declared_capabilities).lower()
    compat_text = (compatibility_text or "").lower()

    for cap in set(observed_capabilities):
        if _keyword_hit(cap, at_text, _ALLOWED_TOOLS_KEYWORDS):
            report.declared_via_allowed_tools.add(cap)
        elif _keyword_hit(cap, compat_text, _COMPATIBILITY_KEYWORDS):
            report.declared_via_compatibility.add(cap)
        else:
            report.undeclared.add(cap)

    return report
