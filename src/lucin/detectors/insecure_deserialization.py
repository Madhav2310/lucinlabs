"""AG-DESERIALIZE: insecure deserialization of untrusted-influenced bytes (CWE-502).

Deserializing attacker-influenced data with a format that can construct arbitrary
Python objects is remote code execution. In agent systems these bytes routinely
arrive from tool inputs, inter-agent messages, downloaded model artifacts, and
cache files whose path is configurable — all reachable from a parameter.

Sinks (all execute code / build arbitrary objects on load):
  - pickle.loads / pickle.load            (and cPickle / _pickle)
  - marshal.loads / marshal.load          (code-object deserialization)
  - dill.loads / dill.load                (pickle superset)
  - joblib.load                           (pickle under the hood — ML supply chain)
  - yaml.load WITHOUT SafeLoader, yaml.full_load, yaml.unsafe_load
        (yaml.safe_load and Loader=SafeLoader/CSafeLoader are SAFE and not flagged)

Corpus evidence: gptcache MapDataManager.init() → pickle.load(open(self.data_path)),
plus constructed pickle/yaml/marshal/joblib/base64-pickle cases.

PRECISION MODEL: we require the deserialized argument to be TAINTED (influenced by
a parameter, directly or through an assignment such as base64.b64decode(encoded)).
A yaml.load call is only flagged when its Loader is unsafe.
"""

from __future__ import annotations

import ast
from pathlib import Path

from lucin.detectors._taint import (
    compute_taint,
    is_tainted,
    iter_functions,
    resolve_sig,
    source_files_for,
)
from lucin.models import Agent, EvidenceClass, Finding, Severity
from lucin.owasp import owasp_ref
from lucin.parsers.body_inspector import build_import_alias_map

# Sinks that are ALWAYS unsafe on untrusted input.
_ALWAYS_UNSAFE = {
    "pickle.loads", "pickle.load",
    "cPickle.loads", "cPickle.load",
    "_pickle.loads", "_pickle.load",
    "marshal.loads", "marshal.load",
    "dill.loads", "dill.load",
    "joblib.load",
    "yaml.unsafe_load", "yaml.full_load",
}

# yaml.load is unsafe unless a Safe loader is passed.
_YAML_LOAD = "yaml.load"
_SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}


def _yaml_load_is_unsafe(call_node: ast.Call) -> bool:
    """yaml.load(x) → unsafe unless Loader is a Safe loader."""
    loader = None
    if len(call_node.args) >= 2:
        loader = call_node.args[1]
    for kw in call_node.keywords:
        if kw.arg == "Loader":
            loader = kw.value
    if loader is None:
        return True  # no loader specified → full (unsafe) loader semantics
    # Resolve the loader's attribute/name to a bare identifier.
    if isinstance(loader, ast.Attribute):
        return loader.attr not in _SAFE_YAML_LOADERS
    if isinstance(loader, ast.Name):
        return loader.id not in _SAFE_YAML_LOADERS
    return True


def detect_insecure_deserialization(agent: Agent) -> list[Finding]:
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
            # LLM-reachable tool entry points. Skipping them removes benign FPs on
            # guarded internal helpers (e.g. an opt-in `_deserialize(...)` behind an
            # allow_pickle flag) while keeping public load_* tool functions.
            if func.name.startswith("_"):
                continue
            tainted, params = compute_taint(func)
            if not params:
                continue

            for node in ast.walk(func):
                if not isinstance(node, ast.Call):
                    continue
                sig = resolve_sig(node, aliases)
                if not sig:
                    continue

                is_yaml = sig == _YAML_LOAD
                if sig not in _ALWAYS_UNSAFE and not is_yaml:
                    continue
                if is_yaml and not _yaml_load_is_unsafe(node):
                    continue

                # The deserialized payload is the first positional argument.
                if not node.args:
                    continue
                payload = node.args[0]
                if not is_tainted(payload, tainted):
                    continue

                findings.append(Finding(
                    id="AG-DESERIALIZE",
                    title=f"Insecure Deserialization in '{func.name}'",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Function '{func.name}' deserializes tool-controlled data via "
                        f"'{sig}'. This format executes code / constructs arbitrary Python "
                        f"objects on load, so a poisoned payload is remote code execution.\n\n"
                        f"The payload is influenced by a tool parameter (directly or through "
                        f"an intermediate decode/assignment)."
                    ),
                    agent_name=agent.name,
                    attack_scenario=(
                        "1. Attacker supplies a crafted blob (tool arg, inter-agent message, "
                        "poisoned model artifact, or a cache file at a configurable path)\n"
                        f"2. Agent calls {sig} on it\n"
                        "3. A __reduce__ / code-object gadget runs arbitrary code on the host"
                    ),
                    blast_radius=(
                        "Arbitrary code execution in the agent process — full host takeover, "
                        "credential theft, and lateral movement."
                    ),
                    owasp_ref=owasp_ref("AG-DESERIALIZE"),
                    fix_suggestion=(
                        "Never deserialize untrusted data with pickle/marshal/dill/joblib.\n"
                        "  - Use a data-only format: json.loads, or yaml.safe_load / "
                        "Loader=SafeLoader.\n"
                        "  - For ML artifacts prefer safetensors over pickle-based formats.\n"
                        "  - If pickle is unavoidable, verify an HMAC/signature over the bytes "
                        "from a trusted key before loading."
                    ),
                    source_file=filepath,
                    source_line=node.lineno,
                    evidence_class=EvidenceClass.WITNESSED,
            witness=[
                        f"tainted payload → {sig}(...) in '{func.name}' (line {node.lineno})"
                    ],
                ))

    seen: set[tuple] = set()
    unique = []
    for f in findings:
        key = (f.source_file, f.source_line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
