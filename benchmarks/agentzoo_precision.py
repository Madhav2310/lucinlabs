"""AgentZoo-style PRECISION measurement for Lucin SCAN on a BROAD, CURATED
population of real GitHub agent programs.

WHY THIS FILE EXISTS
--------------------
build_benign_corpus.py measures FP rate on a *curated-benign* 52-repo corpus
(repos selected to be benign, framework-core paths skipped, known capabilities
excused). That answers "how noisy are we on code we believe is clean?" — it is
NOT a precision number, because the denominator is pre-filtered to be benign.

AgentFlow (arXiv 2607.01640) published 73% precision by manually sampling 100 of
its prompt-to-tool findings on AgentZoo (5,399 GitHub agent programs): 73 real /
27 false. This file mirrors that methodology honestly on a DIFFERENT corpus:

  1. Assemble a BROAD, DIVERSE list of real agent programs BEYOND our curated 52
     (fresh population; no overlap with build_benign_corpus.py).
  2. Download each (archive .zip -> extract), cap ~100 Python files/repo.
  3. Scan every file, collect ALL HIGH/CRITICAL findings (a broad population, so
     we EXPECT a mix of true-positives and false-positives — that is the point).
  4. ADJUDICATE a random (fixed-seed) sample of up to 100 findings: for each,
     a human read the actual code snippet and recorded TP / FP / UNKNOWN with a
     one-line reason. Verdicts are embedded below (ADJUDICATIONS) so the exact
     precision number is reproducible and re-auditable by a third party.
  5. Precision = TP / (TP + FP) over the adjudicated sample (UNKNOWN excluded
     and reported separately). Per-detector breakdown included.

HONESTY / SCOPE
---------------
- This is a CURATED-BROAD population (hand-picked real agent repos across many
  frameworks), NOT a uniform random sample of all GitHub agent code. It is
  labeled as such. It does NOT skip framework-core paths (unlike the benign
  corpus) — that is deliberate: the broad population is where FPs live.
- No finding is auto-declared TP/FP. If the snippet is insufficient, verdict is
  UNKNOWN (excluded from precision, reported separately). We do NOT guess to
  inflate precision.
- Comparison to AgentFlow's 73% is across DIFFERENT corpora, both real agent
  programs, both manual-sample methodology. We do not claim strict comparability
  beyond that.

USAGE
-----
    venv/bin/python benchmarks/agentzoo_precision.py            # download+scan+adjudicate+report
    venv/bin/python benchmarks/agentzoo_precision.py --scan-only   # phase A only (produce sample)
    venv/bin/python benchmarks/agentzoo_precision.py --list

OUTPUTS
-------
    benchmarks/agentzoo_findings.json          # corpus manifest + ALL HIGH/CRIT findings + sampled snippets
    benchmarks/agentzoo_precision_results.json # adjudicated sample joined w/ verdicts + precision + per-detector
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.request
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from lucin.scanner import scan_target  # noqa: E402

CORPUS_DIR = ROOT / "benchmarks" / "agentzoo_corpus"
FINDINGS_FILE = ROOT / "benchmarks" / "agentzoo_findings.json"
RESULTS_FILE = ROOT / "benchmarks" / "agentzoo_precision_results.json"

FILES_PER_REPO = 100          # runtime cap, mirrors build_benign_corpus
SAMPLE_SIZE = 100             # adjudication sample size (mirrors AgentFlow's 100)
SAMPLE_SEED = 20260730        # fixed seed -> reproducible sample
DL_TIMEOUT = 90               # seconds per archive download


def _ssl_ctx() -> ssl.SSLContext:
    """Verified TLS context. See build_benign_corpus.py for the rationale."""
    import certifi
    return ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or certifi.where())


# ---------------------------------------------------------------------------
# THE BROAD CURATED POPULATION — real GitHub agent programs.
#
# Hand-curated (no GitHub search API / token available). Every entry is a repo
# the author knows to be a real agent project. Diversity over cleanliness:
# autonomous agents, coding agents, multi-agent frameworks, RAG/retrieval
# agents, browser/computer agents, voice agents, tool platforms, MCP.
#
# NONE of these overlap with build_benign_corpus.py's 52 repos (verified by the
# _assert_no_overlap() guard below). Branch is auto-resolved (main -> master).
# ---------------------------------------------------------------------------
REPOS: list[str] = [
    # --- autonomous / general agents ---
    "Significant-Gravitas/AutoGPT",
    "yoheinakajima/babyagi",
    "TransformerOptimus/SuperAGI",
    "Josh-XT/AGiXT",
    "OpenBMB/ChatDev",
    "OpenBMB/XAgent",
    "OpenBMB/AgentVerse",
    "microsoft/JARVIS",
    "frdel/agent-zero",
    "mannaandpoem/OpenManus",
    "reworkd/AgentGPT",
    "101dotxyz/GPTeam",
    "VRSEN/agency-swarm",
    "kortix-ai/suna",
    # --- coding / software-engineering agents ---
    "gpt-engineer-org/gpt-engineer",
    "Pythagora-io/gpt-pilot",
    "princeton-nlp/SWE-agent",
    "All-Hands-AI/OpenHands",
    "stitionai/devika",
    "entropy-research/Devon",
    "paul-gauthier/aider",
    "smol-ai/developer",
    "OpenBMB/RepoAgent",
    "sweepai/sweep",
    "qodo-ai/pr-agent",
    "potpie-ai/potpie",
    "shroominic/codeinterpreter-api",
    "OpenInterpreter/open-interpreter",
    # --- computer / OS / desktop agents ---
    "OthersideAI/self-operating-computer",
    "microsoft/UFO",
    # --- multi-agent frameworks / orchestration ---
    "crewAIInc/crewAI",
    "langroid/langroid",
    "agiresearch/AIOS",
    "google/adk-python",
    "awslabs/agent-squad",
    "strands-agents/sdk-python",
    "camel-ai/owl",
    "bytedance/deer-flow",
    "AgentEra/Agently",
    "julep-ai/julep",
    "superduper-io/superduper",
    "NVIDIA/NeMo-Agent-Toolkit",
    "google-deepmind/concordia",
    "THUDM/AgentBench",
    # --- RAG / retrieval / research agents ---
    "infiniflow/ragflow",
    "QuivrHQ/quivr",
    "Cinnamon/kotaemon",
    "weaviate/Verba",
    "pathwaycom/llm-app",
    "truefoundry/cognita",
    "llmware-ai/llmware",
    "stanford-oval/storm",
    "onyx-dot-app/onyx",
    "microsoft/graphrag",
    "microsoft/RD-Agent",
    "SakanaAI/AI-Scientist",
    "run-llama/rags",
    "run-llama/sec-insights",
    "langchain-ai/open_deep_research",
    "langchain-ai/opengpts",
    "langchain-ai/chat-langchain",
    # --- tool / function-calling / benchmarks ---
    "ShishirPatil/gorilla",
    "OpenBMB/ToolBench",
    # --- browser / web agents ---
    "Skyvern-AI/skyvern",
    "unclecode/crawl4ai",
    "lavague-ai/LaVague",
    # --- chatbots / assistant platforms ---
    "lm-sys/FastChat",
    "oobabooga/text-generation-webui",
    "zylon-ai/private-gpt",
    "PromtEngineer/localGPT",
    "h2oai/h2ogpt",
    "chatchat-space/Langchain-Chatchat",
    "xtekky/gpt4free",
    "dataelement/bisheng",
    # --- voice agents ---
    "pipecat-ai/pipecat",
    "vocodedev/vocode-python",
    # --- core frameworks (distinct from benign-corpus example dirs) ---
    "langchain-ai/langchain",
    "microsoft/TaskMatrix",
    "jina-ai/langchain-serve",
    "mshumer/gpt-author",
    "simonw/llm",
]


# repos used by build_benign_corpus.py (owner/repo, lowercased) — the population
# must NOT overlap. Kept here so the overlap guard is self-contained and honest.
_BENIGN_OWNER_REPO = {
    "crewaiinc/crewai-examples", "langchain-ai/langserve", "anthropics/anthropic-quickstarts",
    "pydantic/pydantic-ai", "openai/openai-agents-python", "modelcontextprotocol/servers",
    "gkamradt/langchain-tutorials", "microsoft/autogen", "agentops-ai/agentops",
    "superagent-ai/superagent", "griptape-ai/griptape", "huggingface/smolagents",
    "agno-agi/agno", "run-llama/llama_index", "mem0ai/mem0", "stanfordnlp/dspy",
    "jxnl/instructor", "deepset-ai/haystack", "microsoft/semantic-kernel",
    "langflow-ai/langflow", "chainlit/chainlit", "flowiseai/flowise", "botpress/botpress",
    "geekan/metagpt", "browser-use/browser-use", "composiohq/composio", "camel-ai/camel",
    "langgenius/dify", "openai/openai-python", "anthropics/anthropic-sdk-python",
    "modelcontextprotocol/python-sdk", "berriai/litellm", "neuml/txtai", "prefecthq/marvin",
    "letta-ai/letta", "langchain-ai/langgraph", "openai/swarm", "nvidia/nemo-guardrails",
    "microsoft/promptflow", "sinaptik-ai/pandas-ai", "dottxt-ai/outlines", "mirascope/mirascope",
    "prefecthq/controlflow", "madcowd/ell", "confident-ai/deepeval", "explodinggradients/ragas",
    "microsoft/taskweaver", "zilliztech/gptcache", "vanna-ai/vanna", "kyegomez/swarms",
    "modelscope/agentscope", "phidatahq/phidata", "assafelovic/gpt-researcher",
    "aurelio-labs/semantic-router", "argilla-io/distilabel", "guidance-ai/guidance",
}


def _assert_no_overlap() -> None:
    overlap = {r for r in REPOS if r.lower() in _BENIGN_OWNER_REPO}
    if overlap:
        raise SystemExit(f"POPULATION OVERLAP with benign corpus: {sorted(overlap)}")


# ---------------------------------------------------------------------------
# Download + extract
# ---------------------------------------------------------------------------

def _safe_name(owner_repo: str) -> str:
    return owner_repo.replace("/", "__")


def download_repo(owner_repo: str) -> dict:
    """Download a GitHub archive zip (try main, then master). Returns a dict with
    status + extracted root path. Never raises — failures are recorded honestly."""
    safe = _safe_name(owner_repo)
    extract_dir = CORPUS_DIR / safe
    rec = {"repo": owner_repo, "safe": safe}

    if extract_dir.exists():
        subs = sorted((p for p in extract_dir.iterdir() if p.is_dir()), key=lambda p: p.name)
        if subs:
            rec.update(status="cached", root=str(subs[0]), branch="cached")
            return rec

    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    for branch in ("main", "master"):
        url = f"https://github.com/{owner_repo}/archive/refs/heads/{branch}.zip"
        zip_path = CORPUS_DIR / f"{safe}.zip"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "lucin-agentzoo/1.0"})
            with urllib.request.urlopen(req, timeout=DL_TIMEOUT, context=_ssl_ctx()) as r:
                zip_path.write_bytes(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue  # try next branch
            rec.update(status="dl_error", error=f"HTTP {e.code} ({branch})")
            return rec
        except Exception as e:
            rec.update(status="dl_error", error=f"{type(e).__name__}: {e} ({branch})")
            return rec

        extract_dir.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(zip_path) as z:
                z.extractall(extract_dir)
        except Exception as e:
            rec.update(status="extract_error", error=str(e))
            zip_path.unlink(missing_ok=True)
            return rec
        zip_path.unlink(missing_ok=True)
        subs = sorted((p for p in extract_dir.iterdir() if p.is_dir()), key=lambda p: p.name)
        rec.update(status="ok", root=str(subs[0] if subs else extract_dir), branch=branch,
                   size_kb=sum(f.stat().st_size for f in extract_dir.rglob("*") if f.is_file()) // 1024)
        return rec

    rec.update(status="not_found", error="no main/master branch archive")
    return rec


# ---------------------------------------------------------------------------
# File selection — light filter (broad population; we do NOT skip framework core)
# ---------------------------------------------------------------------------

def _select_py_files(root: Path) -> list[Path]:
    skip = ("/__pycache__/", "/.git/", "/node_modules/", "/site-packages/",
            "/.egg-info/", "/test/", "/tests/", "/docs/", "/doc/", "/.venv/",
            "/venv/", "/migrations/", "/migration/")
    skip_names = {"setup.py", "conftest.py", "_version.py", "versioneer.py"}
    cands: list[Path] = []
    for p in root.rglob("*.py"):
        s = str(p).lower().replace("\\", "/")
        if any(k in s for k in skip):
            continue
        if p.name in skip_names or p.name.startswith("test_") or p.name.endswith("_test.py"):
            continue
        try:
            sz = p.stat().st_size
        except OSError:
            continue
        if not (100 < sz < 500_000):
            continue
        cands.append(p)
    cands.sort()
    if len(cands) <= FILES_PER_REPO:
        return cands
    # Even-stride sample across the (sorted) tree so the 100 files spread across
    # the repo instead of clustering in one subdir. Deterministic.
    step = len(cands) / FILES_PER_REPO
    return [cands[int(i * step)] for i in range(FILES_PER_REPO)]


def scan_repo(rec: dict) -> dict:
    """Scan up to FILES_PER_REPO files; collect findings at EVERY severity.

    Originally this kept only HIGH/CRITICAL, which made the headline metric
    unable to distinguish a finding we FIXED from one we merely RE-GRADED to
    MEDIUM — a change that lowers the HIGH/CRIT count while the user still sees
    the finding. That is precisely the way a precision number can flatter itself,
    so the harness now records every severity and `phase_a` reports the split.
    """
    out = {"repo": rec["repo"], "safe": rec["safe"], "branch": rec.get("branch")}
    root = Path(rec["root"])
    files = _select_py_files(root)
    findings = []
    errors = []
    t0 = time.time()
    for f in files:
        try:
            res = scan_target(f)
        except Exception as e:
            errors.append(f"{f.name}: {type(e).__name__}: {e}")
            continue
        for fd in res.findings:
            findings.append({
                "repo": rec["repo"],
                "abs_path": str(f),
                # The file the SCANNER attributes the weakness to, which is not always
                # the file we fed it: AG-CORS/AG-NOAUTH inspect sibling *.py files, so a
                # finding surfaced while scanning `utils.py` can legitimately point at
                # `server.py`. This harness previously recorded only the scanned path and
                # dropped `fd.source_file`, which made 11 of 13 AG-CORS findings look
                # mislocated and cost the product ~11 points of measured precision.
                "file": str(f.relative_to(root)),
                "finding_file": (
                    str(Path(fd.source_file).relative_to(root))
                    if fd.source_file and str(fd.source_file).startswith(str(root))
                    else (fd.source_file or None)
                ),
                "id": fd.id,
                "title": fd.title,
                "severity": fd.severity.value,
                "tool": fd.tool_name,
                "line": fd.source_line,
                # sorted() so the witness array is deterministic bytes across
                # processes (the scanner builds it from hash-ordered sets); this
                # also makes the all_findings sort key below fully reproducible.
                "witness": sorted(fd.witness or []),
            })
    out.update(files_scanned=len(files), findings=findings,
               errors=errors[:5], elapsed_ms=round((time.time() - t0) * 1000))
    return out


def _snippet(abs_path: str, line: int, ctx: int = 5) -> dict:
    try:
        lines = Path(abs_path).read_text(errors="replace").splitlines()
    except Exception as e:
        return {"error": str(e)}
    if line and line > 0:
        lo = max(0, line - 1 - ctx)
        hi = min(len(lines), line - 1 + ctx + 1)
    else:
        lo, hi = 0, min(len(lines), 2 * ctx + 1)
    return {"start_line": lo + 1,
            "code": "\n".join(f"{lo + i + 1:5d}| {ln}" for i, ln in enumerate(lines[lo:hi]))}


# ---------------------------------------------------------------------------
# Phase A: download + scan + build sample with snippets
# ---------------------------------------------------------------------------

def phase_a() -> dict:
    _assert_no_overlap()
    print(f"Population: {len(REPOS)} curated real agent repos (no overlap w/ benign corpus)")
    print(f"Corpus dir: {CORPUS_DIR}\n")

    # Downloads (network-bound -> threads). Cached repos short-circuit.
    dl_records: list[dict] = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for rec in ex.map(download_repo, REPOS):
            dl_records.append(rec)
            tag = rec["status"]
            extra = rec.get("error", rec.get("branch", ""))
            print(f"  [{tag:>13}] {rec['repo']:<40} {extra}")

    ok = [r for r in dl_records if r["status"] in ("ok", "cached")]
    print(f"\nDownloaded/cached: {len(ok)}/{len(REPOS)} repos. Scanning...\n")

    # Scans (CPU-bound pure-Python AST → multiprocessing, NOT serial: learning #5,
    # mirrors build_benign_corpus.py's Pool). maxtasksperchild bounds worker memory
    # on huge repos; leave 2 cores for the OS. ~10x faster on a 12-core box.
    repo_results = []
    total_files = 0
    workers = max(2, (os.cpu_count() or 4) - 2)
    with Pool(processes=workers, maxtasksperchild=4) as pool:
        for rr in pool.imap_unordered(scan_repo, ok):
            repo_results.append(rr)
            total_files += rr["files_scanned"]
            print(f"  scanned {rr['repo']:<40} {rr['files_scanned']:>3} files "
                  f"{len(rr['findings']):>3} findings  ({rr['elapsed_ms']}ms)")

    every_severity = [f for rr in repo_results for f in rr["findings"]]
    # The headline metric stays HIGH/CRIT-scoped (comparable to AgentFlow's
    # methodology and to our own earlier runs), but we now ALSO carry every
    # severity so a re-grade can never masquerade as a fix.
    all_findings = [f for f in every_severity
                    if f["severity"] in ("high", "critical")]
    # Deterministic ORDER independent of scan completion order AND of the
    # scanner's per-file hash-set emission order (which varies with
    # PYTHONHASHSEED). The key must be TOTAL (fully disambiguating) — a partial
    # key leaves ties broken by hash-randomized input order, which makes the
    # fixed-seed sample below non-reproducible. tool+title+witness complete it.
    all_findings.sort(key=lambda f: (f["repo"], f["file"], f["line"] or 0, f["id"],
                                     f["tool"] or "", f["title"] or "",
                                     "|".join(f.get("witness") or [])))

    # Per-detector totals across the WHOLE population.
    by_det = defaultdict(int)
    for f in all_findings:
        by_det[f["id"]] += 1

    # Reproducible random sample (fixed seed), mirroring AgentFlow's manual 100.
    idx = list(range(len(all_findings)))
    random.Random(SAMPLE_SEED).shuffle(idx)
    sample_idx = sorted(idx[:min(SAMPLE_SIZE, len(all_findings))])
    sample = []
    for i in sample_idx:
        f = dict(all_findings[i])
        f["key"] = f"{f['repo']}::{f['file']}::L{f['line']}::{f['id']}"
        f["snippet"] = _snippet(f["abs_path"], f["line"])
        sample.append(f)

    manifest = {
        "population_label": "curated-broad real agent repos (hand-picked, NOT a uniform random sample)",
        "n_repos_targeted": len(REPOS),
        "n_repos_downloaded": len(ok),
        "n_files_scanned": total_files,
        "files_per_repo_cap": FILES_PER_REPO,
        "sample_seed": SAMPLE_SEED,
        "sample_size": len(sample),
        "download_records": dl_records,
        "repo_findings_summary": [
            {"repo": rr["repo"], "files": rr["files_scanned"],
             "high_crit": len(rr["findings"]), "errors": rr["errors"]}
            for rr in repo_results
        ],
        "total_high_crit_findings": len(all_findings),
        # Every severity, so "did we FIX it or merely RE-GRADE it?" is answerable.
        "total_findings_all_severities": len(every_severity),
        "by_severity": {s: sum(1 for f in every_severity if f["severity"] == s)
                        for s in ("critical", "high", "medium", "low", "info")},
        "findings_all_severities": [
            {k: v for k, v in f.items() if k != "abs_path"} for f in every_severity],
        "per_detector_totals": dict(sorted(by_det.items(), key=lambda kv: -kv[1])),
        "all_findings": [{k: v for k, v in f.items() if k != "abs_path"} for f in all_findings],
        "adjudication_sample": sample,
    }
    FINDINGS_FILE.write_text(json.dumps(manifest, indent=2))
    sev = manifest["by_severity"]
    print(f"\nPhase A complete. {len(every_severity)} findings at ALL severities "
          f"({len(all_findings)} HIGH/CRIT) across {total_files} files / {len(ok)} repos.")
    print("  by severity: " + "  ".join(f"{k}={v}" for k, v in sev.items() if v))
    print(f"Sample of {len(sample)} written for adjudication -> {FINDINGS_FILE.name}")
    return manifest


# ---------------------------------------------------------------------------
# TUNING VERDICTS -- **CONTAMINATED. NEVER USE FOR A PUBLISHED PRECISION NUMBER.**
#
# These 100 verdicts adjudicated the ORIGINAL 429-finding population. The precision
# campaign then built its filters specifically to remove the FP classes these labels
# named. So any precision computed over the survivors of THIS table measures how well
# the filters hit the labels they were trained on -- train-on-test.
#
# The damage was concrete: this file printed 58% at one point and 85.7% later, and both
# were published/quoted as precision. Of these labels, 12 of 30 TP survive as HIGH/CRIT
# but only 2 of 70 FP do -- because removing them was the objective. The surviving set
# is enriched for TP by construction.
#
# Retained for provenance and for the fate table (deleted/demoted/kept) only.
# Precision is computed from HOLDOUT_ADJUDICATIONS below.
# ---------------------------------------------------------------------------
TUNING_ADJUDICATIONS: dict[str, dict] = {
    "AgentEra/Agently::agently/core/application/AgentTask/Verification.py::L2223::AG-001": {"verdict": "FP", "reason": "_terminal_evidence_projection_for_observers only builds a dict of reference ids; no exec/eval/subprocess (EXECUTE_CODE misclassified)"},  # #0 AG-001
    "Cinnamon/kotaemon::libs/ktem/ktem/index/file/pipelines.py::L0::AG-COMP": {"verdict": "FP", "reason": "RAG file-indexing pipeline persists to vector store+DB but has no agent self-modification (AG-COMP self-modify premise absent)"},  # #1 AG-COMP
    "Cinnamon/kotaemon::libs/ktem/ktem/index/file/pipelines.py::L115::AG-SQL": {"verdict": "FP", "reason": "'stmt' is a SQLAlchemy select() construct executed via session.execute(stmt) — parameterized ORM, not string SQL injection"},  # #2 AG-SQL
    "Cinnamon/kotaemon::libs/ktem/ktem/index/file/pipelines.py::L541::AG-SQL": {"verdict": "FP", "reason": "finish() runs select(self.Source).where(Source.id==file_id) — parameterized ORM select, not injection"},  # #3 AG-SQL
    "Josh-XT/AGiXT::agixt/cli.py::L0::AG-005b": {"verdict": "TP", "reason": "cli.py genuinely combines subprocess.Popen command execution (L953/982) with HTTP/token network calls"},  # #4 AG-005b
    "Josh-XT/AGiXT::agixt/cli.py::L884::AG-001": {"verdict": "TP", "reason": "execute(command, timeout, is_background) spawns subprocess.Popen — real arbitrary command execution"},  # #5 AG-001
    "Josh-XT/AGiXT::agixt/extensions/essential_abilities.py::L324::AG-001": {"verdict": "FP", "reason": "get_extension_context returns a descriptive STRING about terminal commands; the method itself does not execute code (EXECUTE_CODE misclassified)"},  # #6 AG-001
    "OpenBMB/XAgent::XAgent/running_recorder.py::L0::AG-006": {"verdict": "FP", "reason": "running_recorder writes run logs to disk; it is a recorder, not a destructive-action agent tool"},  # #7 AG-006
    "OpenBMB/XAgent::XAgent/toolserver_interface.py::L0::AG-005a": {"verdict": "FP", "reason": "toolserver_interface is a pure HTTP client (requests.post) with no database access in-file — AG-005a DB premise false"},  # #8 AG-005a
    "OpenBMB/XAgent::XAgent/toolserver_interface.py::L0::AG-005b": {"verdict": "TP", "reason": "toolserver_interface POSTs to a remote tool-execution server (/execute, upload/download) — real remote code-exec + network combination"},  # #9 AG-005b
    "OpenInterpreter/open-interpreter::codex-rs/skills/src/assets/samples/skill-installer/scripts/install-skill-from-github.py::L0::AG-006": {"verdict": "FP", "reason": "install-skill-from-github.py is a human-invoked CLI installer script (subprocess git), not an LLM-exposed autonomous tool"},  # #10 AG-006
    "OpenInterpreter/open-interpreter::codex-rs/windows-sandbox-rs/sandbox_smoketests.py::L0::AG-006": {"verdict": "FP", "reason": "sandbox_smoketests.py is a test harness ('Run a suite of smoke tests'), not agent code"},  # #11 AG-006
    "OpenInterpreter/open-interpreter::scripts/codex_package/v8.py::L0::AG-002": {"verdict": "FP", "reason": "v8.py is a Cargo build-artifact override script; no network egress present — AG-002 exfil premise absent"},  # #12 AG-002
    "OpenInterpreter/open-interpreter::scripts/just-shell.py::L0::AG-028": {"verdict": "FP", "reason": "just-shell.py is a dev 'just' recipe shell launcher (build tooling), not an agent execution surface"},  # #13 AG-028
    "ShishirPatil/gorilla::berkeley-function-call-leaderboard/bfcl_eval/eval_checker/multi_turn_eval/multi_turn_utils.py::L0::AG-028": {"verdict": "FP", "reason": "BFCL eval-checker util; execution exists but AG-028's missing-telemetry premise does not apply to an offline benchmark harness"},  # #14 AG-028
    "ShishirPatil/gorilla::berkeley-function-call-leaderboard/bfcl_eval/model_handler/local_inference/nanbeige_fc.py::L0::AG-028": {"verdict": "FP", "reason": "BFCL model handler (eval(item) for parsing); AG-028 missing-telemetry premise inapplicable to a benchmark handler"},  # #15 AG-028
    "ShishirPatil/gorilla::berkeley-function-call-leaderboard/bfcl_eval/model_handler/local_inference/qwen_fc.py::L36::AG-001": {"verdict": "TP", "reason": "decode_execute runs eval(item) on model-produced tool-call strings — genuine code execution of LLM output"},  # #16 AG-001
    "Significant-Gravitas/AutoGPT::autogpt_platform/backend/backend/copilot/bot/bot_backend.py::L0::AG-NOAUTH": {"verdict": "FP", "reason": "bot_backend is a Pyro RPC facade with no HTTP server construction; AG-NOAUTH 'HTTP server' premise false"},  # #17 AG-NOAUTH
    "Skyvern-AI/skyvern::skyvern/forge/sdk/copilot/tools/__init__.py::L0::AG-005b": {"verdict": "FP", "reason": "AG-005b exec premise rests on update_workflow_tool being EXECUTE_CODE (see #19), which is a misclassification"},  # #18 AG-005b
    "Skyvern-AI/skyvern::skyvern/forge/sdk/copilot/tools/__init__.py::L278::AG-001": {"verdict": "FP", "reason": "update_workflow_tool takes a workflow_yaml string and updates workflow config; updating YAML config is not code execution"},  # #19 AG-001
    "TransformerOptimus/SuperAGI::superagi/controllers/tool_config.py::L0::AG-NOAUTH": {"verdict": "FP", "reason": "tool_config.py DOES configure auth (fastapi_jwt_auth, Depends(check_auth) on create-or-update) — AG-NOAUTH 'no auth' is false [FP BUG]"},  # #20 AG-NOAUTH
    "TransformerOptimus/SuperAGI::superagi/helper/read_email.py::L0::AG-006": {"verdict": "FP", "reason": "read_email.clean_email_body parses/cleans email via BeautifulSoup; no destructive action"},  # #21 AG-006
    "TransformerOptimus/SuperAGI::superagi/tools/file/delete_file.py::L0::AG-006": {"verdict": "TP", "reason": "delete_file.py is a file-DELETION agent tool with no human-approval gate — genuine destructive-action-without-HITL"},  # #22 AG-006
    "VRSEN/agency-swarm::src/agency_swarm/messages/message_filter.py::L0::AG-005b": {"verdict": "FP", "reason": "message_filter removes message types; no code execution and no network (AG-005b misfire)"},  # #23 AG-005b
    "VRSEN/agency-swarm::src/agency_swarm/messages/message_filter.py::L0::AG-006": {"verdict": "FP", "reason": "message_filter is not a destructive-action tool (AG-006 misfire)"},  # #24 AG-006
    "VRSEN/agency-swarm::src/agency_swarm/ui/core/console_event_adapter.py::L295::AG-001": {"verdict": "FP", "reason": "_format_shell_call only formats and prints a shell command to the console for display; it does not execute anything"},  # #25 AG-001
    "agiresearch/AIOS::aios/tool/virtual_env/controllers/python.py::L0::AG-005b": {"verdict": "TP", "reason": "desktop-VM controller POSTs to /execute plus screenshot/terminal/file endpoints — real remote command execution + network"},  # #26 AG-005b
    "agiresearch/AIOS::aios/tool/virtual_env/providers/vmware/provider.py::L0::AG-006": {"verdict": "TP", "reason": "VMwareProvider runs subprocess.Popen and check_output(f'vmrun ...', shell=True); destructive VM control with no HITL"},  # #27 AG-006
    "bytedance/deer-flow::backend/packages/harness/deerflow/sandbox/local/local_sandbox.py::L0::AG-005b": {"verdict": "TP", "reason": "local_sandbox runs subprocess.run/Popen to execute agent code plus network — genuine exec+network combination"},  # #28 AG-005b
    "bytedance/deer-flow::backend/packages/harness/deerflow/skills/skillscan/orchestrator.py::L694::AG-001": {"verdict": "FP", "reason": "_call_shell_may_be_true is a STATIC-ANALYSIS AST checker that inspects whether a Call sets shell=True — it analyzes code, it does not execute it"},  # #29 AG-001
    "bytedance/deer-flow::backend/packages/harness/deerflow/tools/builtins/task_tool.py::L0::AG-006": {"verdict": "FP", "reason": "task_tool delegates work to subagents; delegation is not a destructive file/exec action (AG-006 premise weak)"},  # #30 AG-006
    "bytedance/deer-flow::backend/packages/harness/deerflow/tools/skill_manage_tool.py::L0::AG-006": {"verdict": "TP", "reason": "skill_manage_tool creates/evolves custom skill code on disk (shutil/tempfile) with no approval — real excessive-agency write"},  # #31 AG-006
    "bytedance/deer-flow::backend/packages/harness/deerflow/tools/skill_manage_tool.py::L0::AG-COMP": {"verdict": "TP", "reason": "skill_manage_tool self-modifies the agent's own skill set (create+evolve skills) — genuine write+self-modify composition"},  # #32 AG-COMP
    "camel-ai/owl::community_usecase/cooking-assistant/run_gpt4o.py::L0::AG-COMP": {"verdict": "FP", "reason": "owl cooking-assistant demo uses only Search+Browser toolkits; only log files written — no self-modify/memory (AG-COMP overreach)"},  # #33 AG-COMP
    "camel-ai/owl::community_usecase/learning-assistant/run_gpt4o.py::L0::AG-COMP": {"verdict": "FP", "reason": "owl learning-assistant demo uses only Search+Browser toolkits; no self-modify/memory write (AG-COMP overreach)"},  # #34 AG-COMP
    "dataelement/bisheng::src/backend/bisheng/utils/validate.py::L75::AG-001": {"verdict": "TP", "reason": "execute_function compiles and runs exec(code_obj)/exec(...) on a code string — arbitrary code execution"},  # #35 AG-001
    "entropy-research/Devon::devon_agent/agents/prompts/codegemma_prompts.py::L15::AG-001": {"verdict": "FP", "reason": "llama3_7b_history_to_bash_history formats conversation history into text (commented body); no execution — name-based misclassification"},  # #36 AG-001
    "entropy-research/Devon::devon_agent/agents/prompts/llama3_prompts.py::L0::AG-028": {"verdict": "FP", "reason": "llama3_prompts.py builds command-doc strings for prompts; no execution (AG-028 misfire)"},  # #37 AG-028
    "entropy-research/Devon::devon_agent/environments/shell_environment.py::L18::AG-001": {"verdict": "FP", "reason": "read_with_timeout reads a subprocess's stdout/stderr file descriptors; it is an I/O reader, not an exec tool"},  # #38 AG-001
    "entropy-research/Devon::devon_agent/environments/swebenchenv.py::L0::AG-006": {"verdict": "TP", "reason": "swebenchenv runs subprocess (agent shell environment) executing model commands with no HITL"},  # #39 AG-006
    "entropy-research/Devon::devon_agent/tools/utils.py::L0::AG-006": {"verdict": "TP", "reason": "devon tools/utils.py calls ctx.environment.execute(f\"cat '{file_path}'\") etc — shell exec via env with interpolated params, no HITL"},  # #40 AG-006
    "entropy-research/Devon::devon_swe_bench_experimental/agent/prompt.py::L0::AG-028": {"verdict": "FP", "reason": "prompt.py is agent prompt text/templates; no execution (AG-028 misfire)"},  # #41 AG-028
    "entropy-research/Devon::devon_swe_bench_experimental/agent/prompt.py::L246::AG-001": {"verdict": "FP", "reason": "history_to_bash_history formats history (fully commented body); no execution — name-based misclassification"},  # #42 AG-001
    "entropy-research/Devon::devon_swe_bench_experimental/environment/environment.py::L0::AG-005a": {"verdict": "TP", "reason": "environment.py runs subprocess.run(shell=True)/create_subprocess_shell on agent input — genuine shell execution"},  # #43 AG-005a
    "entropy-research/Devon::devon_swe_bench_experimental/swebenchenv/environment/utils.py::L88::AG-001": {"verdict": "FP", "reason": "read_with_timeout reads subprocess output fds; I/O reader, not an execution tool (same class as #38)"},  # #44 AG-001
    "entropy-research/Devon::devon_swe_bench_experimental/swebenchenv/environment/utils.py::L163::AG-DOCKER-EXEC": {"verdict": "TP", "reason": "_get_non_persistent_container runs `docker run` via subprocess.Popen — real container-execution/escape vector"},  # #45 AG-DOCKER-EXEC
    "google-deepmind/concordia::concordia/document/interactive_document_tools.py::L0::AG-006": {"verdict": "FP", "reason": "interactive_document tool.execute(**args) dispatches document Q&A operations (e.g. multiple_choice_question); not destructive (AG-006 premise weak)"},  # #46 AG-006
    "google-deepmind/concordia::concordia/document/interactive_document_tools.py::L352::AG-011": {"verdict": "FP", "reason": "multiple_choice_question is a benign LLM-questioning method; there is no injected/poisoned tool description (AG-011 misfire)"},  # #47 AG-011
    "h2oai/h2ogpt::openai_server/agent_tools/common/utils.py::L0::AG-006": {"verdict": "FP", "reason": "common/utils is_url_valid_and_alive + requests.get is a URL utility, not a destructive agent tool"},  # #48 AG-006
    "h2oai/h2ogpt::openai_server/agent_tools/scholar_papers_query.py::L0::AG-TRIFECTA": {"verdict": "TP", "reason": "AG-TRIFECTA: a PDF URL influenced via the LLM flows to requests.get(pdf_url) — genuine LLM-controlled fetch/exfil flow"},  # #49 AG-TRIFECTA
    "h2oai/h2ogpt::openai_server/backend_utils.py::L0::AG-COMP": {"verdict": "FP", "reason": "backend_utils does per-user upload/download keyed by auth header; file I/O helper, not agent self-modification"},  # #50 AG-COMP
    "h2oai/h2ogpt::src/create_data.py::L0::AG-005a": {"verdict": "TP", "reason": "create_data.py runs os.system('wget ...%s' % filename) with string interpolation + pickle.loads — real command-injection/exec surface"},  # #51 AG-005a
    "h2oai/h2ogpt::src/db_utils.py::L0::AG-COMP": {"verdict": "FP", "reason": "db_utils.py sqlite user store uses parameterized cursor.execute(sql,(params)); no agent self-modification (AG-COMP premise absent)"},  # #52 AG-COMP
    "h2oai/h2ogpt::src/function_client.py::L21::AG-SSRF": {"verdict": "TP", "reason": "AG-SSRF: execute_function_on_server builds url from host/port params → requests.post(url) — attacker-controllable request authority"},  # #53 AG-SSRF
    "h2oai/h2ogpt::src/function_server.py::L0::AG-CORS": {"verdict": "TP", "reason": "function_server.py sets CORSMiddleware allow_origins=['*'] (witness-confirmed) — real wildcard CORS misconfiguration"},  # #54 AG-CORS
    "h2oai/h2ogpt::src/gpt_langchain.py::L0::AG-006": {"verdict": "FP", "reason": "gpt_langchain.py is a 10k-LOC library module; subprocess/requests are incidental infra, not an LLM-invokable destructive tool (AG-006 file-level misfire)"},  # #55 AG-006
    "h2oai/h2ogpt::src/utils.py::L0::AG-006": {"verdict": "FP", "reason": "utils.py is a 3k-LOC utility lib (git subprocess, url downloads); AG-006 file-level misfire on general utilities"},  # #56 AG-006
    "infiniflow/ragflow::agent/sandbox/providers/local.py::L0::AG-006": {"verdict": "TP", "reason": "ragflow agent/sandbox/providers/local.py runs subprocess.Popen to execute agent code with no HITL"},  # #57 AG-006
    "infiniflow/ragflow::common/data_source/utils.py::L0::AG-TRIFECTA": {"verdict": "TP", "reason": "AG-TRIFECTA: connector fetch (Notion/data source) flows via the LLM to download_object over network — genuine untrusted-data→sink flow"},  # #58 AG-TRIFECTA
    "jina-ai/langchain-serve::lcserve/backend/utils.py::L0::AG-CORS": {"verdict": "TP", "reason": "jina langchain-serve gateway.py sets allow_origins=['*'] (witness-confirmed) — real wildcard CORS"},  # #59 AG-CORS
    "julep-ai/julep::julep/define.py::L0::AG-006": {"verdict": "FP", "reason": "julep define.py is a @flow authoring DSL frontend that appends graph steps, not runtime destructive work (AG-006 misfire)"},  # #60 AG-006
    "julep-ai/julep::julep/execution/projection_store.py::L1048::AG-SQL": {"verdict": "FP", "reason": "projection_store.apply_schema runs a nested execute(sql) applying fixed internal projection schema DDL; 'sql' is not an LLM/tool parameter"},  # #61 AG-SQL
    "langroid/langroid::examples/basic/python-code-exec-tool.py::L26::AG-001": {"verdict": "TP", "reason": "langroid example execute_code(code_string) literally executes Python code — real code-exec tool"},  # #62 AG-001
    "langroid/langroid::langroid/agent/chat_agent.py::L0::AG-006": {"verdict": "FP", "reason": "chat_agent.py is langroid framework core (2433 LOC, no exec/net); AG-006 file-level misfire on framework internals"},  # #63 AG-006
    "langroid/langroid::langroid/agent/chat_agent.py::L0::AG-COMP": {"verdict": "FP", "reason": "chat_agent.py framework core; AG-COMP file-level misfire on framework internals"},  # #64 AG-COMP
    "lavague-ai/LaVague::lavague-qa/lavague/qa/generator.py::L0::AG-006": {"verdict": "FP", "reason": "lavague-qa generator.py generates QA test scenario files; not a destructive-no-HITL agent tool (AG-006 misfire)"},  # #65 AG-006
    "microsoft/RD-Agent::rdagent/components/coder/factor_coder/factor.py::L107::AG-001": {"verdict": "TP", "reason": "RD-Agent factor.py execute() writes generated factor code to disk and executes it — real code execution"},  # #66 AG-001
    "microsoft/RD-Agent::rdagent/scenarios/kaggle/kaggle_crawler.py::L0::AG-005a": {"verdict": "FP", "reason": "kaggle_crawler.py downloads Kaggle data via subprocess; no database access — AG-005a DB premise false, non-agent crawler"},  # #67 AG-005a
    "microsoft/RD-Agent::rdagent/scenarios/kaggle/kaggle_crawler.py::L0::AG-COMP": {"verdict": "FP", "reason": "kaggle_crawler.py is a data crawler; no agent self-modification (AG-COMP premise absent)"},  # #68 AG-COMP
    "microsoft/TaskMatrix::LowCodeLLM/src/app.py::L0::AG-NOAUTH": {"verdict": "TP", "reason": "TaskMatrix LowCodeLLM Flask app exposes @app.route('/api/execute', POST)->llm.execute with no authentication"},  # #69 AG-NOAUTH
    "microsoft/TaskMatrix::LowCodeLLM/src/executingLLM.py::L0::AG-NOAUTH": {"verdict": "FP", "reason": "executingLLM.py is a prompt-string module (no HTTP server in this file); AG-NOAUTH misattributed — the server is in app.py"},  # #70 AG-NOAUTH
    "onyx-dot-app/onyx::backend/onyx/db/document.py::L1462::AG-SQL": {"verdict": "FP", "reason": "get_document runs select(DbDocument).where(id==document_id) — parameterized SQLAlchemy ORM, not injection"},  # #71 AG-SQL
    "onyx-dot-app/onyx::backend/onyx/db/document.py::L1690::AG-SQL": {"verdict": "FP", "reason": "get_document_updated_at uses ORM select().where(id==...); parameterized, not injection"},  # #72 AG-SQL
    "onyx-dot-app/onyx::backend/onyx/db/document.py::L1931::AG-SQL": {"verdict": "FP", "reason": "get_num_chunks_for_document uses select(...).where(DbDocument.id==document_id) — parameterized ORM, not injection"},  # #73 AG-SQL
    "onyx-dot-app/onyx::backend/onyx/tools/fake_tools/coding_agent.py::L0::AG-006": {"verdict": "FP", "reason": "onyx tools/fake_tools/coding_agent.py is a mock/test coding agent (fake_tools/); AG-006 misfire on test scaffolding"},  # #74 AG-006
    "paul-gauthier/aider::aider/utils.py::L0::AG-006": {"verdict": "FP", "reason": "aider/utils.py subprocess is a pip-install helper; AG-006 file-level misfire on a utility module"},  # #75 AG-006
    "paul-gauthier/aider::aider/utils.py::L338::AG-001": {"verdict": "FP", "reason": "printable_shell_command returns oslex.join(cmd_list) — it shell-escapes/joins into a display string; no execution"},  # #76 AG-001
    "potpie-ai/potpie::legacy/app/modules/intelligence/tools/registry/registry.py::L0::AG-006": {"verdict": "FP", "reason": "registry.py is an in-memory tool metadata store; no destructive operation (AG-006 misfire)"},  # #77 AG-006
    "potpie-ai/potpie::legacy/app/modules/intelligence/tools/registry/registry.py::L48::AG-001": {"verdict": "FP", "reason": "resolve_allow_list returns a List[str] of tool names; no code execution (EXECUTE_CODE misclassified)"},  # #78 AG-001
    "potpie-ai/potpie::legacy/app/modules/utils/gvisor_runner.py::L0::AG-NOAUTH": {"verdict": "FP", "reason": "gvisor_runner.py is a command-sandbox runner, not an HTTP server; AG-NOAUTH 'server' premise false"},  # #79 AG-NOAUTH
    "potpie-ai/potpie::legacy/app/modules/utils/gvisor_runner.py::L351::AG-DOCKER-EXEC": {"verdict": "TP", "reason": "_check_docker_available runs the `docker` binary via subprocess (part of the container-exec path) — docker-exec vector"},  # #80 AG-DOCKER-EXEC
    "potpie-ai/potpie::legacy/app/modules/utils/gvisor_runner.py::L440::AG-DOCKER-EXEC": {"verdict": "TP", "reason": "_run_with_docker_gvisor runs `docker run` to execute commands in a container — real container-exec vector"},  # #81 AG-DOCKER-EXEC
    "qodo-ai/pr-agent::pr_agent/cli.py::L0::AG-006": {"verdict": "FP", "reason": "pr-agent cli.py entrypoint posts PR review comments; AG-006 file-level misfire (no destructive-no-HITL tool)"},  # #82 AG-006
    "qodo-ai/pr-agent::pr_agent/cli.py::L83::AG-001": {"verdict": "FP", "reason": "run_command parses a fixed argparse command set (choices=commands) and calls run(); internal CLI dispatch, not shell/code exec"},  # #83 AG-001
    "qodo-ai/pr-agent::pr_agent/servers/github_action_runner.py::L0::AG-NOAUTH": {"verdict": "FP", "reason": "github_action_runner.py reads GitHub event JSON from env; it is not an HTTP server — AG-NOAUTH premise false"},  # #84 AG-NOAUTH
    "qodo-ai/pr-agent::pr_agent/servers/github_action_runner.py::L0::AG-NOAUTH": {"verdict": "FP", "reason": "duplicate of #84 (same file emitted twice) — GitHub Action runner, not an HTTP server"},  # #85 AG-NOAUTH
    "reworkd/AgentGPT::platform/reworkd_platform/web/api/agent/analysis.py::L0::AG-NOAUTH": {"verdict": "FP", "reason": "AgentGPT analysis.py defines a Pydantic BaseModel (45 LOC); no HTTP server — AG-NOAUTH misfire"},  # #86 AG-NOAUTH
    "simonw/llm::llm/cli.py::L4018::AG-001": {"verdict": "TP", "reason": "simonw/llm _tools_from_code runs exec(code_or_path, namespace) on user-supplied Python to load tools — real code execution"},  # #87 AG-001
    "smol-ai/developer::v0/main.py::L0::AG-006": {"verdict": "TP", "reason": "smol-developer main() autonomously generates and write_file()s multiple code files to disk with no human approval — excessive agency"},  # #88 AG-006
    "strands-agents/sdk-python::strands-py/src/strands/tools/executors/_executor.py::L0::AG-005b": {"verdict": "FP", "reason": "strands _executor.py is an abstract base class for tool executors (abc, no concrete exec/net); AG-005b misfire on an ABC"},  # #89 AG-005b
    "sweepai/sweep::sweepai/handlers/on_check_suite.py::L116::AG-DOCKER-EXEC": {"verdict": "TP", "reason": "sweep run_dockerfile_config runs `docker run` via subprocess (witness) — real container-exec vector"},  # #90 AG-DOCKER-EXEC
    "truefoundry/cognita::backend/server/routers/components.py::L0::AG-NOAUTH": {"verdict": "FP", "reason": "cognita components.py is a read-only APIRouter (GET list endpoints only); low-risk and auth is applied app-level — AG-NOAUTH weak/misfire"},  # #91 AG-NOAUTH
    "truefoundry/cognita::backend/server/routers/components.py::L0::AG-NOAUTH": {"verdict": "FP", "reason": "duplicate of #91 — read-only component-listing GET router"},  # #93 AG-NOAUTH
    "unclecode/crawl4ai::crawl4ai/async_crawler_strategy.py::L0::AG-002": {"verdict": "FP", "reason": "crawl4ai async_crawler_strategy.py is a Playwright crawler; no data-egress sink in-file — AG-002 exfil premise absent"},  # #94 AG-002
    "unclecode/crawl4ai::crawl4ai/model_loader.py::L0::AG-002": {"verdict": "FP", "reason": "crawl4ai model_loader.py downloads/loads ML models (ingress); AG-002 exfil premise absent"},  # #95 AG-002
    "unclecode/crawl4ai::crawl4ai/model_loader.py::L0::AG-COMP": {"verdict": "FP", "reason": "crawl4ai model_loader.py is a model downloader; no agent self-modification (AG-COMP premise absent)"},  # #96 AG-COMP
    "xtekky/gpt4free::g4f/mcp/pa_downloader.py::L0::AG-002": {"verdict": "FP", "reason": "gpt4free pa_downloader.py downloads provider files from GitHub (ingress); AG-002 exfiltration premise absent"},  # #97 AG-002
    "zylon-ai/private-gpt::private_gpt/components/engines/chat/chat_engine.py::L738::AG-001": {"verdict": "FP", "reason": "_close_active_tool_block orchestrates streaming tool-call blocks (emits events, builds ToolSelection); no code execution (EXECUTE_CODE misclassified)"},  # #98 AG-001
    "zylon-ai/private-gpt::private_gpt/components/skills/repositories/skill_repository.py::L420::AG-SQL": {"verdict": "FP", "reason": "_skill_exists runs select(SkillORM.id).where(id==skill_id, collection==collection) — parameterized ORM select, not injection"},  # #99 AG-SQL
}


# ---------------------------------------------------------------------------
# CLEAN HOLDOUT VERDICTS -- the only table precision may be computed from.
#
# Every key here had NO verdict in TUNING_ADJUDICATIONS, so no label below influenced
# the design of any detector or filter. Criteria were fixed in advance:
#   benchmarks/ADJUDICATION_RUBRIC.md
# key -> {"verdict": "TP"|"FP"|"UNKNOWN", "reason": "<grounded in code, cites file:line>"}
# ---------------------------------------------------------------------------
HOLDOUT_ADJUDICATIONS: dict[str, dict] = {
    "AgentEra/Agently::examples/agent_task/agently_architecture_diagram_task.py::L160::AG-007": {"verdict": "FP", "reason": "L160 is Agently.create_agent(...) — no key literal anywhere in the file; key comes from os.getenv('DEEPSEEK_API_KEY') (_business_example_common.py:35). No secret, and an examples/ script."},  # AG-007
    "Josh-XT/AGiXT::agixt/cli.py::L1270::AG-SQL": {"verdict": "FP", "reason": "The 'SQL sink' is session.execute(command,...) at cli.py:1295 -> subprocess.Popen(['/bin/bash','-c',command]) cli.py:949/982. No SQL or DB code in the path; misidentified sink."},  # AG-SQL
    "Josh-XT/AGiXT::agixt/cli.py::L2583::AG-001": {"verdict": "FP", "reason": "cli.py:2583 run_shell_command has ZERO callers repo-wide (grep -rn run_shell_command = only the def); cli.py is an argparse server-management CLI (cli.py:1-40, __main__ at 4985). Dead human-only code."},  # AG-001
    "Josh-XT/AGiXT::agixt/cli.py::L3424::AG-DOCKER-EXEC": {"verdict": "FP", "reason": "cli.py:3455-3474 docker run args all literals (redis:alpine, -p, -v data dir), no escape flags; container runs redis-server, not agent code. Human argparse CLI (cli.py:3915)."},  # AG-DOCKER-EXEC
    "OpenBMB/ChatDev::functions/function_calling/code_executor.py::L1::AG-001": {"verdict": "TP", "reason": "code_executor.py:35-47 writes the LLM-supplied `code` param to a temp .py and runs sys.executable on it, no sandbox/allowlist. utils/function_catalog.py:37 turns functions/function_calling/*.py into LLM tool schemas."},  # AG-001
    "OpenBMB/XAgent::XAgent/toolserver_interface.py::L0::AG-TRIFECTA": {"verdict": "FP", "reason": "Egress leg misidentified: unwrap_tool_response (toolserver_interface.py:29-56) only writes base64 to a local file; download_all_files (:157-173) POSTs to the configured toolserver. No exfil sink."},  # AG-TRIFECTA
    "OpenInterpreter/open-interpreter::codex-cli/scripts/build_npm_package.py::L327::AG-001": {"verdict": "FP", "reason": "Human-run build script (argparse main at build_npm_package.py:91/450); run_command's only callers pass literal argv ['pnpm',...] at :335-336. No agent surface."},  # AG-001
    "OpenInterpreter/open-interpreter::scripts/stage_npm_packages.py::L469::AG-001": {"verdict": "FP", "reason": "Human release CLI (argparse L87, __main__ L603); run_command:471 is subprocess.run(list, no shell) with cmd built from literals/paths L540-573. Build tooling, not agent-exposed."},  # AG-001
    "ShishirPatil/gorilla::berkeley-function-call-leaderboard/bfcl_eval/eval_checker/multi_turn_eval/multi_turn_utils.py::L13::AG-001": {"verdict": "TP", "reason": "eval(func_call) at multi_turn_utils.py:83 runs decoded_model_responses passed in at base_handler.py:296/588; denylist L75-81 tests only the outer name, so __import__ bypasses it."},  # AG-001
    "ShishirPatil/gorilla::berkeley-function-call-leaderboard/bfcl_eval/model_handler/local_inference/arch.py::L157::AG-001": {"verdict": "TP", "reason": "arch.py:171 eval(item) on raw model output: api_response text (158) -> extract_tool_calls (198-208) leaves non-JSON matches as str -> eval. LLM-controlled code exec in shipped bfcl_eval pkg."},  # AG-001
    "ShishirPatil/gorilla::berkeley-function-call-leaderboard/bfcl_eval/model_handler/local_inference/granite_4.py::L27::AG-011": {"verdict": "FP", "reason": "granite_4.py:28-147 is a copied Jinja chat template inside _format_prompt's docstring in a BFCL eval model handler. No tool description, no filesystem access, no jailbreak text."},  # AG-011
    "ShishirPatil/gorilla::berkeley-function-call-leaderboard/bfcl_eval/model_handler/local_inference/granite_4.py::L320::AG-001": {"verdict": "FP", "reason": "granite_4.py:322 raises if any item is not a dict, so the `type(item)==str` branch guarding eval() at :327 is unreachable dead code. Also an offline leaderboard eval decoder (base_handler.py:262), not an agent tool."},  # AG-001
    "ShishirPatil/gorilla::berkeley-function-call-leaderboard/bfcl_eval/model_handler/local_inference/nanbeige_fc.py::L35::AG-001": {"verdict": "FP", "reason": "eval() at nanbeige_fc.py:42 is unreachable: :37 raises unless every item is a dict, so type(item)==str is never true. Only exec-like sink in the file; also a BFCL benchmark eval harness."},  # AG-001
    "ShishirPatil/gorilla::goex/docker/docker/python_executor.py::L6::AG-001": {"verdict": "FP", "reason": "Runs only inside the container (dockerfile COPY; docker_sandbox.py:78-90 containers.run cmd 'python_executor.py code_execute'); no --privileged/docker.sock/host-net. Exec is the sandbox by design."},  # AG-001
    "ShishirPatil/gorilla::goex/docker/sqllite_docker/python_executor.py::L6::AG-001": {"verdict": "FP", "reason": "In-container sandbox entrypoint: dockerfile bakes it into an isolated image; host runs it via containers.run with no privileged/host flags (exec_engine/docker_sandbox.py:80-90). Exec IS the sandbox."},  # AG-001
    "Skyvern-AI/skyvern::skyvern/forge/sdk/copilot/tools/__init__.py::L0::AG-TRIFECTA": {"verdict": "FP", "reason": "Sink update_workflow_tool (tools/__init__.py:278) only validates+persists workflow YAML locally, no egress; 'data' leg delete_block_tool (L450) is a block deletion, not a sensitive read."},  # AG-TRIFECTA
    "THUDM/AgentBench::src/server/tasks/dbbench/result_processor.py::L158::AG-001": {"verdict": "TP", "reason": "eval(result) at result_processor.py:163 is fed the agent's own commit_final_answer argument: task.py:172 answer=arguments -> 204 -> 209 compare_results -> 24 _clean_answer -> 205. LLM-controlled RCE."},  # AG-001
    "TransformerOptimus/SuperAGI::superagi/agent/tool_builder.py::L50::AG-001": {"verdict": "FP", "reason": "build_tool only importlib.import_module's a path from DB Tool rows (tool_builder.py:60-80) picked by integer IDs (agent_iteration_step_handler.py:162-165). Loader plumbing, no agent-controlled arg."},  # AG-001
    "VRSEN/agency-swarm::src/agency_swarm/agent/tools.py::L26::AG-023": {"verdict": "FP", "reason": "add_tool(agent, tool) is a developer-facing Python registration API; every caller is framework code (agency/setup.py:403, agent/subagents.py:122, tools.py:95/101/153). No LLM-callable surface, so no HITL gate is owed."},  # AG-023
    "VRSEN/agency-swarm::src/agency_swarm/cli/migrate_agent.py::L59::AG-001": {"verdict": "FP", "reason": "Human-invoked CLI: only caller is src/agency_swarm/cli/main.py:87 with argparse args; cmd is a fixed list ['npx', runner, ts_script, settings_arg] (migrate_agent.py:102). No agent surface."},  # AG-001
    "VRSEN/agency-swarm::src/agency_swarm/integrations/fastapi.py::L0::AG-CORS": {"verdict": "TP", "reason": "fastapi.py:161-162 defaults cors_origins to ['*'] on the agency/tool-serving app, and :138-141 disables auth entirely when app_token env is unset, so any origin can drive agent endpoints."},  # AG-CORS
    "VRSEN/agency-swarm::src/agency_swarm/integrations/realtime_config.py::L0::AG-CORS": {"verdict": "FP", "reason": "MISLOCATED: witness names fastapi.py, but the flagged file (src/agency_swarm/integrations/realtime_config.py) contains no CORS config — not actionable at the named location (rubric: weakness must exist in this code)", "defect": "repo-level fan-out with misattributed file anchor"},  # AG-CORS
    "VRSEN/agency-swarm::src/agency_swarm/tools/utils.py::L0::AG-TRIFECTA": {"verdict": "FP", "reason": "'Egress' tool_output_file_from_url (utils.py:237) is a fetch, SSRF-guarded at L66/254; 'data' leg from_openapi_schema (L290) takes developer-supplied schema config, not untrusted input."},  # AG-TRIFECTA
    "VRSEN/agency-swarm::src/agency_swarm/tools/utils.py::L177::AG-011": {"verdict": "FP", "reason": "utils.py:177 is a developer helper (path arg from caller code), not a registered tool, and has no description/docstring ingestion so the claimed 'description injection' mechanism is absent here."},  # AG-011
    "VRSEN/agency-swarm::src/agency_swarm/tools/utils.py::L198::AG-011": {"verdict": "FP", "reason": "utils.py:198-211 just returns ToolOutputImage(file_id=...): no filesystem access, benign docstring, no tool decorator. Exported library helper (tools/__init__.py:46), not agent-callable."},  # AG-011
    "agiresearch/AIOS::aios/llm_core/adapter.py::L0::AG-TRIFECTA": {"verdict": "FP", "reason": "Legs misidentified: 'untrusted input' is a GET to the developer-configured ollama host (adapter.py:120-123, 296) returning model names; 'egress' execute_llm_syscall:743 is the framework's own LLM completion. No sensitive-read leg "},  # AG-TRIFECTA
    "agiresearch/AIOS::aios/tool/virtual_env/providers/virtualbox/manager.py::L254::AG-SSRF": {"verdict": "FP", "reason": "URL authority is the local VM IP parsed from 'VBoxManage guestproperty get' output (manager.py:231-235), inside _install_vm provisioning (:47); no request/tool-controlled input reaches it."},  # AG-SSRF
    "agiresearch/AIOS::aios/tool/virtual_env/providers/virtualbox/provider.py::L18::AG-001": {"verdict": "FP", "reason": "subprocess.run(list) with no shell; every caller (provider.py:73,86,104,110,112,119) passes fixed ['VBoxManage',...] argv. VM-lifecycle plumbing, not an agent-callable exec tool."},  # AG-001
    "agiresearch/AIOS::aios/tool/virtual_env/providers/vmware/manager.py::L247::AG-SSRF": {"verdict": "FP", "reason": "download_screenshot is a nested helper inside _install_vm (manager.py:121); ip is the output of `vmrun getGuestIPAddress` (L222-238) passed only at L258. No agent/user-controlled URL authority."},  # AG-SSRF
    "agiresearch/AIOS::aios/tool/virtual_env/providers/vmware/provider.py::L32::AG-001": {"verdict": "FP", "reason": "provider.py:32 receives argv lists of fixed binary 'vmrun' + literal subcommands (L63,78,91,97,103), no shell, no injectable command; agent MCP exec is a different fn (mcp_server.py:29)."},  # AG-001
    "agiresearch/AIOS::aios/tool/virtual_env/server/main.py::L75::AG-001": {"verdict": "TP", "reason": "main.py:73-103 unauthenticated Flask /execute runs subprocess.run(command, shell=shell) ('without any safety checks', l.89); reached from MCP tools via mcp_server.py:16,33 -> python.py:112-124."},  # AG-001
    "agiresearch/AIOS::runtime/launch.py::L0::AG-CORS": {"verdict": "TP", "reason": "launch.py:47-53 allow_origins=['*'] + allow_credentials=True on a kernel server with no auth dependency that exposes POST /agents/submit (line 600) and POST /query (line 727)."},  # AG-CORS
    "bytedance/deer-flow::backend/packages/harness/deerflow/agents/memory/backends/deermem/deermem/core/retrieval.py::L172::AG-SQL": {"verdict": "FP", "reason": "index_fact uses fully parameterised SQL: retrieval.py:188 `DELETE ... WHERE doc_id = ?` and :189-209 `INSERT ... VALUES (?,?,?,?,?,?,?,?,?,?)` with the row tuple bound. No string interpolation of any param."},  # AG-SQL
    "bytedance/deer-flow::backend/packages/harness/deerflow/sandbox/local/local_sandbox.py::L0::AG-TRIFECTA": {"verdict": "FP", "reason": "No egress leg: write_file (local_sandbox.py:737-751) writes a local sandbox file; download_file (:715-732) reads a local file restricted to VIRTUAL_PATH_PREFIX. Both legs are local FS ops."},  # AG-TRIFECTA
    "bytedance/deer-flow::backend/packages/harness/deerflow/sandbox/local/local_sandbox.py::L466::AG-001": {"verdict": "FP", "reason": "Agent bash_tool refuses host shell unless opt-in: tools.py:1802-1803 gate on is_host_bash_allowed (security.py:45 default False, config.example.yaml:1199) plus path allowlist tools.py:1205-1246."},  # AG-001
    "bytedance/deer-flow::backend/packages/harness/deerflow/tools/builtins/task_tool.py::L231::AG-001": {"verdict": "FP", "reason": "No subprocess/exec/eval anywhere in task_tool.py (grep clean); body only builds subagent Command objects, and the 'bash' subagent is gated by is_host_bash_allowed() (L300-308)."},  # AG-001
    "entropy-research/Devon::devon_agent/environments/swebenchenv.py::L165::AG-DOCKER-EXEC": {"verdict": "FP", "reason": "docker run at L168-180 has no escape flags (no --privileged/docker.sock/host-net) and is unreachable: DockerEnvironment/SWEEnvEnvironment never instantiated (server.py:253-6, config_utils.py:16)."},  # AG-DOCKER-EXEC
    "entropy-research/Devon::devon_swe_bench_experimental/environment/environment.py::L69::AG-001": {"verdict": "TP", "reason": "session.py:412-416 passes any unrecognised LLM-emitted command verbatim to communicate() -> environment.py:69-73 subprocess.run(shell=True). Unrestricted agent shell, no allowlist/approval."},  # AG-001
    "frdel/agent-zero::.github/scripts/docker_release_plan.py::L44::AG-001": {"verdict": "FP", "reason": "CI-only Actions helper: run_command uses subprocess.run(args) list form, no shell, fixed git/docker binaries, reached only via main() at line 823-841. Build script, not agent-exposed."},  # AG-001
    "google-deepmind/concordia::concordia/document/interactive_document_tools.py::L473::AG-011": {"verdict": "FP", "reason": "yes_no_question (interactive_document_tools.py:473-483) only delegates to multiple_choice_question; no filesystem or other capability. Tool descriptions come from developer-passed Tool objects (:107, :122-148). Witness list empty."},  # AG-011
    "h2oai/h2ogpt::openai_server/agent_prompting.py::L0::AG-CORS": {"verdict": "FP", "reason": "MISLOCATED: witness names server.py, but the flagged file (openai_server/agent_prompting.py) contains no CORS config — not actionable at the named location (rubric: weakness must exist in this code)", "defect": "repo-level fan-out with misattributed file anchor"},  # AG-CORS
    "h2oai/h2ogpt::openai_server/agent_utils.py::L0::AG-CORS": {"verdict": "FP", "reason": "MISLOCATED: witness names server.py, but the flagged file (openai_server/agent_utils.py) contains no CORS config — not actionable at the named location (rubric: weakness must exist in this code)", "defect": "repo-level fan-out with misattributed file anchor"},  # AG-CORS
    "h2oai/h2ogpt::openai_server/backend_utils.py::L0::AG-CORS": {"verdict": "FP", "reason": "MISLOCATED: witness names server.py, but the flagged file (openai_server/backend_utils.py) contains no CORS config — not actionable at the named location (rubric: weakness must exist in this code)", "defect": "repo-level fan-out with misattributed file anchor"},  # AG-CORS
    "h2oai/h2ogpt::src/create_data.py::L0::AG-CORS": {"verdict": "FP", "reason": "MISLOCATED: witness names function_server.py, but the flagged file (src/create_data.py) contains no CORS config — not actionable at the named location (rubric: weakness must exist in this code)", "defect": "repo-level fan-out with misattributed file anchor"},  # AG-CORS
    "h2oai/h2ogpt::src/create_data.py::L514::AG-001": {"verdict": "FP", "reason": "create_data.py:513-519 is a pytest test; os.system arg is a literal from ALL_OIG_DATASETS (create_data.py:443+, a constant list) plus a fixed HF URL. Human-run, no injectable input."},  # AG-001
    "h2oai/h2ogpt::src/db_utils.py::L0::AG-CORS": {"verdict": "FP", "reason": "MISLOCATED: witness names function_server.py, but the flagged file (src/db_utils.py) contains no CORS config — not actionable at the named location (rubric: weakness must exist in this code)", "defect": "repo-level fan-out with misattributed file anchor"},  # AG-CORS
    "h2oai/h2ogpt::src/function_client.py::L0::AG-CORS": {"verdict": "FP", "reason": "src/function_client.py defines no HTTP server and no CORS: it is a requests client (function_client.py:8-25). The wildcard CORS is in src/function_server.py:43-49, a different file; claim is misattributed to this code."},  # AG-CORS
    "h2oai/h2ogpt::src/gpt_langchain.py::L0::AG-CORS": {"verdict": "FP", "reason": "Witnessed CORS is src/function_server.py:45, an internal RPC server whose one endpoint dispatches a fixed 2-function allowlist (path_to_docs/process_file_list, :131-134); no agent/LLM surface."},  # AG-CORS
    "h2oai/h2ogpt::src/gpt_langchain.py::L8250::AG-001": {"verdict": "TP", "reason": "Live path in get_chain() (gpt_langchain.py:8021): when AUTOGPT agent is selected, PythonREPL repl_tool (:8246-8254) plus ShellTool (:8213) are handed to the agent tool list (:8296+), unsandboxed."},  # AG-001
    "h2oai/h2ogpt::src/utils.py::L0::AG-CORS": {"verdict": "FP", "reason": "MISLOCATED: witness names function_server.py, but the flagged file (src/utils.py) contains no CORS config — not actionable at the named location (rubric: weakness must exist in this code)", "defect": "repo-level fan-out with misattributed file anchor"},  # AG-CORS
    "h2oai/h2ogpt::src/utils.py::L0::AG-TRIFECTA": {"verdict": "FP", "reason": "Both cited legs are download() at src/utils.py:770, a requests.get helper not registered as an LLM tool (agent tools live in openai_server/agent_tools/); no sensitive-data-read leg exists."},  # AG-TRIFECTA
    "h2oai/h2ogpt::src/utils.py::L1827::AG-DESERIALIZE": {"verdict": "FP", "reason": "utils.py:1819-1829 is a deepcopy idiom: pickle.loads consumes only the bytes just produced by pickle.dumps of an in-process object; no external/attacker-supplied payload can enter."},  # AG-DESERIALIZE
    "h2oai/h2ogpt::src/utils.py::L2058::AG-001": {"verdict": "TP", "reason": "utils.py:2086 Popen(cmd) runs the LLM-written code file; used as exec_func by autogen executor (autogen_utils.py:355-366), factory default run_code_in_docker=False, restrictions=0 (1055-1063)."},  # AG-001
    "h2oai/h2ogpt::src/utils_procs.py::L0::AG-CORS": {"verdict": "FP", "reason": "src/utils_procs.py is a psutil rlimit helper module (no FastAPI, no CORS, no HTTP at all). The allow_origins=['*'] lives in src/function_server.py:43-49; the finding is attributed to unrelated code."},  # AG-CORS
    "infiniflow/ragflow::agent/sandbox/providers/local.py::L107::AG-001": {"verdict": "TP", "reason": "LLM tool 'execute_code' script param (agent/tools/code_exec.py:243,300,341) reaches LocalProvider.execute_code -> subprocess.Popen on host (local.py:121-139); code states it is not a sandbox (:58)."},  # AG-001
    "julep-ai/julep::julep/app_deploy.py::L1089::AG-001": {"verdict": "FP", "reason": "Fixed-binary helm call: subprocess.run(list), no shell; runner used only by HelmLaneReconciler (app_deploy.py:620) with hardcoded 'helm upgrade/test' argv (:645-700,:757-767). Not agent-exposed."},  # AG-001
    "julep-ai/julep::julep/app_deploy.py::L1096::AG-001": {"verdict": "FP", "reason": "_run_command_output:1096 is subprocess.run(list) with no shell; sole caller L806 passes a fixed kubectl argv with a validated namespace inside HelmLaneReconciler deploy plumbing. Not an agent tool."},  # AG-001
    "langchain-ai/langchain::libs/langchain_v1/langchain/agents/middleware/file_search.py::L210::AG-001": {"verdict": "FP", "reason": "grep_search's only exec is subprocess.run(['rg','--json',...,'--',pattern,root]) at file_search.py:305-320: fixed binary, no shell, '--' flag guard, path forced under root (L297)."},  # AG-001
    "lavague-ai/LaVague::lavague-core/lavague/core/base_driver.py::L214::AG-001": {"verdict": "FP", "reason": "base_driver.py:213-216 is @abstractmethod execute_script with body 'pass' - no exec sink exists at this location, contradicting the witness 'confirmed by body inspection'."},  # AG-001
    "lavague-ai/LaVague::lavague-qa/lavague/qa/generator.py::L100::AG-RAG-NO-SANITIZE": {"verdict": "TP", "reason": "generator.py:102-103 retrieves chunks from live page HTML (get_html(), line 159) and injects them unsanitized into the prompt at 188-192; LLM output written as runnable pytest (258-263)."},  # AG-RAG-NO-SANITIZE
    "onyx-dot-app/onyx::backend/onyx/db/document.py::L1471::AG-SQL": {"verdict": "FP", "reason": "get_cc_pairs_for_document (document.py:1471-1488) builds a SQLAlchemy ORM select()/join()/where() expression; document_id is bound as a parameter. No string interpolation, no raw SQL."},  # AG-SQL
    "pathwaycom/llm-app::templates/unstructured_to_sql_on_the_fly/app.py::L250::AG-SQL": {"verdict": "TP", "reason": "Unauthenticated REST query (app.py:221-227) -> LLM-generated SQL string executed verbatim via cursor.execute + conn.commit (app.py:251-254); only guard is a prompt instruction (:168)."},  # AG-SQL
    "potpie-ai/potpie::legacy/app/modules/intelligence/agents/hatchet_local_bootstrap.py::L109::AG-DOCKER-EXEC": {"verdict": "FP", "reason": "Dev bootstrap run by scripts/setup_hatchet_local.sh (docstring :8-9); fixed argv 'docker compose run --no-deps ... hatchet-admin token create', literal tenant id, no escape flags, no LLM input."},  # AG-DOCKER-EXEC
    "potpie-ai/potpie::legacy/app/modules/utils/gvisor_runner.py::L184::AG-001": {"verdict": "FP", "reason": "Unused legacy utility: no import of gvisor_runner anywhere in the repo (grep); the function IS the gVisor sandbox wrapper (L184-265). Not agent-reachable, and the title inverts the mitigation."},  # AG-001
    "potpie-ai/potpie::legacy/app/modules/utils/gvisor_runner.py::L603::AG-001": {"verdict": "FP", "reason": "_run_command_regular is a private fallback of run_command_isolated (gvisor_runner.py:184), which has zero callers repo-wide (only its own docstring); unwired legacy/ utility, no agent path."},  # AG-001
    "simonw/llm::llm/models.py::L297::AG-023": {"verdict": "FP", "reason": "add_tool is explicitly in Toolbox._blocked (models.py:231-238) and both tool-exposure loops skip _blocked names (models.py:273, 288), so it is never exposed to the model."},  # AG-023
    "sweepai/sweep::sweepai/handlers/on_check_suite.py::L103::AG-DOCKER-EXEC": {"verdict": "TP", "reason": "on_check_suite.py:137-156 shell=True docker build/run of cloned PR repo's Dockerfile, --env-file secrets, no --read-only/--network none/user-ns; reached via /backend/validate_pull (api.py:1085)."},  # AG-DOCKER-EXEC
    "unclecode/crawl4ai::crawl4ai/legacy/llmtxt.py::L219::AG-DESERIALIZE": {"verdict": "FP", "reason": "Input is a self-written local cache: llmtxt.py:48 bm25_index_file = docs_dir/'bm25_index.pkl', docs_dir = Path.home()/'.crawl4ai'/'docs' (legacy/docs_manager.py:10), dumped at :293/:369. Reached only via legacy human CLI, whose `f"},  # AG-DESERIALIZE
    "xtekky/gpt4free::g4f/api/tool_loop_detection.py::L0::AG-CORS": {"verdict": "FP", "reason": "MISLOCATED: witness names __init__.py, but the flagged file (g4f/api/tool_loop_detection.py) contains no CORS config — not actionable at the named location (rubric: weakness must exist in this code)", "defect": "repo-level fan-out with misattributed file anchor"},  # AG-CORS
    "yoheinakajima/babyagi::babyagi/functionz/core/execution.py::L55::AG-001": {"verdict": "TP", "reason": "exec(DB code) at execution.py:120 with secrets injected; code settable by agent tool add_new_function (default_functions.py:35) and unauth PUT /api/function, POST /api/execute (api/__init__.py:42,57)."},  # AG-001
    "zylon-ai/private-gpt::private_gpt/components/database/function_inspector.py::L123::AG-SQL": {"verdict": "FP", "reason": "The interpolated 'schema' (L124) comes only from inspect(engine).get_schema_names() filtered by config (database_query_generator.py:981-995) - real DB schema names, never an agent/tool param."},  # AG-SQL
    "zylon-ai/private-gpt::private_gpt/components/database/function_inspector.py::L210::AG-SQL": {"verdict": "FP", "reason": "'query' is a local built at function_inspector.py:223, not a param; schema comes from database_query_generator.py:985-993 filtering live get_schema_names() against config - not LLM/user input."},  # AG-SQL
    "zylon-ai/private-gpt::private_gpt/components/database/function_inspector.py::L34::AG-SQL": {"verdict": "FP", "reason": "f-string interpolation is real (L37 into query L47) but the function is dead code: its only call site is commented out at function_inspector.py:26-28 ('Postgres support is not complete')."},  # AG-SQL
}


def _wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """One-sided-safe Wilson score interval for a proportion. n==0 -> (0,1)."""
    if n == 0:
        return (0.0, 1.0)
    phat = k / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = (z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


# ---------------------------------------------------------------------------
# Phase B: join verdicts, compute precision + per-detector breakdown
# ---------------------------------------------------------------------------

def phase_b() -> None:
    if not FINDINGS_FILE.exists():
        raise SystemExit("Run phase A first (no agentzoo_findings.json).")
    manifest = json.loads(FINDINGS_FILE.read_text())
    sample = manifest["adjudication_sample"]

    # Precision is computed ONLY over the clean holdout: findings whose keys had no
    # verdict in TUNING_ADJUDICATIONS, and therefore never influenced any filter.
    adjudicated = []
    missing = []
    contaminated = []
    for f in sample:
        if f["key"] in TUNING_ADJUDICATIONS:
            contaminated.append(f["key"])
            continue
        v = HOLDOUT_ADJUDICATIONS.get(f["key"])
        if v is None:
            missing.append(f["key"])
            continue
        adjudicated.append({**f, **v})

    # TWO DEFENSIBLE BOUNDS, because one judgement call moves the number ~11 points and
    # hiding that behind a single figure would be the same sin as the 58%.
    #
    # AG-CORS inspects sibling *.py files, so a finding surfaced while scanning `utils.py`
    # can legitimately point at `server.py`. The DETECTOR attributes this correctly
    # (`Finding.source_file` names the server); this HARNESS scans one file at a time and
    # used to record only the scanned path, which made 11 of 13 AG-CORS findings look
    # mislocated. Adjudicators split on it, three of them independently.
    #
    #   LOWER: a row naming a file that does not contain the weakness is an FP. Conservative,
    #          and matches what a reader of THIS harness's output sees.
    #   UPPER: credit the weakness the witness correctly identifies. Matches what the
    #          product actually reports, and what a directory-mode scan would show.
    #
    # Neither is "the" answer. A directory-mode re-measurement is the honest next step: a
    # user runs `lucin scan .`, which dedupes 7 identical AG-CORS rows to 1, while this
    # harness runs 5,868 single-file scans and cannot dedupe across them.
    tp = [a for a in adjudicated if a["verdict"] == "TP"]
    fp = [a for a in adjudicated if a["verdict"] == "FP"]
    unk = [a for a in adjudicated if a["verdict"] == "UNKNOWN"]
    denom = len(tp) + len(fp)
    precision = (len(tp) / denom) if denom else 0.0

    # per-detector breakdown within the adjudicated sample
    per_det = defaultdict(lambda: {"TP": 0, "FP": 0, "UNKNOWN": 0})
    for a in adjudicated:
        per_det[a["id"]][a["verdict"]] += 1

    results = {
        "population_label": manifest["population_label"],
        "n_repos_downloaded": manifest["n_repos_downloaded"],
        "n_files_scanned": manifest["n_files_scanned"],
        "total_high_crit_findings": manifest["total_high_crit_findings"],
        "sample_size": manifest["sample_size"],
        "adjudicated": len(adjudicated),
        "unadjudicated_keys": missing,
        "tp": len(tp), "fp": len(fp), "unknown": len(unk),
        "precision": round(precision, 4) if denom else None,
        "precision_pct": round(precision * 100, 1) if denom else None,
        "wilson95": [round(x, 4) for x in _wilson(len(tp), denom)],
        "precision_measured": bool(denom),
        "precision_upper_pct": (
            round(100 * (len(tp) + sum(1 for a in adjudicated
                                       if a.get("defect") and a["verdict"] == "FP")) / denom, 1)
            if denom else None
        ),
        "bounds_note": (
            "LOWER counts a row naming a file without the weakness as FP; UPPER credits the "
            "witness-correct weakness (the detector's source_file is right, this per-file "
            "harness dropped it). Directory-mode re-measurement is the honest next step."
        ),
        "contaminated_excluded": len(contaminated),
        "contamination_note": (
            "Precision is computed ONLY over findings with no verdict in "
            "TUNING_ADJUDICATIONS. Those tuning labels were used to design the "
            "precision filters, so any number derived from them is train-on-test. "
            "The previously published 58% and the later 85.7% are both withdrawn."
        ),
        "per_detector": {
            k: dict(v) for k, v in sorted(per_det.items(),
                                          key=lambda kv: -(kv[1]["TP"] + kv[1]["FP"]))
        },
        "verdicts": [
            {"key": a["key"], "id": a["id"], "verdict": a["verdict"], "reason": a["reason"]}
            for a in adjudicated
        ],
    }
    RESULTS_FILE.write_text(json.dumps(results, indent=2))

    print("\n" + "=" * 74)
    print("AGENTZOO-STYLE PRECISION (Lucin SCAN, curated-broad real-agent population)")
    print("=" * 74)
    print(f"  repos downloaded:        {results['n_repos_downloaded']}")
    print(f"  files scanned:           {results['n_files_scanned']}")
    print(f"  total HIGH/CRIT findings:{results['total_high_crit_findings']}")
    print(f"  HIGH/CRIT excluded as CONTAMINATED (had a tuning verdict): "
          f"{len(contaminated)}")
    print(f"  clean holdout adjudicated: {results['adjudicated']} "
          f"(of {len(sample) - len(contaminated)} eligible; {len(missing)} not yet read)")
    if denom == 0:
        print()
        print("  PRECISION: **NOT MEASURED** -- refusing to print a number.")
        print("  The clean holdout has no verdicts yet. Precision must NOT be computed from")
        print("  TUNING_ADJUDICATIONS: those labels were used to build the precision filters,")
        print("  so any figure derived from them is train-on-test (this is why the previously")
        print("  published 58% and the later 85.7% are both withdrawn).")
        print("  Adjudicate the holdout per benchmarks/ADJUDICATION_RUBRIC.md, then re-run.")
    else:
        print(f"  TP={results['tp']}  FP={results['fp']}  UNKNOWN={results['unknown']}")
        print(f"  PRECISION = TP/(TP+FP) = {results['tp']}/{denom} = "
              f"{results['precision_pct']}%")
        lo, hi = results["wilson95"]
        print(f"  Wilson 95% CI = [{lo*100:.1f}%, {hi*100:.1f}%]   (n={denom})")
        # upper bound: restore verdicts the AG-CORS localisation rule flipped to FP
        up_tp = len(tp) + sum(1 for a in adjudicated
                              if a.get("defect") and a["verdict"] == "FP")
        if up_tp != len(tp):
            ulo, uhi = _wilson(up_tp, denom)
            print("  UPPER BOUND (crediting witness-correct AG-CORS, since the detector's")
            print(f"    own source_file names the right file) = {up_tp}/{denom} = "
                  f"{100*up_tp/denom:.1f}%  CI [{ulo*100:.1f}%, {uhi*100:.1f}%]")
            print(f"  => report the RANGE {results['precision_pct']}%-{100*up_tp/denom:.1f}%,"
                  f" not a single point.")
        print("  (UNKNOWN excluded from precision; reported separately)")
        if len(missing):
            print(f"  NOTE: {len(missing)} eligible findings are unread -- the sample is")
            print("        partial, so this is not yet a population estimate.")
    print("-" * 74)
    print("  per-detector (within adjudicated sample):")
    for k, v in results["per_detector"].items():
        print(f"    {k:<14} TP={v['TP']:<3} FP={v['FP']:<3} UNKNOWN={v['UNKNOWN']}")
    print("-" * 74)
    print("  AgentFlow published 73% (73/100) on AgentZoo (5,399 programs).")
    print("  Different corpora, both real agent programs, both manual-sample.")
    print("=" * 74)
    print(f"  results -> {RESULTS_FILE.relative_to(ROOT)}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="list the population and exit")
    ap.add_argument("--scan-only", action="store_true", help="phase A only (produce sample)")
    ap.add_argument("--report-only", action="store_true", help="phase B only (needs findings json)")
    args = ap.parse_args()

    if args.list:
        _assert_no_overlap()
        for i, r in enumerate(REPOS):
            print(f"  [{i:3d}] {r}")
        print(f"\n  {len(REPOS)} repos (no overlap w/ benign corpus).")
        return

    if args.report_only:
        phase_b()
        return

    phase_a()
    if not args.scan_only:
        phase_b()


if __name__ == "__main__":
    main()
