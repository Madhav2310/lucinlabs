# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Lucin (package: `lucin`, pip name `lucin`) is a static security scanner for AI agents. It parses agent
framework code (LangChain, MCP, CrewAI, AutoGen, OpenAI Swarm, PydanticAI, Google ADK, and a generic
fallback) into a normalized `Agent`/`Tool` model, runs detector rules over it, and reports OWASP-mapped
findings with a 0-100 security score. `control_plane/` is a separate, early-stage FastAPI SaaS scaffold
built on top of the OSS engine (see `control_plane/README.md`).

Note: `CONTRIBUTING.md` still refers to the package by its old name `agentguard` and an older detector
layout — the source of truth for current structure is `src/lucin/` and `src/lucin/detectors/__init__.py`,
not that doc.

## Commands

```bash
pip install -e ".[dev]"          # install with test/lint deps
pytest                            # run full test suite (433 passing, tests/ dir)
pytest tests/test_scanner.py      # run one test file
pytest tests/test_scanner.py::test_name -q   # run a single test
ruff check src/                   # lint

lucin scan ./my-agent/            # core scan command
lucin scan ./my-agent/ --ci --fail-on high
lucin info ./my-agent/            # inventory without running detections
lucin redteam ./my-agent/         # targeted adversarial payloads (experimental)
lucin monitor ./traces.jsonl      # behavioral anomaly scoring (experimental)
lucin serve --port 8080           # REST API (requires `.[api]` extra)

# Reproduce headline validated numbers (see README "Validated Capabilities"):
python benchmarks/build_benign_corpus.py   # SCAN precision (0 FP / 52 repos)
python benchmarks/recall_corpus.py         # SCAN recall (38/50 = 76%)
python benchmarks/guard_live_llm.py        # GUARD live-LLM block test
```

`pyproject.toml` defines the `lucin` console script (`lucin.cli:app`), ruff config
(line-length 100, py310 target), and optional extras: `api` (FastAPI/uvicorn for `lucin serve`),
`behavioral` (river/numpy/sklearn — required for the *validated* Half-Space Trees monitor backend;
without it, `behavioral/streaming.py` falls back to an unvalidated pure-Python implementation that
warns on use), `dev` (pytest/ruff).

## Architecture

Pipeline: **parse → detect → score → report**.

```
target dir/file
    → parsers/*  (framework-specific: langchain_parser, mcp_parser, crewai_parser,
                   autogen_parser, swarm_parser, pydantic_ai_parser, google_adk_parser,
                   llamaindex_parser, generic_parser as catch-all)
    → normalized Agent/Tool/MCPServer models (models.py)
    → scanner.scan_target() orchestrates parsing + detectors/run_all_detectors()
    → Finding objects, one per (detector, location)
    → scoring.py computes 0-100 score from findings
    → reporter.py (terminal/rich), html_report.py, sarif.py, owasp_report.py (output formats)
```

**Detector registry is the source of truth for "what runs."** `src/lucin/detectors/__init__.py`
defines `PER_AGENT_DETECTORS` (analyze one agent) and `CROSS_AGENT_DETECTORS` (analyze relationships,
e.g. delegation chains), and `ACTIVE_DETECTOR_COUNT = len(PER_AGENT_DETECTORS) + len(CROSS_AGENT_DETECTORS)`.
A detector module existing in `detectors/` does not mean it runs — it must be imported and added to one
of those two lists. Two detectors are intentionally built but NOT registered (documented inline in that
file): `detect_path_traversal` (sound, but the benign corpus has byte-identical legitimate patterns —
precision over recall) and `detect_memory_poisoning`/AG-013 (its entry point currently `return []`,
disabled pending real false-positive data). When adding a new detector, register it in one of the two
lists or it silently never fires and the transparency count won't reflect it.

**Taint analysis is intentionally limited, not a whole-program call graph** (no PyCG on the build
mirror). Layers, from what's actually wired into production scans:
1. Intraprocedural, flow-sensitive, field-insensitive taint per function (`parsers/body_inspector.py`,
   `intraproc_taint`) — this is what most detectors use.
2. Capability-based classification as the cross-function approximation: each tool is classified by
   capabilities it exhibits (untrusted input, shell exec, network egress, secrets access, ...), and
   dangerous *combinations* are flagged (lethal trifecta, dangerous-combination detectors) rather than
   proving a literal data-flow path.
3. Limited cross-function/intra-class taint (`analysis/cross_function_taint.py`, via `detectors/_taint.py`)
   is wired into SSRF, insecure-deserialization, and path-traversal detectors — same-file method-to-method
   flows only, no cross-file or dynamic-dispatch resolution.
4. `analysis/file_scope_taint.py` is a separate summary-based analyzer that is unit-tested but NOT wired
   into the production scan path — experimental only.

**`GUARD` (runtime) vs `SCAN` (static)**: `src/lucin/guard/` is the runtime interception/admission layer
(`interceptor.py`, `admission.py`, `injection_detector.py`, `ifc_runtime.py`, `taint_registry.py`,
`provenance.py`, `adapters.py` for framework runtime hooks, `otel_export.py`). It shares the same
`lucin.aifg.AIFG` engine and `IFCLabel` lattice as the static scanner (`aifg.py`) — this is called out as
a deliberate invariant in `control_plane/README.md`: a static finding and a runtime enforcement decision
are the same object type, not two parallel implementations that can drift.

**`src/lucin/prove/`** is the red-team/adversarial-testing engine backing `lucin redteam`:
`attack_library.py` + `payload_generator.py` build targeted attacks from the agent's actual tool names,
`benchmark.py` drives ASR (attack success rate) evaluation.

**`src/lucin/behavioral/`** backs `lucin monitor` — ML-based anomaly scoring over agent traces
(multi-model ensemble: frequency/temporal/parameter/structural/sequence), validated only on synthetic
corpora so far (see README "Validated Capabilities" for exact numbers and what's launch-gated).

**`src/lucin/multiagent/`** covers cross-agent risks: delegation chains, memory/vector-store
poisoning detection, identity/cascade spoofing checks.

**`_fs.py`** centralizes the vendored/build directory exclusion list (`venv`, `.venv`, `node_modules`,
`site-packages`, `*.dist-info`, `.git`, `dist`, `build`, `__pycache__`) used by all file walks — this is
why `lucin scan .` doesn't flag a project's own dependencies.

**`control_plane/`**: FastAPI app (`api/app.py`) + Postgres/TimescaleDB models (`models/`) + SDK
(`sdk/guard_client.py`) for a hosted SaaS layer around the OSS engine. Explicitly a first-pass scaffold
with honest TODOs — read `control_plane/README.md` before assuming any endpoint is production-ready.

## Rule-quality conventions (from CONTRIBUTING.md, still applicable)

- Detector functions take `Agent` and return `list[Finding]`.
- Every rule maps to an OWASP Agentic Top 10 category and cites a real-world basis where possible.
- Precision is prioritized over recall — a detector with any known false-positive path against the
  benign corpus should not be registered (see the path-traversal precedent above) until fixed.
- Rule IDs: current allocation is visible directly in the README's detector table and in
  `grep -rhoE 'id="AG-[A-Z0-9-]+"' src/lucin/detectors/*.py` — treat that grep, not `CONTRIBUTING.md`'s
  stale range table, as ground truth for what IDs exist.

## Honesty/claims discipline

This repo is unusually strict about not overclaiming: numbers in README.md and
`DEFINITION_OF_DONE.md` are labeled by provenance (real repos vs. synthetic corpora vs.
launch-gated/not-yet-validated), and each ships the exact command to regenerate it. When touching
detectors, benchmarks, or README claims, keep that discipline — don't state a capability or number
without a way to reproduce it, and don't upgrade a "synthetic" or "launch-gated" label without new
evidence.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
