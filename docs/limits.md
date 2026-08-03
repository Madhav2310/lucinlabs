# Limits — what Lucin does not catch (yet)

Honesty is a feature here. This page states the boundaries plainly. If a claim wouldn't
survive a security researcher reading the actual code, it doesn't belong in the docs — so
these are the real edges, each tied to the code or the measured number that proves it.

## SCAN is a static, pre-deploy scanner

It finds enabling misconfigurations and known dangerous patterns in code before you ship.
It does **not**:

- **Detect novel zero-days or emergent runtime behavior** — that needs runtime monitoring.
- **Catch vulnerabilities that only appear during execution** — dynamic injection, runtime
  prompt attacks, or behavior emerging from model+tool interaction.
- **Guarantee 100% detection** — coverage depends on how the agent is structured. Highly
  dynamic Python (heavy `getattr`, reflection, generated code) reduces recall.
- **Solve alignment** — we bound what tools *can* do; we don't fix the model's *intent*.

A clean scan means no known dangerous static patterns were found. It does not mean the
agent is safe under all inputs.

## Per-class recall gaps (measured, not hidden)

Measured recall is **38/50 = 76%** (`python benchmarks/recall_corpus.py`). The gaps:

### SSRF — partial (17%)
`AG-SSRF` is deliberately conservative: it fires only when taint forms the **URL host** of
a request sink (`u = f"http://{host}"; get(u)`). It will *not* flag a bare whole-URL
parameter or a `__init__`-assigned sink, and it skips patterns that a legitimate
URL-fetching tool would also match. This trades SSRF recall for the precision result
(0 confirmed FP outside a documented per-repo known-capability allowlist) — by design
(`src/lucin/detectors/ssrf.py`).

### Path traversal — 0% (detector built but UNREGISTERED)
`AG-PATH-TRAVERSAL` is built, sound, and unit-tested — but it is **intentionally not
registered** in the scan path. The benign corpus contains byte-identical *legitimate* file
tools (`open(param)`, `os.path.join(base, name)`, `Path.write_text`) that are
indistinguishable from the vulnerable shapes under static analysis. Registering the
detector would break the precision result (0 confirmed FP outside a documented per-repo
known-capability allowlist), so it is gated off — **precision over recall**.
The gate and its rationale are documented in `src/lucin/detectors/__init__.py`.

### Container escape — 80%
`AG-DOCKER-EXEC` resolves docker commands built via a variable, but misses cases where the
container is driven through the docker **SDK** rather than a subprocess command.

## Interprocedural / cross-file taint

Lucin does **not** perform whole-program, call-graph-based interprocedural taint
analysis. The standard Python call-graph tool, **PyCG**, is unavailable on the build
mirror, so it is not vendored or integrated. What actually runs:

- **Single-function (intraprocedural) taint**, flow-sensitive, field-insensitive, over each
  tool body (`parsers/body_inspector.py`, `intraproc_taint`).
- **Limited cross-function / intra-class taint** (`analysis/cross_function_taint.py`, wired
  via `detectors/_taint.py`) — resolves same-file method-to-method flows (e.g.
  `__init__` → `pickle.load`). Not a full call graph; does not cross files or resolve
  dynamic dispatch.
- **Capability-based classification** as the cross-function approximation — flag dangerous
  *capability combinations* (the trifecta / dangerous-combination detectors) instead of
  proving a precise A→B path.

A separate `analysis/file_scope_taint.py` exists and is unit-tested but is **not wired**
into production scans — treat it as experimental.

**Consequence:** a vuln where untrusted input enters in one function and reaches a sink in
a *different file*, with no single tool exhibiting the dangerous combination, may be
missed with path-level precision. The capability heuristic recovers many of these, but not
all, and dynamic dispatch is treated as a conservative barrier.

## Detectors held back on purpose

- **AG-013 (memory/RAG poisoning)** — registered but returns no findings; disabled pending
  real false-positive data before it is re-enabled.
- **AG-PATH-TRAVERSAL** — built and unit-tested, unregistered for precision (above).

## Experimental / not-yet-validated capabilities

These ship as code but are **not** part of the validated core:

- **`lucin monitor` (behavioral, ML)** — validated on **synthetic** corpora only
  (session-level benign FP 3.75%, drift, adaptive-evasion). Precision on **real production
  traces** is *not yet measured* — genuinely launch-gated (needs real user traffic).
- **`lucin redteam` (PROVE)** — payload generation works; a published model-level
  attack-success-rate frontier is currently **endpoint-gated**: the only reachable LLM
  gateway applies a content filter that rejects overt injection payloads at the API layer,
  which confounds a clean ASR measurement. See `DEFINITION_OF_DONE.md`.
- **`lucin serve` (REST API)** — experimental.

## Launch-gated residuals (cannot be faked pre-launch)

By the project's own contract (`DEFINITION_OF_DONE.md`), these require real users/traces
and are **not** claimed as done:

- Behavioral precision on real production traffic.
- A design-partner production witness of GUARD.
- SCAN precision at the true scale/diversity of the *population* of user repos (the 52-repo
  corpus is a strong pre-launch proxy, not the population).
- Days-later multi-agent attack detection in a live deployment.

## Reproduce these claims

Every number on this page regenerates:

```bash
python benchmarks/recall_corpus.py        # 38/50 = 76%, per-class + false-negative list
python benchmarks/build_benign_corpus.py  # 0 confirmed FP (documented per-repo allowlist) / 52 repos / 2,732 files
python -m pytest tests/ -q                # 517 passing
```
