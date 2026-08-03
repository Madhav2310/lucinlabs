# Methodology — how the numbers are measured (and how to reproduce them)

Every headline number in this project ships with the command that regenerates it. This
page tells you what the corpora are, how precision and recall are computed, and the exact
commands to reproduce them offline. All numbers below were regenerated on 2026-07-29.

> Principle: **external truth over internal polish.** Author-written unit tests do *not*
> count as validation of a detection claim. Precision is measured on real third-party
> repositories; recall is measured on a held-out corpus whose provenance is published.

---

## 1. Precision — 0 adjudicated false positives (documented allowlist)

**Result:** **0 adjudicated false positives** across **52 real repos / 2,732 files** — 52/52
repos clean. False positives are counted as distinct **(file, detector-id) pairs**, outside
a documented per-repo known-capability allowlist (`known_tp`, annotated inline in the
script); this yields a **0.0% per-file FP** rate. It is a documented, reviewable
methodology — **not** a per-file zero-FP proof.

**Reproduce:**

```bash
python benchmarks/build_benign_corpus.py
```

**What the corpus is.** A set of 52 real, third-party AI-agent / LLM-framework
repositories (LangChain-adjacent frameworks, MCP SDKs, CrewAI, AutoGen/Swarm, LlamaIndex
tool specs, browser agents, RAG stacks, etc.). These are legitimate projects that are
*not* meant to contain the incident-class misconfigurations Lucin flags. Each repo is
scanned (capped per repo for runtime); a "false positive" is any CRITICAL/HIGH finding on
this benign code.

**File selection (load-bearing — read this).** The FP denominator is *production
agent-code files*, capped at ~100 per repo for runtime. Author-written **test fixtures and
example/demo scripts are excluded** from the denominator: they are not the production agent
surface a user ships. Be clear-eyed about what this means — like every static analyzer, a
raw full-repo `lucin scan .` **will** surface findings inside test/example files (an
`exec()` in a test, a hardcoded key in a doc snippet). Those are expected and are *not*
counted against precision. The published number is therefore **adjudicated**: production
agent-code files, tests/examples excluded, and legitimate true-positives listed per repo
(`known_tp`). We publish the method precisely so it is reviewable — it is **not**, and is
never claimed to be, a raw per-file zero across an entire tree.

**How the number is computed.** `FP findings = CRITICAL/HIGH findings on benign code`;
`clean repos = repos with zero such findings`. The report prints per-repo status and a
summary block:

```
Repos scanned:    52
Files scanned:    2732
Clean repos:      52/52  (100%)
FP findings:      0  (distinct file×detector pairs, CRITICAL/HIGH, on benign code)
FP rate:          0.0%  (distinct FP (file,id) pairs / files scanned)
```

Confirmed true positives that legitimately exist in a benign repo are excluded via the
per-repo known-capability allowlist (`known_tp`) documented inline in the script (they are
real issues, not false alarms; no admitted FP is hidden in that list) — the reported
count is **0 adjudicated false positives** outside that documented allowlist.

**Why precision comes first.** In a security tool a false positive is worse than a miss
for adoption: noisy tools get uninstalled and burn word-of-mouth. Several detectors are
deliberately conservative (see AG-SSRF) or held unregistered (see AG-PATH-TRAVERSAL in
[what SCAN misses](/limits/)) specifically to protect this precision result.

---

## 1b. Precision on a BROAD population — **WITHDRAWN, being re-measured**

The number in §1 is measured on a corpus **selected to be benign**, with
production-agent-code file selection. That answers *"how noisy are we on code we
believe is clean?"* It is **not** the number a user gets from `lucin scan .` on an
arbitrary repository. So we measure that too, and publish it even though it is
unflattering — an unpublished bad number is just marketing.

**Corpus:** 81 hand-picked real GitHub agent repos (autonomous/coding/browser/RAG
agents, multi-agent frameworks, MCP), **zero overlap** with the §1 corpus
(enforced by an `_assert_no_overlap()` guard), **5,868 Python files**. It is a
**curated-broad population, NOT a uniform random sample** — and unlike §1 it does
*not* skip framework-core or utility files, which is exactly where noise lives.

**Reproduce:**

```bash
python benchmarks/agentzoo_precision.py            # download + scan + report
python benchmarks/agentzoo_precision.py --scan-only  # regenerate the sample only
```

**Method** (mirrors AgentFlow, arXiv 2607.01640, which published 73% precision by
manually inspecting 100 of its findings): collect every HIGH/CRITICAL finding,
draw a fixed-seed 100-finding sample, and have a human read the actual code
behind each one, recording TP / FP / **UNKNOWN**. UNKNOWN is excluded from
precision and reported separately — we do not guess in order to inflate it.

**Baseline (2026-07-30).** On the 100-finding sample the scanner started at
**8 TP / 52 FP / 40 UNKNOWN = 13.3%**. Total HIGH/CRIT on the population then fell
**429 → 87**, the §1 corpus stayed at 0 adjudicated FP, and recall held at 76%.

**WITHDRAWN: the post-fix precision figure (2026-07-30).** We previously published
**58%** — "the survivors of that same hand-adjudicated sample: 7 TP / 5 FP". Re-running
`benchmarks/agentzoo_precision.py` today prints **85.7% (12 TP / 2 FP)**. Both numbers are
invalid, for the same reason, and the drift is the symptom rather than the disease:

* The 100 verdicts in `ADJUDICATIONS` were the labels **used to design the precision
  filters**. The five fixes below were built to remove the FP classes those labels named.
* `phase_b()` computes precision only over sampled findings that still match a verdict key
  (`ADJUDICATIONS.get(f["key"])`; unmatched findings are silently skipped).
* So the surviving matched set is **enriched for TP by construction**: 12 of 30 TP-labelled
  findings survive as HIGH/CRIT, but only **2 of 70 FP-labelled** ones do — because removing
  them was the goal.

That is train-on-test. It measures how well the filters hit the labels they were built from,
not precision on unseen code. Neither 58% nor 85.7% may be published.

**Replacement measurement: a clean holdout.** Of the current 87 HIGH/CRIT findings, **73 had
no prior verdict**, so no label among them influenced any detector or filter. All 73 were
adjudicated against criteria fixed in advance (`benchmarks/ADJUDICATION_RUBRIC.md`), reading
the real cloned code rather than the snippet. The contaminated table is retained, renamed
`TUNING_ADJUDICATIONS`, and excluded from the calculation; `phase_b()` now refuses to print a
number if the holdout is empty, so the mistake cannot silently recur.

### Result on the clean holdout (2026-07-30)

**Precision = 20.5%–31.5% (n=73, 0 UNKNOWN).** Two bounds, both published:

* **Lower: 15/73 = 20.5%**, Wilson 95% CI [12.9%, 31.2%] — counts a finding whose named file
  does not contain the weakness as an FP.
* **Upper: 23/73 = 31.5%**, Wilson 95% CI [22.0%, 42.9%] — credits the weakness the witness
  correctly identifies.

The gap is a single judgement call about AG-CORS attribution, and it is worth ~11 points, so
collapsing it into one figure would repeat the sin that produced the 58%. **The detector is
right and this harness was wrong**: `agent_server.py:186` sets `Finding.source_file` to the
actual server file, and `agentzoo_precision.py` recorded only the file it fed to `scan_target`
(now fixed — it records `finding_file` too). Three adjudicators independently split on this
case.

```bash
python benchmarks/agentzoo_precision.py --report-only
```

Even the upper bound is **roughly half** of what we previously published, and this is the
figure that counts, because it is the only one measured on findings no filter was tuned
against. Per-rule (lower bound):

| Rule | TP | FP | Precision |
|---|---:|---:|---:|
| AG-001 (exec) | 10 | 21 | 32% |
| AG-CORS | 2 | 11 | 15% |
| AG-SQL | 1 | 6 | 14% |
| **AG-TRIFECTA** | **0** | **6** | **0%** |
| AG-DOCKER-EXEC | 1 | 3 | 25% |
| AG-011 / AG-023 / AG-SSRF / AG-DESERIALIZE / AG-007 | 0 | 11 | 0% |
| AG-RAG-NO-SANITIZE | 1 | 0 | 100% |

**Three findings that matter more than the headline:**

1. **AG-TRIFECTA has zero true positives on the clean holdout (0/6).** The flagship detector,
   the one the whole information-flow story rests on, did not produce a single confirmed
   finding here. Every case failed on a misidentified leg — an "egress" that was a local write
   or a fetch, or a "sensitive read" that was a deletion or developer config.
2. **AG-CORS is a repo-level finding with a misattributed anchor.** 13 findings correspond to
   **5 distinct weaknesses**; **11 of 13 name a file that contains no CORS configuration**,
   while the witness names the real one. A user opening the flagged file finds nothing. Under
   the pre-committed rubric these are FPs, and the underlying defect is fan-out plus
   mislocation, not detection.
3. **This harness does not measure what a user experiences.** It runs ~5,868 **single-file**
   scans; a user runs `lucin scan .` on a directory. Those differ: a directory scan now
   collapses 7 identical AG-CORS rows to 1 (`_dedupe_identical_location`, added 2026-07-30
   with 7 regression tests), while the per-file harness cannot dedupe across separate calls.
   A **directory-mode re-measurement is the honest next step** and would raise the figure.
4. **Zero UNKNOWNs across 73 findings.** The rubric explicitly invites UNKNOWN and none was
   used. Treat that as a caveat on the adjudication, not a strength: it suggests adjudicators
   resolved ambiguity rather than recording it.

**Caveat on who adjudicated.** These verdicts were produced by LLM adjudicators reading the
real code with evidence citations (file:line) recorded for each, not by an independent human
panel. Inter-rater agreement was not measured. Three adjudicators independently hit the
AG-CORS localisation case and split on it, which is direct evidence that verdicts are
sensitive to interpretation; the split was resolved mechanically by applying the rubric as
written (see `benchmarks/_merge_verdicts.py`). An independent human re-adjudication is the
next honest step, and until it exists this number should be read as provisional.

**Why the old 58% was withdrawn, and the caveats that still apply:**

* **The interval is wide.** n = 12 adjudicated survivors → Wilson 95% CI
  **[32%, 81%]**. The point estimate is not a fact; a fresh 100-finding
  adjudication of the current 93 findings is the honest next measurement.
* **The metric is HIGH/CRIT-scoped, so a DEMOTION could masquerade as a fix.** The
  harness now records every severity so this is answerable rather than assumed.
  Measured fate of the original 429 HIGH/CRIT findings:

  | Fate | Count | Share |
  |---|---:|---:|
  | Deleted entirely | 180 | 42% |
  | Demoted to MEDIUM (still shown) | 160 | 37% |
  | Still HIGH/CRIT | 89 | 21% |

  So "429 → 93" is **42% removal and 37% re-prioritisation**, not 78% removal. The
  scanner still emits **647 findings at all severities** on this corpus — it did not
  go quiet, it re-ranked. What a user triages first went from 429 items to 93.

* **Zero confirmed true positives were deleted.** Of the 8 hand-confirmed TPs in the
  sample: **7 remain HIGH/CRIT, 1 was demoted to MEDIUM, 0 were deleted.** Of the 52
  confirmed FPs, 26 were deleted and 21 demoted. That is the load-bearing safety
  check on the reduction, and it passed.

* **Residual uncertainty is 17 findings.** 17 of the 40 UNKNOWN (unadjudicable) items
  were deleted. We cannot claim those were noise — they were all witness-less
  findings on files carrying no agent evidence, the weakest class, but "weakest
  class" is an argument, not evidence.
* **One true positive was demoted.** SuperAGI's `delete_file.py` (destructive tool,
  no human-approval gate) is a genuine finding with no line and no witness, so the
  evidence cap moved it to MEDIUM. It is still reported; it is no longer CRITICAL.
* **The §1 benign number gets easier.** That corpus counts CRITICAL/HIGH only, so
  capping unverifiable findings mechanically helps it. Its 0-FP result should be
  read with that in mind.
* **Ground truth is soft.** Two independent adjudications of the same sample gave
  13.3% and 30% — label noise comparable to the effects being measured. Treat all
  of this as a directional instrument, not a scoreboard.

**What that gap taught us (all five verified and fixed):**

1. **Fetch was classified as egress.** Any network-touching tool defaulted to
   "egress sink", so `download_object`, `scrape_page`, `web_fetch_tool` became
   fake exfiltration sinks (AG-TRIFECTA 11 → 7). This is the *same error class* as
   deciding a sink by category rather than behaviour. Fixed by verb-intent
   resolution in `is_egress_by_name`.
2. **Parameterized ORM was flagged as SQL injection.** `select(T).where(T.id ==
   arg)` passed to `.execute()` looked like a raw-SQL sink; 0 of 7 sampled AG-SQL
   findings were real (AG-SQL 18 → 8). Fixed by `_is_orm_parameterized` — `text()`,
   f-strings and concatenation remain dangerous.
3. **Name-inferred capabilities claimed CRITICAL.** `capabilities = name ∪ body`
   meant reading the body could never withdraw a name guess, so
   `printable_shell_command` (body: `oslex.join` — shell *escaping*) was CRITICAL.
   AG-001 severity is now **graded by evidence**: body-confirmed → CRITICAL,
   name-only → MEDIUM with a witness that says which evidence we had (AG-001
   HIGH/CRIT 92 → 43). The finding still reports, so recall is unchanged.

4. **Witness-less findings on files that are not agents.** The generic parser is
   deliberately aggressive (a function merely NAMED `execute`/`query` makes a file
   an "agent"), so build scripts, benchmark harnesses, pydantic-schema modules,
   prompt-string files and `fake_tools/` were scanned as agents; the
   capability-composition detectors then fired there with no line and no witness.
   Those findings scored **3 TP / 28 FP (9.7%)** with **38 of 100 unadjudicable**.
   A finding on such a file must now carry either agent evidence (`@tool`, a Tool
   base class, an LLM client, a tool registry, MCP config, an agent constructor,
   an HTTP server) or its own witness — see
   `_require_evidence_on_unproven_agents`. This single change removed **220** of
   the population's findings.
5. **Unverifiable findings claimed HIGH/CRITICAL.** The posture family (AG-006,
   AG-028, AG-COMP, AG-002, AG-005a/b, AG-NOAUTH) asserts something about an
   agent's capability *set* — no line, no path, nothing to open. On the adjudicated
   sample, findings with neither a witness nor a line ran **1 TP / 8 FP (11%)** and
   held **21 of the 23** findings that could not be adjudicated at all. Severity is
   now **bounded by evidence** (`_bound_severity_by_evidence`): no evidence path ⇒
   capped at MEDIUM. They are still reported, so recall is unchanged. A sixth fix
   also landed: **AG-DOCKER-EXEC no longer reports a hardened sandbox as an escape**
   (it flagged `--runtime=runsc` gVisor runners and `docker --version` probes —
   0 TP / 3 FP).

**Honest caveats.** Two independent adjudications of the same sample produced
13.3% and 30%, differing almost entirely on witness-less findings — if two careful
readers cannot agree whether one of our findings is real, a user cannot either;
that disagreement is what motivated fix 4. We remain **below AgentFlow's published
73%** on this population; their corpus and ours differ, so neither number strictly
dominates, and we do not claim to beat it. The 34.8% is measured on the *same*
hand-adjudicated subset (survivors of the original 100-finding sample), not a
fresh sample — a fresh 100-finding adjudication of the current 209 findings is the
honest next measurement.

---

## 2. Recall — 38/50 = 76%

**Result:** **38/50 = 76%** recall (24% false-negative rate) across **10 vuln classes**;
**19/22 = 86%** on the real third-party cases alone.

**Reproduce:**

```bash
python benchmarks/recall_corpus.py
```

**What the corpus is.** 50 distinct vulnerable agents across 10 vulnerability classes:

- **22 real third-party cases** — drawn from actual projects/CVE-class patterns.
- **28 clearly-labeled constructed cases** — hand-built, minimal reproductions, each
  labeled `constructed__` in its path so the split is never hidden.

Provenance for every case (source, CVE/reference where applicable, real-vs-constructed)
is recorded in `benchmarks/recall_corpus/manifest.json`. The benchmark runs offline and
parallelized; a case counts as detected only if the scanner emits the *expected rule ID*
for that class.

**Per-class recall (regenerated 2026-07-29):**

| Class | Recall | Notes |
|-------|--------|-------|
| command_injection | 5/5 = 100% | |
| sql_injection | 6/6 = 100% | |
| cql_injection | 2/2 = 100% | Cassandra CQL, via AG-SQL |
| rce_eval_exec | 5/5 = 100% | |
| cors_unauth_server | 5/5 = 100% | AG-CORS / AG-NOAUTH |
| secret_exfil_trifecta | 4/4 = 100% | AG-TRIFECTA (incl. 1 real case from verbatim third-party tool bodies) |
| insecure_deserialization | 6/6 = 100% | AG-DESERIALIZE + cross-function taint |
| container_escape | 4/5 = 80% | AG-DOCKER-EXEC (1 miss: docker built via variable/SDK) |
| ssrf | 1/6 = 17% | AG-SSRF is deliberately conservative (URL-host taint only) |
| path_traversal | 0/6 = 0% | AG-PATH-TRAVERSAL built + sound but **unregistered** (precision) |
| **OVERALL** | **38/50 = 76%** | 19/22 = 86% on real-only |

**The honest false-negative list.** The benchmark prints every miss, with the rule IDs it
*did* emit vs. what was expected — e.g. the SSRF and path-traversal misses (no registered
detector fires) and one container-escape case where the docker command is assembled
through a variable. We publish the misses rather than hide them.

**Why some classes are low on purpose.** SSRF and path traversal are the FP-prone classes:
the benign corpus contains byte-identical legitimate shapes (`open(param)`,
`os.path.join(base, name)`, tools that fetch a URL). Registering an aggressive detector for
these would break the precision result (0 confirmed FP outside the documented per-repo
known-capability allowlist). The project chooses **precision over recall** here —
see [what SCAN misses](/limits/).

---

## 3. Cross-function taint (what makes deserialization 100%)

`insecure_deserialization` reaches 100% partly because of a limited cross-function /
intra-class taint analyzer (`src/lucin/analysis/cross_function_taint.py`, wired via
`src/lucin/detectors/_taint.py`). It resolves same-file method-to-method flows — e.g.
a value stored in `__init__` and later reaching a `pickle.load` sink. It is **not** a
whole-program call graph (PyCG is blocked on the build mirror) and does not cross files or
resolve dynamic dispatch. See [what SCAN misses](/limits/) for the interprocedural boundary.

---

## 4. Test suite

**Result:** **517 passing** (12 skipped, 1 xfail).

**Reproduce:**

```bash
python -m pytest tests/ -q
```

Unit tests verify detector logic on author-written input. Per the project's validation
ladder, unit tests are **necessary but not sufficient** — they do not count as validation
of a precision or recall claim. Those come from the real/held-out corpora above.

---

## Reproducibility summary

| Number | Command |
|--------|---------|
| 0 adjudicated FP (documented per-repo allowlist) / 52 repos / 2,732 files | `python benchmarks/build_benign_corpus.py` |
| Broad-population precision | **WITHDRAWN** — contaminated measurement; clean holdout re-adjudication in progress (§1b) |
| 38/50 = 76% recall / 10 classes / 86% real | `python benchmarks/recall_corpus.py` |
| 517 tests passing | `python -m pytest tests/ -q` |

Other capability numbers (GUARD live-LLM block, content-taint, behavioral, multi-agent)
each have their own regenerating command — see the "Validated Capabilities" table in the
[README](https://github.com/Madhav2310/lucinlabs#readme).
