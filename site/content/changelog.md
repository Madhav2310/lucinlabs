# Changelog

Lucin is pre-launch and developed in the open. Entries are dated and describe what
changed, including the mistakes — a changelog that only lists wins is marketing.

Every claim below has a command that regenerates it. Where a change was **reverted**,
the reason is stated, because a reverted change is information.

---

## 2026-07-30

**Precision work, measured end to end.** Ran the scanner against a fresh population of
**81 real GitHub agent repositories / 5,868 files** (no overlap with the existing
benign corpus, enforced by a guard in the harness), then hand-adjudicated a fixed-seed
100-finding sample by reading the actual code behind each finding. Starting point:
**8 true positives / 52 false positives / 40 unadjudicable = 13.3% precision.** After
the fixes below, and a later clean-holdout **precision of 20.5-31.5% (n=73, 95% CI 12.9-42.9%)** — the original 58% was train-on-test and is withdrawn — with **0 confirmed true positives
deleted**, and **every remaining HIGH/CRITICAL finding now carries a witness or a
source line** a reader can open. Reproduce: `python benchmarks/agentzoo_precision.py`.

Five real defects, each found only by that external measurement and not by 473 passing
unit tests:

- **Fetch was being classified as egress.** Any network-touching tool defaulted to
  "egress sink", so `download_object`, `scrape_page` and `web_fetch_tool` became fake
  exfiltration sinks. Fixed with verb-intent resolution: an outward verb anywhere wins,
  otherwise the leading verb decides, otherwise a fetch verb means source.
  (AG-TRIFECTA findings 11 → 7.)
- **Parameterized ORM was flagged as SQL injection.** `select(T).where(T.id == arg)`
  passed to `.execute()` looked like a raw-SQL sink; 0 of 7 sampled AG-SQL findings
  were real. `text()`, f-strings and concatenation remain dangerous. (18 → 8.)
- **A hardened sandbox was reported as a container escape.** AG-DOCKER-EXEC fired on
  `--runtime=runsc` gVisor runners and on `docker --version` probes — i.e. it reported
  the mitigation as the vulnerability. Escape flags and hardening flags are now
  distinguished. (That detector scored 0 true positives against 3 false alarms on the sampled findings; it now produces none of them.)
- **`shlex.quote` did not clear a finding.** `lucin fix` tells you to wrap a command in
  `shlex.quote`; the scanner then flagged your code again after you did, and reported
  CRITICAL on `subprocess.run(["git","status"])`, which has no user input at all.
  There is now a kind-scoped sanitizer model (`src/lucin/analysis/sanitizers.py`) —
  `shlex.quote` clears COMMAND sinks and deliberately does not silence SQL or path sinks.
- **Findings with no evidence claimed CRITICAL.** Capability-composition rules
  (AG-006, AG-028, AG-COMP, AG-002, AG-005a/b, AG-NOAUTH) assert something about a
  tool set with no line and no path. On the adjudicated sample they ran **1 true
  positive / 8 false positives**, and held 21 of the 23 findings that could not be
  adjudicated at all. Severity is now bounded by evidence: no evidence path, no
  HIGH/CRITICAL. They are still reported, so recall is unchanged.

**Two changes attempted and reverted**, because measurement said they made things worse:

- Letting body evidence *veto* a name-inferred `EXECUTE_CODE` killed real false
  positives but cost **4 real recall cases** (76% → 70%): class-based toolkits hide
  their exec behind `self._docker_exec(...)`, so "no exec found" was absence of
  evidence, not evidence of absence.
- Callee-aware capability inference **broke the benign-corpus precision gate**
  (52/52 clean → 51/52, 0 → 3 false positives). Precision is the brand, so it went back.

**A regression found and fixed.** `knowledge_search` had been dropped from the
untrusted-input vocabulary, so AG-TRIFECTA had silently stopped firing on RAG agents —
the canonical case. Restored, with a regression test; benign corpus held at 0
adjudicated false positives.

**AG-RUGPULL shipped, opt-in.** Tool-description pinning existed in the codebase with
**zero callers**. Now wired behind `lucin scan --pin`, with a dangerous-delta gate so a
benign wording change does not alarm — only a description that gains
exec/exfil/secret language does.

**Documentation for 11 previously undocumented rules.** A third of the rule set had
only an OWASP mapping, so `lucin explain` had nothing to say about it. Written from
each detector's real trigger condition, with thresholds quoted from the code.

**Website.** First real site: 35 pages generated from content that already existed as
markdown, full meta/Open Graph/JSON-LD, AI-crawler-friendly `robots.txt`, and a
reproducible gate (`python site/check_site.py`) that enforces — among other things —
that a page may not cite our favourable precision number without the unfavourable one
beside it. That rule immediately caught four of our own blog posts.

---

## 2026-07-29

**Trained admission detector.** Regex-only prompt-injection triage measured **8.4%
recall** on a real third-party corpus — a hard ceiling, so it was replaced by a small
local classifier: **67.2% recall at a 1% benign false-positive budget** (TF-IDF/ONNX,
no network). Caught and fixed an overfit and a gate-band false-positive bug along the way.

**Session-level behavioural detection.** Per-event alerting was unusable — multiple
comparisons produced a **96% benign session false-positive rate**. Redesigned around
session-level two-scale conformal testing with per-role Wilson bounds:
**3.75% benign session FP** on a synthetic adversarial corpus. Labelled synthetic
everywhere, and kept out of headline claims.

**GUARD blocked a real exfiltration, live.** A real model performed a plausible task
that emailed a customer's PII to an external address; the deterministic gate blocked
it, and a benign task passed with no false block. Honest finding: the model refused
overt injection attempts on its own — GUARD's value is the DLP leak the model does
*not* recognise.

**A latency claim corrected.** "Sub-millisecond" was wrong. Measured ~5 ms per event,
and the claim was fixed everywhere it appeared.

**Half-Space Trees were ranking anomalies backwards.** A hand-rolled implementation
scored anomalies in reverse (Spearman −0.52 vs a reference implementation). Replaced
with `river`'s. Unit tests had been green throughout.

---

## 2026-07-28

**Deleted more than was added.** Removed the single biggest false-positive generator
(bare method-name matching, where `.get()` implied network access and `.run()` implied
execution), dropped dead code, and disabled a memory-poisoning rule that was
effectively a coin flip until it could be measured.

**First real precision measurement.** Built a benign corpus of real third-party agent
repositories and drove the false-positive rate from **19.5%** to **0 adjudicated false
positives**, fixing **22 distinct false-positive bug classes** on the way.
Reproduce: `python benchmarks/build_benign_corpus.py`.

**Honest README.** Removed claims the code did not support — no "ML ensemble" that
wasn't there, no detector count that didn't match the registry — and added a section
describing what the tool does *not* catch.

**SARIF output + GitHub Action**, so findings appear in the GitHub Security tab and
inline on pull requests.
