# Lucin vs Semgrep

Short version: **Semgrep is a better general-purpose SAST tool than Lucin, and Lucin
finds things in AI agents that Semgrep structurally cannot.** They are not substitutes.
If you write Python agents, you probably want both, and Semgrep first.

This page is written to survive being read by a security researcher who uses Semgrep
daily, so it leads with where we lose.

## Where Semgrep is better

- **Breadth.** Semgrep covers 30+ languages with thousands of community rules. Lucin is
  Python-only and ships fewer than 30 detectors.
- **Maturity and ecosystem.** Semgrep has ~16,000 GitHub stars, hundreds of releases, a
  rule registry, an in-browser playground, an IDE integration, and years of production
  use at companies including Dropbox, Figma and Slack. Lucin has none of that, and zero
  users at the time of writing.
- **Custom rules.** Semgrep's pattern language is genuinely excellent: you can express
  a project-specific rule in a few lines of YAML and share it. Lucin's detectors are
  Python, and writing a new one means writing code.
- **Interfile analysis.** Semgrep Pro does cross-file and cross-function dataflow.
  Lucin's interprocedural analysis is an approximation — same-file plus one hop through
  local and `self.*` callees — because the whole-program call graph we wanted is
  unavailable in our build environment. We publish that limit.
- **It is a company with support.** We are pre-launch.

If your question is "how do I find SQL injection and hardcoded secrets across a
polyglot codebase", the answer is Semgrep, not Lucin.

## Where Lucin does something different

**1. The unit of analysis is the agent, not the file.**

Semgrep matches patterns within a file (and, in Pro, across files). Lucin builds an
**information-flow graph over an agent's tool set** and asks whether a path exists from
an untrusted input source, through the model, to a dangerous sink. The dangerous shape
in an agent is usually not a bad line of code — it is three individually reasonable
tools sharing one context:

```
knowledge_search  →  __llm__  →  history_save
(untrusted docs)     (steered)   (egress)
```

No single tool there is a vulnerability. The composition is. A pattern matcher has
nothing to match, because there is no bad pattern — which is why Lucin reports a
**witness path** rather than a line number for these findings.

**2. It understands agent-specific configuration.**

MCP server configs, tool descriptions (which are *instructions to a model*, so
injection in a description is code execution by another route), tool-description drift
between runs (rug-pulls), agent-to-agent handoffs, coding-agent filesystem scope. These
are not Python code patterns, so a Python pattern matcher does not see them.

**3. Precision is published, with an interval and a command.**

This is the part we would ask you to hold us to. Both tools have measured numbers on
real Python code, and neither is flattering:

| | Precision | Measured by | Corpus |
|---|---|---|---|
| Semgrep | 0.205 | RealVuln benchmark, [arXiv:2604.13764](https://arxiv.org/abs/2604.13764) | 26 vulnerable Python repos, 796 hand labels |
| Lucin | 0.58 (95% CI 32–81%, n=12) | our own harness, hand-adjudicated | 81 real agent repos, 5,868 files |

Read that table skeptically, because it is not apples to apples: **different corpora,
different vulnerability classes, and ours is self-measured while Semgrep's is
third-party.** A self-reported number should be trusted less than an independent one.
What we would defend is not any single precision figure but the *practice*: the corpus is named, the
adjudication method is written down, the confidence interval is published, and
`python benchmarks/agentzoo_precision.py` regenerates the number on your machine.

For calibration, commercial SAST precision generally runs **18–36%**, and Meta reports
its own Python taint analyzer (Pysa) at **150 false positives out of 330 detections**
on Instagram server code. Nobody in this field is at 90%. Anyone claiming to be has not
published their method.

**4. We publish what we miss.**

Recall is **76%** (38/50 across 10 vulnerability classes). SSRF detection is 17%. Path
traversal is 0% — the detector exists, is sound and is unit-tested, but stays
unregistered because the benign corpus contains byte-identical legitimate file
operations and registering it would break the precision result. That is a deliberate
trade, and it is on the [limits page](/limits/) rather than buried.

## Using both

They compose cleanly, and this is the honest recommendation:

```bash
semgrep --config=auto .    # general Python/JS/etc. vulnerabilities
lucin scan .               # agent tool graph, MCP configs, information flow
```

Both emit SARIF, so both land in the GitHub Security tab without extra work. Neither
needs an API key for the local path — though note Semgrep's quickstart routes you
through a login for its CI flow, while `lucin scan` never does.

## When you should not use Lucin

- You do not write AI agents. Nothing here applies to you.
- You need language coverage beyond Python. We have none.
- You need a supported product with an SLA today. We are pre-launch and say so.
- You want the highest possible recall and will triage the noise yourself. We chose
  precision over recall, deliberately and in public, and that costs real detections.
