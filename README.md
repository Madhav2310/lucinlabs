# Lucin

[![PyPI](https://img.shields.io/pypi/v/lucin.svg)](https://pypi.org/project/lucin/)
[![Tests](https://img.shields.io/badge/tests-553%20passing-brightgreen)](https://github.com/Madhav2310/lucinlabs/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/lucin.svg)](https://pypi.org/project/lucin/)

**A tool called `get_weather` can contain `subprocess.run`.**

Most agent security scanners read the tool's name, decide it looks fine, and move on. Lucin reads the function body, works out what each tool can actually reach, and reports the path from untrusted input to your data leaving the building, with a file and a line number.

```bash
pip install lucin
lucin scan ./my-agent/
```

No API key. No config file. No account. Your code never leaves your machine.

![Lucin scanning a vulnerable agent](lucin-scan.gif)

## What a finding looks like

```
── CRITICAL · AG-TRIFECTA ──────────────────────────────
Untrusted input reaches an external sink
  Agent:  support_agent
  Proof:  control: read_email      → __llm__ → post_webhook
          data:    query_customers → __llm__ → post_webhook
  Fix:    restrict 1 tool to break every exfil path:
          post_webhook (allow-list hosts, or require approval)
  OWASP:  LLM06 Excessive Agency
  Location: agents/support.py:88
```

Three tools. None of them is a mistake on its own. `read_email` takes in bytes you do not control, `query_customers` reads private data, `post_webhook` can reach the internet. Wired together, they are an exfiltration path, and no code review that looks at functions one at a time will ever see it.

That is the class of bug Lucin exists to find: the one that lives between your tools rather than inside any of them.

## The numbers, including the bad ones

Every figure here ships with the command that regenerates it. Run them instead of trusting me.

| | | Regenerate |
|---|---|---|
| **11** | adjudicated false positives across **54 real repositories / 9,520 files**. 45 of 54 scan completely clean. | `python benchmarks/build_benign_corpus.py` |
| **76%** | recall. 38 of 50 vulnerabilities across 10 classes. Which means a **24% false-negative rate**, and 86% (19/22) on the real third-party cases. | `python benchmarks/recall_corpus.py` |
| **20.5–31.5%** | precision on a broader, deliberately uncurated 81-repo population (n=73 clean-holdout, 95% CI 12.9–42.9%). | `python benchmarks/agentzoo_precision.py --report-only` |
| **30** | active detectors, every one mapped to OWASP Agentic. | `lucin scan --list-rules` |
| **8** | frameworks, plus a generic parser and Agent Skills bundles. | `lucin scan --list-adapters` |

Test suite: **553 passing (15 skipped, 1 xfailed)**, via `python -m pytest tests/ -q` with the `behavioral` extra installed (`pip install -e ".[dev,behavioral]"`).

### Read the third row again

Eleven false positives on a curated benign corpus is a good number. Twenty to thirty percent precision on a population I did not choose is not. Both are true, they answer different questions, and publishing only the first would be a lie of omission.

An earlier precision figure of 58% was computed over the same labels used to build the precision filters, which is training on the test set. It is withdrawn.

**And this number used to be wrong.** The false-positive count was published for months as "0 across 52 repos / 2,732 files." The corpus grew, the claim did not, and nobody noticed until someone re-ran the command. It was corrected on 2026-08-04, and `benchmarks/regression_snapshot.py` now fails the build if any published number drifts from what the harness prints.

That correction is the most useful thing in this README. A security tool that has never published a number it later had to retract has probably never published a checkable number.

### The detector I turned off

Path-traversal recall is **0%**. Not because the detector failed. I built it, unit-tested it, and watched it catch real bugs.

Then I unregistered it, because the benign corpus is full of legitimate file tools that are byte-identical to the attack:

```python
open(param)
os.path.join(base, name)
```

Shipping it would have raised recall on the slide and added false positives in your repository. So the class reads 0%.

`AG-SSRF` is the same trade, smaller: it fires only when tainted data forms the URL host, which costs most of that class and buys quiet. SSRF recall is 17%.

Precision over recall is a policy here, not a slogan. The [limits page](https://lucin.pages.dev/limits) names all 12 misses.

## Commands

| Command | Purpose | Status |
|---|---|---|
| `lucin scan` | Find security issues in agent tool code | Stable |
| `lucin info` | Agent inventory, no detections | Stable |
| `lucin explain` | Explain a finding: meaning, impact, fix | Stable |
| `lucin fix` | Generate code fixes | Stable |
| `lucin discover` | Find MCP configs across IDEs on this machine | Stable |
| `lucin badge` | Security-score badge SVG | Stable |
| `lucin redteam` | Adversarial payloads built from your own tool names | Experimental |
| `lucin monitor` | Behavioural deviation scoring on agent traces | Experimental |
| `lucin serve` | REST API | Experimental |

```bash
lucin scan ./my-agent/ --ci --fail-on high     # exit 1 on findings at/above threshold
lucin scan ./my-agent/ --format sarif          # GitHub code scanning
lucin scan ./my-agent/ --format ocsf           # SIEM
lucin fix ./my-agent/ --id AG-007
lucin redteam ./my-agent/ --dry-run
```

## How it works

Parsers turn LangChain, MCP, CrewAI, AutoGen, Swarm, PydanticAI, Google ADK, LlamaIndex, Agent Skills or plain `@tool` Python into one normalised model of agents and tools. Detectors run over that model. Findings carry a rule ID, a severity, an OWASP mapping, and a witness you can open.

Two things make the output different from a grep with opinions.

**Capability classification, not name matching.** Each tool is classified by what its code actually reaches: shell execution, network egress, secret access, untrusted input. `get_weather` containing `subprocess.run` is classified as shell execution regardless of what it is called.

**Evidence-bounded severity.** A CRITICAL or HIGH finding with no witness and no source line is capped to MEDIUM, because a reader cannot check it. Measured on the precision corpus: findings with a witness or a line ran at 50% precision, findings with neither at 11%. The gate is in `src/lucin/detectors/__init__.py`.

Every scan also prints a 0-100 score, which is a summary of the findings rather than a verdict on the agent: 90+ means no critical or high findings, below 50 means serious ones. Use the findings, not the number.

Full rule list, generated from the shipping source so it cannot drift: **[lucin.pages.dev/rules](https://lucin.pages.dev/rules)**.

## What it does not catch

Lucin is a static, pre-deploy scanner. It finds enabling misconfigurations before you ship. It does not detect novel zero-days, catch anything that only exists at execution time, or fix the model's intent. A clean scan means no known dangerous pattern was found in static configuration. It does not mean the agent is safe under all inputs.

The most important limitation, stated plainly: **there is no whole-program interprocedural taint analysis.** What runs is single-function flow-sensitive taint over each tool body, plus limited same-file method-to-method flows wired into the SSRF, deserialization and path-traversal detectors. Across functions, Lucin approximates by classifying capabilities and flagging dangerous combinations rather than proving a literal data-flow path. That recovers most incident-class patterns and it is not path-level proof, so a vulnerability whose source and sink live in different files, where no single tool holds the dangerous combination alone, can be missed.

Languages: Python source, MCP and agent JSON configs, Agent Skills (`SKILL.md` + YAML), and shell. TypeScript, Java, Go, Rust, C#, Ruby, PHP and Swift are **not enumerated at all**.

A target with no supported files reports `NOT ANALYSED` and never a clean scan: no score, no badge, and `--ci` exits **2** rather than 0. Every scan prints a coverage line, so under-coverage is never silent.

MCP config scanning is language-independent by construction. A Go or Rust MCP server's implementation is invisible to Lucin, but its wiring, meaning overprivilege, unpinned `npx -y`, tokens in `env` and filesystem-root grants, is JSON, and that is where most MCP risk lives.

Full matrix and reasoning: [`docs/limits.md`](docs/limits.md).

## Runtime and red team

`lucin redteam` builds attacks from your agent's actual tool names rather than a generic prompt-injection list, then reports which succeeded and with what evidence. Experimental.

There is also a runtime layer (GUARD) that enforces the same information-flow model the scanner uses statically: the path found in CI is the path blocked in production, sharing one engine rather than two that can drift. In a recorded live-LLM run, a real model emailed a customer's PII to an external address and the gate blocked it deterministically (`benchmarks/guard_live_llm.py`), with 0 false blocks out of 6 benign tasks (`benchmarks/guard_falseblock.py`).

It is a design-partner preview with **zero production deployments**, and the behavioural anomaly layer is validated on synthetic corpora only. What is proven and what is not: [lucin.pages.dev/runtime](https://lucin.pages.dev/runtime).

## CI

```yaml
- uses: Madhav2310/lucinlabs@v1
  with:
    scan-path: './src/agents'
    fail-on: 'high'
```

GitLab: `examples/ci/gitlab-ci.yml`.

**Adopting into a repo that already has findings.** You do not have to fix everything first:

```bash
lucin scan . --write-baseline .lucin-baseline.json
git add .lucin-baseline.json && git commit -m "Accept current findings as baseline"
lucin scan . --ci --fail-on high --baseline .lucin-baseline.json
```

CI then fails only on findings that are new. Existing ones still print, marked accepted, so the debt stays visible instead of disappearing.

## Configuration

`.lucin.yml` in your project root:

```yaml
scan:
  fail_on: high
  exclude_rules: [AG-010]
monitor:
  baseline_actions: 50
  alert_threshold: 60
```

## Telemetry

Anonymous usage counts are **on by default**, and you should hear that from me rather than find it.

**Sent:** Lucin version, Python version, OS, which framework was detected, agent/tool/file *counts*, scan duration, per-rule finding *counts* (`{"AG-001": 2}`, a rule ID and a number), and a random per-machine UUID so ten scans from one user are distinguishable from ten users.

**Never sent:** file paths, repository names, source code, secret values, witness text, or tool and agent names. The collector ([`site/functions/api/telemetry.js`](site/functions/api/telemetry.js), open source in this repo) enforces that server-side with a strict allowlist, so it holds even if a future client tried to send more.

**Off:** `--no-telemetry` for one run, `LUCIN_TELEMETRY=0`, or `lucin telemetry disable` to persist. `lucin telemetry status` prints exactly what the last scan sent.

The default flips to opt-in at 1,000 installs or 90 days after launch, whichever comes first.

## Why this exists

In July 2026 an autonomous agent took an estimated 17,600 actions inside [Hugging Face's infrastructure](https://huggingface.co/blog/security-incident-july-2026) over roughly two and a half days. It was not a clever exploit. A malicious dataset ran code, the code read credentials, the credentials opened doors, and nobody was watching, because no human can watch 17,600 of anything.

Every agent with tool access has that skeleton. The question worth answering before you ship is which of your tools compose into the same shape.

Lucin answers it in under a second on a typical agent. [Full teardown of that incident](https://lucin.pages.dev/blog/hugging-face-agent-breach/).

## Contributing

Detection rules are pure functions: `Agent → list[Finding]`. See [CONTRIBUTING.md](CONTRIBUTING.md).

The single most useful thing you can send is a false positive. If Lucin fires on something in your repository that is not real, open an issue with the snippet. That is worth more to this project than a star.

## License

MIT
