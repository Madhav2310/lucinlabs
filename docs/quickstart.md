# Quickstart

Get from zero to a real finding in under a minute. No API keys, no config file, no signup.

## Install

From PyPI (once published):

```bash
pip install lucin
```

From source (this repo):

```bash
python -m venv venv
venv/bin/pip install -e .
```

Verify the install:

```bash
lucin --help
```

## Scan an agent

Point `scan` at a directory or a single file. It parses the agent's tool code,
classifies each tool's capabilities, and flags dangerous configurations.

```bash
lucin scan ./my-agent/
```

Try it on the bundled vulnerable example:

```bash
lucin scan examples/vulnerable-agent/
```

You'll get a set of findings (each with a rule ID, severity, attack narrative, blast
radius, OWASP mapping, and a concrete fix) plus a 0-100 security score.

## Machine-readable output

```bash
# SARIF 2.1.0 — upload to GitHub code scanning / most SAST dashboards
lucin scan ./my-agent/ --format sarif

# OCSF NDJSON — SIEM ingestion
lucin scan ./my-agent/ --format ocsf

# JSON
lucin scan ./my-agent/ --format json
```

The banner and progress chrome are suppressed automatically for machine-readable
formats, so the output is a clean, parseable document.

## Fail a CI build on findings

```bash
lucin scan ./src/agents --ci --fail-on high
```

Exit code is non-zero when a finding at or above the `--fail-on` severity is present, so
it drops straight into a CI gate. See the repo's `examples/ci/` for GitHub Actions and
GitLab CI snippets.

## Other commands

| Command | What it does |
|---------|--------------|
| `lucin info ./my-agent/` | Show the parsed tool inventory without running detections |
| `lucin explain AG-002` | Explain a rule in depth (meaning, impact, fix) |
| `lucin fix ./my-agent/ --id AG-007` | Generate a code fix for findings of that rule |
| `lucin badge ./my-agent/ --style score` | Emit a security-badge SVG for your README |
| `lucin discover` | Find MCP configs across IDEs on this machine |

Commands marked experimental in the README (`redteam`, `monitor`, `serve`) are usable but
not part of the validated core — see [what SCAN misses](/limits/).

## Telemetry

On by default: anonymous counts only (version, OS, framework detected, per-rule
finding counts, timing) — never file paths, code, secrets, or names. Enforced
server-side by an allowlist, not just a promise. Turn off with
`lucin scan --no-telemetry`, `LUCIN_TELEMETRY=0`, or `lucin telemetry disable`.
Full detail in the README's [Telemetry section](https://github.com/Madhav2310/lucinlabs#telemetry).

## What a clean scan means

A clean scan means no known dangerous static patterns were found. It does **not** mean the
agent is safe under all inputs — see the [threat model](/docs/threat-model/) and
[what SCAN misses](/limits/) for exactly what is and isn't covered.

## Next

- [Benchmarks & methodology](/benchmarks/) — reproduce the precision (0 confirmed FP outside a documented per-repo known-capability allowlist) and 76% recall numbers yourself.
- [Threat model](/docs/threat-model/) — the AIFG model and the lethal trifecta.
- [What SCAN misses](/limits/) — the honest "what we don't catch yet."
- [Runtime enforcement (GUARD)](/runtime/) — the same information-flow model, enforced live. Design-partner preview, not GA.
- [How Lucin compares](/compare/) — honest, measured differences against Semgrep and CodeQL.
