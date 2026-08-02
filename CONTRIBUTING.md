# Contributing to Lucin

Thank you for helping secure AI agents. Every rule you contribute protects thousands of deployments.

## Ways to Contribute

### 1. Add Detection Rules (Most Impactful)

Detection rules are the core of Lucin. Each rule is a pure Python function:

```python
def detect_something(agent: Agent) -> list[Finding]:
    """Detect a specific vulnerability pattern."""
    findings = []
    # Your detection logic here
    return findings
```

**To add a new rule:**

1. Create a file in `src/lucin/detectors/your_rule.py`
2. Follow the existing patterns (see any file in `detectors/`)
3. Register it in `PER_AGENT_DETECTORS` or `CROSS_AGENT_DETECTORS` in
   `src/lucin/detectors/__init__.py` — a detector module existing in `detectors/`
   does **not** mean it runs; it must be added to one of those two lists, or it
   silently never fires
4. Add a test example in `examples/`
5. Verify: zero false positives on safe agents, catches the vulnerability on vulnerable agents

**Rule quality requirements:**
- Every rule MUST have a real-world basis (cite the incident or research)
- Every rule MUST map to the OWASP Top 10 for Agentic Applications via
  `lucin.owasp.owasp_ref(rule_id)` — never a hardcoded string. Add the rule's
  ASI code(s) to `RULE_TO_ASI` in `src/lucin/owasp.py`, the single source of
  truth for that mapping.
- Every rule MUST include an attack scenario (how it's exploited)
- Every rule MUST include a fix suggestion (actionable, not generic)
- Every rule MUST have zero false positives on our example safe agents
- Prefer precision over recall (missing one is better than 10 false positives)

### 2. Add Red Team Attacks

Attack payloads live in `src/lucin/redteam/attacks.py` and `redteam/targeted.py`.

Each attack is a structured object:
```python
AttackPayload(
    id="RT-XXX",
    name="Human-readable name",
    category=AttackCategory.PROMPT_INJECTION,
    description="What this tests",
    payload="The actual text sent to the agent",
    success_indicators=["patterns", "that", "indicate", "success"],
    safe_response_indicators=["patterns", "indicating", "resistance"],
    severity_if_successful="critical",
    owasp_ref="ASI01",
    real_world_example="Reference to real incident",
)
```

### 3. Add Framework Parsers

Parsers convert framework-specific code into our normalized `Agent` model.

Existing parsers: LangChain, MCP, CrewAI, AutoGen, OpenAI Swarm, PydanticAI, Google ADK,
LlamaIndex, plus a generic fallback.

**Needed:** OpenAI Assistants, Semantic Kernel, Smolagents, custom frameworks.

Interface:
```python
def parse_framework(target: Path) -> list[Agent]:
    """Parse agent definitions from framework-specific files."""
    ...
```

### 4. Improve Accuracy

- Report false positives (open an issue with the code that triggered it)
- Report false negatives (vulnerable code that wasn't caught)
- Suggest better tool capability classification patterns

## Development Setup

```bash
git clone https://github.com/Madhav2310/lucinlabs
cd lucinlabs
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src/

# Test your changes
lucin scan ./examples/vulnerable-agent/
```

## Architecture Overview

```
src/lucin/
├── cli.py              # CLI entry point (typer)
├── models.py           # Core data models (Agent, Tool, Finding)
├── owasp.py            # OWASP Agentic Top 10 (ASI01-10) mapping — single source of truth
├── scanner.py          # Orchestrates parsing + detection
├── scoring.py          # Security Score (0-100)
├── reporter.py         # Terminal output (rich)
├── html_report.py      # HTML report generation
├── fix.py              # Code fix generation
├── monitor.py          # Behavioral ML monitoring
├── parsers/            # Framework-specific parsers (LangChain, MCP, CrewAI,
│                        # AutoGen, Swarm, PydanticAI, Google ADK, LlamaIndex,
│                        # generic fallback)
├── detectors/          # Detection rules (one file per category).
│                        # __init__.py's PER_AGENT_DETECTORS / CROSS_AGENT_DETECTORS
│                        # lists are the source of truth for what actually runs —
│                        # not every file in this directory is registered.
├── redteam/            # Red team attack engine
│   ├── attacks.py             # Generic attack payloads
│   ├── targeted.py            # Tool-aware targeted attacks
│   ├── indirect_injection.py  # Indirect injection via tool outputs
│   ├── runner.py              # Attack execution + evaluation
│   └── cli.py                 # Red team CLI integration
└── behavioral/         # ML behavioral analysis (multi-model ensemble:
                         # frequency/temporal/parameter/structural/sequence)
```

## Code Style

- Python 3.10+
- Type hints everywhere
- Docstrings on all public functions
- Follow ruff defaults (line length 100)
- No external dependencies beyond typer/rich/pyyaml/pydantic for core scanner

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b add-rule-ag-025`)
3. Write the code + tests
4. Verify: `lucin scan ./examples/` produces no crashes
5. Submit a PR with description of what the rule detects and why

## Detection Rule IDs

Rule IDs are not allocated by range — they're assigned per detector as it's added.
The current allocation is always visible directly from the source, not from a table
that can drift from it:

```bash
grep -rhoE 'id="AG-[A-Z0-9-]+"' src/lucin/detectors/*.py | sort -u
lucin scan --list-rules   # active detectors only, with severity + OWASP mapping
```

New community rules: pick the next unused `AG-NNN` (three digits) or a short
descriptive slug like `AG-YOUR-RULE`, matching the existing mix.

## Questions?

Open a GitHub issue or discussion. We're friendly.
