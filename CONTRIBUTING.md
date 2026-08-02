# Contributing to AgentGuard

Thank you for helping secure AI agents. Every rule you contribute protects thousands of deployments.

## Ways to Contribute

### 1. Add Detection Rules (Most Impactful)

Detection rules are the core of AgentGuard. Each rule is a pure Python function:

```python
def detect_something(agent: Agent) -> list[Finding]:
    """Detect a specific vulnerability pattern."""
    findings = []
    # Your detection logic here
    return findings
```

**To add a new rule:**

1. Create a file in `src/agentguard/detectors/your_rule.py`
2. Follow the existing patterns (see any file in `detectors/`)
3. Register it in `detectors/__init__.py`
4. Add a test example in `examples/`
5. Verify: zero false positives on safe agents, catches the vulnerability on vulnerable agents

**Rule quality requirements:**
- Every rule MUST have a real-world basis (cite the incident or research)
- Every rule MUST map to OWASP Agentic Top 10
- Every rule MUST include an attack scenario (how it's exploited)
- Every rule MUST include a fix suggestion (actionable, not generic)
- Every rule MUST have zero false positives on our example safe agents
- Prefer precision over recall (missing one is better than 10 false positives)

### 2. Add Red Team Attacks

Attack payloads live in `src/agentguard/redteam/attacks.py` and `redteam/targeted.py`.

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
    owasp_ref="A01 - Excessive Agency",
    real_world_example="Reference to real incident",
)
```

### 3. Add Framework Parsers

Parsers convert framework-specific code into our normalized `Agent` model.

Existing parsers: LangChain, MCP, CrewAI, AutoGen.

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
git clone https://github.com/agentguard/agentguard
cd agentguard
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src/

# Test your changes
agentguard scan ./examples/vulnerable-agent/
```

## Architecture Overview

```
src/agentguard/
├── cli.py              # CLI entry point (typer)
├── models.py           # Core data models (Agent, Tool, Finding)
├── scanner.py          # Orchestrates parsing + detection
├── scoring.py          # Security Score (0-100)
├── reporter.py         # Terminal output (rich)
├── html_report.py      # HTML report generation
├── fix.py              # Code fix generation
├── monitor.py          # Behavioral ML monitoring
├── parsers/            # Framework-specific parsers
│   ├── langchain_parser.py
│   ├── mcp_parser.py
│   ├── crewai_parser.py
│   └── autogen_parser.py
├── detectors/          # Detection rules (one file per category)
│   ├── shell_access.py        # AG-001
│   ├── data_exfiltration.py   # AG-002
│   ├── mcp_auth.py            # AG-003, AG-012
│   ├── overprivilege.py       # AG-005
│   ├── missing_controls.py    # AG-006, AG-009, AG-010
│   ├── secrets.py             # AG-007
│   ├── tool_poisoning.py      # AG-011
│   ├── memory_poisoning.py    # AG-013
│   ├── delegation.py          # AG-014
│   └── supply_chain.py        # AG-015
├── redteam/            # Red team attack engine
│   ├── attacks.py             # Generic attack payloads
│   ├── targeted.py            # Tool-aware targeted attacks
│   ├── indirect_injection.py  # Indirect injection via tool outputs
│   ├── runner.py              # Attack execution + evaluation
│   └── cli.py                 # Red team CLI integration
└── behavioral/         # ML behavioral analysis
    ├── features.py            # 26-dimension feature extraction
    └── scoring.py             # Ensemble anomaly scorer
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
4. Verify: `agentguard scan ./examples/` produces no crashes
5. Submit a PR with description of what the rule detects and why

## Detection Rule ID Allocation

| Range | Category |
|-------|----------|
| AG-001 to AG-004 | Execution & Access |
| AG-005 to AG-008 | Capability & Secrets |
| AG-009 to AG-012 | Controls & Transport |
| AG-013 to AG-016 | Memory & Supply Chain |
| AG-017 to AG-020 | Agent-type Specific |
| AG-021 to AG-025 | Advanced Patterns |
| AG-100+ | Community-contributed rules |

## Questions?

Open a GitHub issue or discussion. We're friendly.
