"""Red-team error types."""


class NoTargetConfigured(RuntimeError):
    """Raised when an attack is attempted with no target to attack.

    Never caught in order to produce a score. Before this existed,
    `redteam/cli.py` substituted `_create_mock_agent()` whenever no `--api`
    endpoint was supplied, so `lucin redteam ./any-agent/` reported a
    resilience score computed from canned responses — identical for every
    input, in 0 ms, with per-attack "evidence" for replies no agent produced.

    Absence of a target is representable. Fabrication is not.
    """
