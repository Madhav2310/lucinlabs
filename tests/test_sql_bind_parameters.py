"""AG-SQL must flag the query string, never the bind parameters.

WHY THIS TEST EXISTS
--------------------
`_parameter_reaches_sql_sink` checked EVERY argument of a SQL call for taint,
including the parameter values. That meant a correctly parameterised query — the
remediation this detector's own `fix_suggestion` recommends — was flagged exactly
like a genuinely injectable f-string:

    cursor.execute("DELETE FROM t WHERE id = :id", id=vector_id)   # was FLAGGED
    cursor.execute(f"DELETE FROM t WHERE id = {vector_id}")        # correctly flagged

A value passed as a bind parameter cannot alter the structure of the query. That is
the entire point of parameterisation, and it is where the industry draws the line:
Bandit's B608 inspects strings "involved in some form of string building operation"
(`+`, `%`, `.format`, f-string) — the query text, not the values; CodeQL's
py/sql-injection documents query parameters and prepared statements as the
recommended safe way to embed untrusted data. No mainstream SAST flags a bind
parameter.

MEASURED IMPACT (2026-08-04, `python benchmarks/build_benign_corpus.py`)
    before: 12 false positives (5 AG-SQL)
    after :  9 false positives (2 AG-SQL)
    recall: 38/50 unchanged; sql_injection class 6/6 = 100% unchanged

The recall corpus keeps all 6 SQL cases because the real vulnerabilities in them
put taint in the QUERY position (`execute(sql, ...)` where `sql` is a parameter,
and f-strings interpolating a tainted name), while the cleared findings had taint
only in bind positions. Both corpora can now be satisfied at once — before this
fix, "0 false positives" and "100% SQL recall" were not simultaneously reachable,
because mem0/txtai driver methods were labelled TP in one corpus and FP in the other.

If this test fails, AG-SQL has gone back to flagging the fix it recommends.
"""
import textwrap
from pathlib import Path

from lucin.scanner import scan_target


def _scan_source(tmp_path: Path, source: str) -> set[str]:
    """Write an agent module and return the set of function names AG-SQL flagged."""
    (tmp_path / "agent.py").write_text(textwrap.dedent(source))
    flagged: set[str] = set()
    for finding in scan_target(tmp_path).findings:
        if finding.id != "AG-SQL":
            continue
        for witness in finding.witness:
            # witness form: "param(s) [...] → SQL sink in 'name' (line N)"
            if "in '" in witness:
                flagged.add(witness.split("in '")[1].split("'")[0])
    return flagged


SOURCE = """
    import sqlite3
    from langchain.tools import tool

    @tool
    def bind_named(vector_id: str) -> str:
        \"\"\"Named bind parameter — NOT injectable.\"\"\"
        cur = sqlite3.connect("d.db").cursor()
        cur.execute("DELETE FROM items WHERE id = :id", id=vector_id)
        return "ok"

    @tool
    def bind_positional(user_id: str) -> str:
        \"\"\"Positional bind parameters — NOT injectable.\"\"\"
        cur = sqlite3.connect("d.db").cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return "ok"

    @tool
    def interpolated(vector_id: str) -> str:
        \"\"\"f-string into the query text — genuinely injectable.\"\"\"
        cur = sqlite3.connect("d.db").cursor()
        cur.execute(f"DELETE FROM items WHERE id = {vector_id}")
        return "ok"

    @tool
    def passthrough(sql: str) -> str:
        \"\"\"Caller-supplied SQL in the query position — injectable.\"\"\"
        cur = sqlite3.connect("d.db").cursor()
        cur.execute(sql, limit=10)
        return "ok"

    @tool
    def interpolated_with_binds(table: str, vector_id: str) -> str:
        \"\"\"Tainted query text does not become safe just because a bind exists.\"\"\"
        cur = sqlite3.connect("d.db").cursor()
        cur.execute(f"DELETE FROM {table} WHERE id = :id", id=vector_id)
        return "ok"

    @tool
    def interpolated_with_tuple_params(table: str, uid: str) -> str:
        \"\"\"Same, with a positional params TUPLE.\"\"\"
        cur = sqlite3.connect("d.db").cursor()
        cur.execute(f"DELETE FROM {table} WHERE id = ?", (uid,))
        return "ok"

    @tool
    def interpolated_with_dict_params(table: str, uid: str) -> str:
        \"\"\"Same, with a params DICT.\"\"\"
        cur = sqlite3.connect("d.db").cursor()
        cur.execute(f"SELECT * FROM {table} WHERE id = :id", {"id": uid})
        return "ok"

    @tool
    def kwargs_splat(payload: dict) -> str:
        \"\"\"execute(**payload) — query unresolvable, must fail closed.\"\"\"
        cur = sqlite3.connect("d.db").cursor()
        cur.execute(**payload)
        return "ok"

    @tool
    def starred_args(args: tuple) -> str:
        \"\"\"execute(*args) — query unresolvable, must fail closed.\"\"\"
        cur = sqlite3.connect("d.db").cursor()
        cur.execute(*args)
        return "ok"
"""


def test_bind_parameters_are_not_injection_sites(tmp_path):
    """The remediation must not be reported as the vulnerability."""
    flagged = _scan_source(tmp_path, SOURCE)
    assert "bind_named" not in flagged, (
        "AG-SQL flagged a named bind parameter — that is the recommended fix, "
        "not an injection. See _query_expr in detectors/sql_injection.py."
    )
    assert "bind_positional" not in flagged, (
        "AG-SQL flagged a positional bind parameter (execute(sql, (user_id,)))."
    )


def test_query_position_taint_still_fires(tmp_path):
    """The precision fix must not cost recall — these are real injections."""
    flagged = _scan_source(tmp_path, SOURCE)
    assert "interpolated" in flagged, "AG-SQL missed an f-string SQL injection"
    assert "passthrough" in flagged, (
        "AG-SQL missed caller-supplied SQL passed straight into execute()"
    )


def test_bind_parameter_does_not_launder_a_tainted_query(tmp_path):
    """A bind parameter elsewhere in the call must not whitelist a tainted query.

    The dangerous inverse of this fix: treating "this call has parameters" as a
    blanket sanitizer would let `execute(f"DELETE FROM {table} ...", id=x)` pass.
    Only the query ARGUMENT is exempt from suspicion, never the whole call.
    """
    flagged = _scan_source(tmp_path, SOURCE)
    for name in ("interpolated_with_binds",
                 "interpolated_with_tuple_params",
                 "interpolated_with_dict_params"):
        assert name in flagged, (
            f"AG-SQL let a tainted table name through in {name}() because the call "
            "also had bind parameters — parameterisation exempts the parameter "
            "positions, never the query text itself."
        )


def test_unresolvable_query_position_fails_closed():
    """A query we cannot resolve statically must be analysed, not skipped.

    `execute(**payload)` and `execute(*args)` put the query text behind a splat.
    Returning "no query expression found" and skipping would make the most opaque
    call sites the safest-looking ones — precisely backwards. The `**payload` form
    was missed by an earlier version of this fix.

    Asserted against `_parameter_reaches_sql_sink` directly, not through
    `scan_target`, because `detect_sql_injection` applies a SEPARATE, pre-existing
    reachability pre-gate first (sql_injection.py: the function must have a
    DB-ish name — sql/query/db/database/execute — or at least one `str`
    parameter). These fixtures take `dict`/`tuple`, so the pre-gate skips them
    before taint analysis ever runs. That gate is a deliberate precision
    heuristic and is out of scope for this fix — but note the false-negative path
    it implies: a tool named e.g. `helper(payload: dict)` doing
    `cursor.execute(**payload)` is invisible to AG-SQL regardless of taint.
    """
    import ast

    from lucin.detectors.sql_injection import _parameter_reaches_sql_sink

    tree = ast.parse(textwrap.dedent(SOURCE))
    by_name = {
        n.name: n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert _parameter_reaches_sql_sink(by_name["kwargs_splat"]) == ["payload"], (
        "execute(**payload) was skipped — _query_expr returned None instead of "
        "failing closed on the splat"
    )
    assert _parameter_reaches_sql_sink(by_name["starred_args"]) == ["args"], (
        "execute(*args) was skipped instead of failing closed"
    )
