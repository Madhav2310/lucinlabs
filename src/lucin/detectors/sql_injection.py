"""AG-SQL: SQL injection via agent tool parameter.

Corpus-derived detector (2026-07-28). Found live in:
  - AgentOps/smolagents text_to_sql example:
      @tool
      def sql_engine(query: str) -> str:
          rows = con.execute(text(query))   # <-- direct injection

This is a classic SQL injection vulnerability appearing inside agent tool bodies.
The LLM (or an attacker via prompt injection) can send arbitrary SQL through the
tool parameter — including DDL, `DROP TABLE`, `SELECT * FROM secrets`, etc.

Why it's worse in agents than in web apps:
  - The LLM can craft injections that look like legitimate queries
  - The attack surface is the tool's natural-language description, not a login form
  - No user to notice the injected payload — it goes directly to the DB

Detection: intraprocedural taint — does any parameter flow into a SQL execution
sink without going through a whitelist/parameterized-query sanitizer?

Sink signatures: sqlalchemy `execute(text(...))`, cursor.execute, raw f-string SQL.
Sanitizer: parameterized queries (execute("SELECT ... WHERE id = ?", (user_id,))),
ORM query builders (session.query, Model.filter_by).
"""

import ast
from lucin.models import Agent, Finding, Severity, ToolCapability
from lucin.parsers.body_inspector import _resolve_call_name
from lucin.owasp import owasp_ref


# SQL execution sinks that accept raw strings (dangerous)
_SQL_EXEC_SINKS = {
    # Django ORM raw — passes string directly to DB
    "raw", "RawSQL",
    # pandas — reads arbitrary SQL string
    "read_sql", "read_sql_query",
}

# SQLAlchemy text() is dangerous ONLY as a bare function call, not as a method
# (e.g. self.client.text(q) on a search client is NOT a SQL sink).
# Checked separately in _is_sql_sink with a bare-function-only guard.
_SQLA_TEXT_BARE = "text"

# Receiver variable names that indicate a DB cursor/connection.
# When execute() is called on a variable with one of these name patterns,
# it's a SQL execution call, not an orchestration call.
_DB_RECEIVER_NAMES = frozenset({
    "cursor", "cur", "curs",
    "conn", "con", "connection", "cnx", "cx",
    "db", "database", "db_conn",
    "session", "sess",
    "engine", "eng",
    "c",  # common single-letter cursor variable
})

def _is_db_receiver(receiver_name: str) -> bool:
    """True if `.execute()`'s receiver name denotes a DB cursor/connection.

    E3 FIX: the old check was `receiver_name in _DB_RECEIVER_NAMES OR
    any(receiver_name.endswith(n) for n in _DB_RECEIVER_NAMES)`. Because the set
    contains the single letter `"c"` (a common bare-cursor name), the unbounded
    `.endswith("c")` matched ANY receiver ending in 'c' — `self.rc`, `src`,
    `self.logic`, `self.mimic` — turning arbitrary `.execute()` calls into
    "SQL sinks" (a false-positive class). We keep the exact-match set (so a
    literal `c.execute(query)` still counts) but require a SEPARATOR BOUNDARY for
    the suffix form: `_session`/`db_conn` match (`_<name>`), while `src`/`rc`/
    `logic` do not.
    """
    if receiver_name in _DB_RECEIVER_NAMES:
        return True
    return any(receiver_name.endswith("_" + n) for n in _DB_RECEIVER_NAMES)


# Parameterized-query patterns that ARE safe (sanitizers)
_SAFE_PATTERNS = {
    "filter_by", "filter", "where", "select", "insert", "update", "delete",
    "Model.objects", "session.query",
}


# SQLAlchemy / ORM construct builders. A value produced by one of these is a
# parameterized statement object — the driver binds the values, so interpolation
# is impossible. `text()` is deliberately ABSENT: `text(f"... {x}")` is the real
# injection vector and must keep flowing taint.
_ORM_CONSTRUCTORS = {
    "select", "insert", "update", "delete", "where", "filter", "filter_by",
    "join", "outerjoin", "order_by", "group_by", "having", "limit", "offset",
    "values", "returning", "options", "with_entities", "scalar_subquery",
    "subquery", "exists", "union", "union_all", "distinct", "add_columns",
}


def _is_orm_parameterized(value_node) -> bool:
    """True iff this expression is a pure ORM construct chain (safe by binding).

    Requires BOTH: (a) at least one ORM constructor call in the expression, and
    (b) no raw-SQL construction anywhere in it — no `text(...)`, no f-string, no
    `%`/`+` string building. So `select(T).where(T.id == arg)` is safe, while
    `select(text(f"... {arg}"))` and `"SELECT " + arg` remain dangerous.
    """
    saw_orm = False
    for n in ast.walk(value_node):
        if isinstance(n, ast.JoinedStr):          # f-string → raw SQL building
            return False
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
            return False                          # concat / %-format
        if isinstance(n, ast.Call):
            fname = (n.func.attr if isinstance(n.func, ast.Attribute)
                     else n.func.id if isinstance(n.func, ast.Name) else "")
            if fname == "text":                   # sqlalchemy.text() → raw SQL
                return False
            if fname in ("format", "join") and isinstance(n.func, ast.Attribute):
                return False                      # "...".format(x) / "".join(...)
            if fname in _ORM_CONSTRUCTORS:
                saw_orm = True
    return saw_orm


def _parameter_reaches_sql_sink(func_node) -> list[str]:
    """Return param names that flow into a SQL sink without parameterization."""
    # LiteralString (PEP 675) and other non-dynamic types cannot carry
    # user-controlled data at type-check time — credit them as safe.
    _SAFE_PARAM_TYPES = {"LiteralString", "int", "float", "bool", "Literal"}

    def _is_safe_annotation(ann) -> bool:
        if ann is None:
            return False
        if isinstance(ann, ast.Name) and ann.id in _SAFE_PARAM_TYPES:
            return True
        if isinstance(ann, ast.Attribute) and ann.attr in _SAFE_PARAM_TYPES:
            return True
        return False

    param_names = {
        a.arg for a in func_node.args.args
        if not _is_safe_annotation(a.annotation)
    } - {"self", "cls", "ctx", "context"}
    if not param_names:
        return []

    tainted: set[str] = set(param_names)
    violations: list[str] = []

    # Propagate taint through assignments
    changed = True
    while changed:
        changed = False
        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign):
                # A SQLAlchemy/ORM CONSTRUCT binds its parameters — the result is
                # a parameterized statement object, NOT a raw SQL string. Blindly
                # tainting it made `stmt = select(T).where(T.id == arg)` followed
                # by `session.execute(stmt)` look like injection: the single
                # largest AG-SQL false-positive class, 0 true positives across
                # 81 real agent repos (onyx x3, kotaemon x2, private-gpt).
                # `text(...)` and string building stay DANGEROUS (see below).
                if _is_orm_parameterized(node.value):
                    continue
                rhs_names = {n.id for n in ast.walk(node.value)
                             if isinstance(n, ast.Name)}
                if rhs_names & tainted:
                    for target in node.targets:
                        for n in ast.walk(target):
                            if isinstance(n, ast.Name) and n.id not in tainted:
                                tainted.add(n.id)
                                changed = True

    # Check: does any call to a SQL sink have a tainted argument?
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue

        # Get method and receiver information for precise sink matching
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            # Get receiver name. Handle both simple names (cursor.execute) and
            # attribute receivers (self._session.execute, self.conn.execute) —
            # for the latter, use the LAST attribute (._session → "session").
            # This is the common real-world form (found missing on LlamaIndex's
            # Cassandra CQL wrapper, a real documented injection).
            receiver = node.func.value
            if isinstance(receiver, ast.Name):
                receiver_name = receiver.id.lower()
            elif isinstance(receiver, ast.Attribute):
                receiver_name = receiver.attr.lower()
            else:
                receiver_name = ""
        elif isinstance(node.func, ast.Name):
            method = node.func.id
            receiver_name = ""
        else:
            continue

        full_name = _resolve_call_name(node) or ""

        # Is this call a SQL sink?
        # Case 1: known dangerous bare methods (raw, RawSQL, read_sql)
        # Case 2: SQLAlchemy text() — ONLY as a bare function call, not .text() method
        # Case 3: .execute() on a known DB receiver variable name
        is_bare_call = isinstance(node.func, ast.Name)
        is_sink = (
            method in _SQL_EXEC_SINKS
            or full_name in _SQL_EXEC_SINKS
            or (is_bare_call and method == _SQLA_TEXT_BARE)  # bare text(q), not obj.text(q)
            or (method == "execute" and _is_db_receiver(receiver_name))
        )
        if not is_sink:
            continue

        # Check if any argument is tainted
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        for arg in all_args:
            arg_names = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
            if arg_names & tainted:
                # Confirm it's not wrapped in a parameterized call
                # (e.g. execute("SELECT ... WHERE id = ?", params))
                if _is_parameterized(node):
                    continue
                violations.extend(arg_names & tainted)

    return list(set(violations))


# SQLAlchemy ORM builder functions — when used as first argument to execute(),
# they generate parameterized SQL internally. Not a raw injection vector.
_SQLA_ORM_BUILDERS = frozenset({
    "select", "insert", "update", "delete", "text",
    "Select", "Insert", "Update", "Delete",
})


def _is_orm_builder_chain(node: ast.expr) -> bool:
    """Return True if node is (or chains from) a SQLAlchemy ORM builder call.

    Handles: delete(T).where(...), select(T).filter(...).limit(n), etc.
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    # Direct call: delete(T), select(T)
    if isinstance(func, ast.Name) and func.id in _SQLA_ORM_BUILDERS:
        return True
    # Attribute call: somebuilder.where(...), somebuilder.filter(...)
    if isinstance(func, ast.Attribute):
        if func.attr in _SQLA_ORM_BUILDERS:
            return True
        # Recurse into the receiver: delete(T).where(...) → check delete(T)
        return _is_orm_builder_chain(func.value)
    return False


def _is_parameterized(call_node: ast.Call) -> bool:
    """Return True if the call uses parameterized query syntax (second arg is params)."""
    if not call_node.args:
        return False

    first_arg = call_node.args[0]

    # SQLAlchemy ORM: execute(select(...)), execute(delete(...).where(...))
    # The first argument may be a chained builder: delete(T).where(T.id == x)
    if _is_orm_builder_chain(first_arg):
        return True

    # Classic parameterized: execute("SELECT ...", (param,)) or {"p": val}
    if len(call_node.args) >= 2:
        second_arg = call_node.args[1]
        if isinstance(second_arg, (ast.Tuple, ast.List, ast.Dict)):
            return True
    for kw in call_node.keywords:
        if kw.arg in ("params", "parameters", "values", "bindparams"):
            return True
    return False


def detect_sql_injection(agent: Agent) -> list[Finding]:
    """Detect tool parameters flowing directly into SQL execution sinks."""
    findings = []
    scanned: set[str] = set()

    sources = set()
    if agent.source_file:
        sources.add(agent.source_file)
    for tool in agent.tools:
        if tool.source_file:
            sources.add(tool.source_file)

    for filepath in sources:
        if filepath in scanned:
            continue
        scanned.add(filepath)

        try:
            source = __import__("pathlib").Path(filepath).read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            continue

        for node in ast.walk(tree):
            # E2: async def tools reach SQL sinks exactly like sync ones.
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            sql_in_name = any(kw in node.name.lower()
                             for kw in ("sql", "query", "db", "database", "execute"))
            has_str_param = any(
                isinstance(a.annotation, ast.Name) and a.annotation.id == "str"
                for a in node.args.args
            )
            if not (sql_in_name or has_str_param):
                continue

            # Exclude DDL schema-management functions (corpus: mem0 vector stores).
            # create_col/create_table/drop_index are schema setup, not query injection.
            ddl_in_name = any(kw in node.name.lower() for kw in (
                "create_col", "create_table", "create_index", "drop_table", "drop_index",
                "alter_table", "create_schema", "init_schema", "setup_db", "setup_table",
                "ensure_table", "migrate", "create_collection", "init_collection",
            ))
            if ddl_in_name:
                continue

            violated_params = _parameter_reaches_sql_sink(node)
            if not violated_params:
                continue

            findings.append(Finding(
                id="AG-SQL",
                title=f"SQL Injection via Tool Parameter: '{node.name}'",
                severity=Severity.CRITICAL,
                description=(
                    f"Function '{node.name}' passes parameter(s) {violated_params} "
                    f"directly into a SQL execution sink without parameterization.\n\n"
                    f"Corpus evidence: this exact pattern (def sql_engine(query: str): "
                    f"con.execute(text(query))) appeared in real agent repos. An attacker "
                    f"via prompt injection can send arbitrary SQL."
                ),
                agent_name=agent.name,
                attack_scenario=(
                    "1. Attacker embeds SQL injection in a document the agent processes\n"
                    "2. Agent calls this function with the injected payload\n"
                    "3. Raw SQL executes against the database\n"
                    "Example: 'Find x UNION SELECT password FROM admin_users --'"
                ),
                blast_radius=(
                    "Full read/write access to the database as the connection user. "
                    "Possible: table deletion, credential extraction, lateral movement."
                ),
                owasp_ref=owasp_ref("AG-SQL"),
                fix_suggestion=(
                    "Use parameterized queries — NEVER pass tool parameters directly to SQL:\n"
                    "  # UNSAFE: con.execute(text(query))\n"
                    "  # SAFE:   con.execute(text('SELECT ... WHERE name = :n'), {'n': val})\n"
                    "  # Or use an ORM (SQLAlchemy session.query, Django ORM filter)"
                ),
                source_file=filepath,
                source_line=node.lineno,
                witness=[f"param(s) {violated_params} → SQL sink in '{node.name}' (line {node.lineno})"],
            ))

    # de-duplicate
    seen: set[tuple] = set()
    unique = []
    for f in findings:
        key = (f.source_file, f.source_line, str(f.witness))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
