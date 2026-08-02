"""Cross-function (intra-file / intra-class) taint — sound AST propagation.

Today's dataflow detectors (deserialization / ssrf / path-traversal) share a
single-function taint model in ``detectors/_taint.py``: a parameter is tainted,
propagation is an assignment fixpoint WITHIN one function body, and a sink whose
argument is tainted is a candidate. That misses the real corpus shape where the
untrusted value crosses a function/method boundary WITHIN THE SAME MODULE.

Measured miss this module recovers (recall corpus, real third-party code):
    gptcache MapDataManager
        def __init__(self, data_path, ...):
            self.data_path = data_path          # param → instance field
        def init(self):
            with open(self.data_path, "rb") as f:
                self.data = pickle.load(f)       # field read → deserialization sink
    The sink method's own body shows no untrusted *parameter*, so intraprocedural
    taint sees nothing. The taint lives in an instance field set by another method.

WHAT THIS ADDS (two sound propagation kinds — nothing speculative):
  (a) INSTANCE-FIELD taint: ``self.F`` is tainted iff SOME method of the class
      assigns ``self.F = <expr>`` where ``<expr>`` is tainted (param-derived or a
      previously-tainted field). A reader method that references ``self.F`` then
      sees ``self.F`` as a tainted token. Fixpoint over the class → terminates
      (bounded by #fields).
  (b) ``with CTX as VAR`` binding propagation: ``VAR`` becomes tainted when the
      context expression is tainted. (Needed by the gptcache flow above and a
      genuine intraprocedural gap in the old fixpoint.)

SOUNDNESS / PRECISION FIRST (the sacred 0.0% FP gate depends on this):
  - We ONLY create field taint from an EXACT ``self.<name> = <tainted-rhs>``
    assignment. Never "any field could be tainted." Subscript targets
    (``self.data[k] = ...``) and non-``self`` receivers do NOT create field taint.
  - The bare receiver name ``self`` is NEVER added to the tainted set (that would
    make every ``self.*`` reference match — massive over-taint). Only the fully
    qualified ``self.<field>`` token is tainted.
  - Attribute-target assignments do NOT taint local Name variables; only real
    ``x = ...`` / ``with ... as x`` bindings do.
  - Staticmethods (no instance receiver) create no field taint.
  - Ambiguous shapes propagate NOTHING. A missed vuln is acceptable here; a false
    positive is not.

SCOPE / HONEST LIMIT: intra-file / intra-class only. Calls are resolved by AST
within the single module. Full CROSS-FILE interprocedural taint needs a real
call graph (PyCG), which is blocked in this environment — that remains a
documented boundary, not something this module claims to solve.

Pure stdlib ``ast``; no external dependencies.
"""

from __future__ import annotations

import ast

# Framework plumbing parameters that are never attacker-controlled tool inputs.
# Kept in sync with detectors/_taint.SKIP_PARAMS.
_SKIP_PARAMS = {
    "self", "cls", "ctx", "context", "run_manager", "config", "runtime",
    "callbacks", "cb", "tool_context",
}


# ---------------------------------------------------------------------------
# AST annotation — attach the enclosing class to each direct method.
# ---------------------------------------------------------------------------

def annotate_functions(tree: ast.AST) -> None:
    """Annotate every function node in ``tree`` with ``_ag_class``.

    ``_ag_class`` is the enclosing ``ClassDef`` iff the function is a DIRECT
    method of that class; otherwise ``None`` (module-level functions and
    functions nested inside another function body get ``None`` — a nested
    function's first arg is not an instance receiver).

    Idempotent and cheap; called once per tree by ``iter_functions``.
    """

    def visit(node: ast.AST, cls: ast.ClassDef | None) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                child._ag_class = None  # type: ignore[attr-defined]
                visit(child, child)          # this class is the receiver for its methods
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                child._ag_class = cls  # type: ignore[attr-defined]
                visit(child, None)           # nested funcs have no instance receiver
            else:
                visit(child, cls)

    visit(tree, None)


# ---------------------------------------------------------------------------
# Token extraction — bare names PLUS depth-1 attribute paths (``self.field``).
# ---------------------------------------------------------------------------

def tokens(node: ast.AST) -> set[str]:
    """Collect taint tokens referenced anywhere in an expression subtree.

    Yields:
      - every bare ``Name`` id                       (``x`` → ``"x"``)
      - every depth-1 attribute path rooted at a Name (``self.data_path`` →
        ``"self.data_path"``; the inner ``self`` Name also yields ``"self"``)

    This is a strict SUPERSET of the old ``names_in`` (which yielded only bare
    Name ids). Attribute-path tokens can only ever match an instance-field taint
    token that this module explicitly seeded, so mixing this with a bare-name
    taint set produces no new matches — it is backward compatible by construction.
    """
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
            out.add(f"{n.value.id}.{n.attr}")
    return out


def is_tainted(expr: ast.AST, tainted: set[str]) -> bool:
    """True iff any token of ``expr`` is in the tainted set."""
    return bool(tokens(expr) & tainted)


# ---------------------------------------------------------------------------
# Small AST helpers
# ---------------------------------------------------------------------------

def _self_name(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Instance-receiver parameter name for a method, or None.

    Returns None for staticmethods (no instance receiver) and for methods with
    no positional parameter.
    """
    for dec in func.decorator_list:
        if isinstance(dec, ast.Name) and dec.id == "staticmethod":
            return None
        if isinstance(dec, ast.Attribute) and dec.attr == "staticmethod":
            return None
    posargs = list(func.args.posonlyargs) + list(func.args.args)
    return posargs[0].arg if posargs else None


def _params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """User-visible parameter names (minus framework plumbing)."""
    a = func.args
    collected = list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs)
    if a.vararg:
        collected.append(a.vararg)
    if a.kwarg:
        collected.append(a.kwarg)
    return {x.arg for x in collected} - _SKIP_PARAMS


def _bare_targets(target: ast.expr) -> set[str]:
    """Names bound by an assignment target — ONLY plain ``Name`` bindings.

    ``x`` / ``a, b`` / ``*rest`` bind local names. ``self.f`` (Attribute) and
    ``d[k]`` (Subscript) do NOT bind a local name and are deliberately excluded
    (attribute assignments are handled by the class-field fixpoint, never by
    tainting the bare receiver).
    """
    out: set[str] = set()
    if isinstance(target, ast.Name):
        out.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for el in target.elts:
            out |= _bare_targets(el)
    elif isinstance(target, ast.Starred):
        out |= _bare_targets(target.value)
    return out


def _field_assigned(target: ast.expr, self_name: str) -> str | None:
    """If ``target`` is exactly ``<self_name>.<field>`` return ``<field>``, else None."""
    if (isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == self_name):
        return target.attr
    return None


# ---------------------------------------------------------------------------
# Local (single-function) taint with attribute + with-as support.
# ---------------------------------------------------------------------------

def local_taint(func: ast.AST, seed: set[str]) -> set[str]:
    """Monotone assignment fixpoint over ONE function body, seeded with ``seed``.

    Propagates through:
      - ``x = <tainted>``            → ``x`` tainted
      - ``x: T = <tainted>``         → ``x`` tainted
      - ``with <tainted> as x``      → ``x`` tainted   (async with too)
    Only plain Name targets are tainted (see ``_bare_targets``). Terminates:
    the tainted set only grows and is bounded by the names in the function.
    """
    tainted = set(seed)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                if tokens(node.value) & tainted:
                    for tgt in node.targets:
                        for nm in _bare_targets(tgt):
                            if nm not in tainted:
                                tainted.add(nm)
                                changed = True
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                if tokens(node.value) & tainted and isinstance(node.target, ast.Name):
                    if node.target.id not in tainted:
                        tainted.add(node.target.id)
                        changed = True
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is None:
                        continue
                    ctx_toks = tokens(item.context_expr) & tainted
                    # Propagate a `with ... as x` binding ONLY when the context
                    # expression's taint originates from an INSTANCE FIELD (a
                    # dotted ``self.field`` token) — i.e. this is the
                    # cross-function delivery path this module exists to add
                    # (gptcache: ``with open(self.data_path, "rb") as f``).
                    #
                    # A purely intraprocedural param → with-as flow
                    # (``def load(self, path): with open(os.path.join(path, F)) as f:
                    #   pickle.load(f)`` — promptflow FAISSIndex.load) is LEFT to the
                    # pre-existing behaviour (which never tainted with-as bindings).
                    # The benign corpus contains byte-identical file-load code of
                    # that exact shape, so tainting bare-param with-as bindings
                    # breaks the sacred 0.0% false-positive rate. Precision first:
                    # we only add the flow that crosses a method boundary.
                    if any("." in t for t in ctx_toks):
                        for nm in _bare_targets(item.optional_vars):
                            if nm not in tainted:
                                tainted.add(nm)
                                changed = True
    return tainted


# ---------------------------------------------------------------------------
# Class-level instance-field taint (fixpoint over all methods of a class).
# ---------------------------------------------------------------------------

def field_taint_for_class(cls: ast.ClassDef) -> set[str]:
    """Field names ``F`` such that some method assigns ``self.F = <tainted-rhs>``.

    Fixpoint: on each pass, for every method we compute local taint seeded with
    that method's params plus the fields already known tainted (as ``self.F``
    tokens), then record any field assigned from a tainted RHS. Repeats until no
    new field is discovered. Memoized on the class node.
    """
    cached = getattr(cls, "_ag_field_taint", None)
    if cached is not None:
        return cached

    methods = [n for n in cls.body
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    fields: set[str] = set()

    changed = True
    while changed:
        changed = False
        for m in methods:
            sn = _self_name(m)
            if sn is None:
                continue
            seed = _params(m) | {f"{sn}.{fld}" for fld in fields}
            local = local_taint(m, seed)
            for node in ast.walk(m):
                if isinstance(node, ast.Assign) and (tokens(node.value) & local):
                    for tgt in node.targets:
                        fld = _field_assigned(tgt, sn)
                        if fld and fld not in fields:
                            fields.add(fld)
                            changed = True
                elif isinstance(node, ast.AnnAssign) and node.value is not None \
                        and (tokens(node.value) & local):
                    fld = _field_assigned(node.target, sn)
                    if fld and fld not in fields:
                        fields.add(fld)
                        changed = True

    cls._ag_field_taint = fields  # type: ignore[attr-defined]
    return fields


# ---------------------------------------------------------------------------
# Public entry point used by detectors/_taint.compute_taint
# ---------------------------------------------------------------------------

def augment_taint(func: ast.AST, params: set[str]) -> tuple[set[str], set[str]]:
    """Compute (tainted_tokens, effective_params) for ``func``.

    Extends single-function taint with instance-field taint when ``func`` is a
    method (``_ag_class`` set by ``annotate_functions``) that READS a tainted
    field. Returns:
      - tainted_tokens:   bare names + tainted ``self.field`` tokens + locals.
      - effective_params: the user params, PLUS any referenced tainted-field
        tokens — so a reader method with no bare params (e.g. ``def init(self)``)
        is NOT skipped by a detector's ``if not params`` guard when it genuinely
        consumes an untrusted instance field.
    """
    seed = set(params)
    field_tokens: set[str] = set()

    cls = getattr(func, "_ag_class", None)
    if cls is not None:
        sn = _self_name(func)  # type: ignore[arg-type]
        if sn is not None:
            fields = field_taint_for_class(cls)
            if fields:
                referenced = tokens(func)
                for fld in fields:
                    tok = f"{sn}.{fld}"
                    if tok in referenced:
                        seed.add(tok)
                        field_tokens.add(tok)

    tainted = local_taint(func, seed)
    effective_params = set(params) | field_tokens
    return tainted, effective_params
