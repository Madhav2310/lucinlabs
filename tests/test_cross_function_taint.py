"""Tests for CROSS-FUNCTION (intra-file / intra-class) taint.

Adds instance-field taint (a param stored in ``self.F`` by one method, read by
another) plus the ``with ... as`` binding delivery it requires. Motivating real
miss: gptcache ``MapDataManager`` — ``self.data_path`` set in ``__init__`` and
``pickle.load(open(self.data_path))`` in ``init()``.

Precision is sacred (flagship = 0.0% FP / 52 repos), so this file carries BOTH
fires-on-vuln AND does-not-fire-on-benign assertions — including a regression
guard for the promptflow ``FAISSIndex.load`` shape (bare-param ``with open(...)``)
that the ``with``-binding step must NOT newly flag.
"""

import ast
import tempfile
import textwrap

from lucin.analysis import cross_function_taint as cft
from lucin.detectors._taint import compute_taint, is_tainted, iter_functions
from lucin.detectors.insecure_deserialization import detect_insecure_deserialization
from lucin.models import Agent, Tool, ToolCapability


def _agent_with_source(source: str) -> Agent:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(textwrap.dedent(source))
        path = f.name
    tool = Tool(name="the_tool", capabilities=[ToolCapability.READ_DATA],
                source_file=path, source_line=1)
    return Agent(name="test_agent", source_file=path, tools=[tool])


def _funcs(source: str) -> dict:
    tree = ast.parse(textwrap.dedent(source))
    fns = list(iter_functions(tree))  # annotates _ag_class as a side effect
    return {fn.name: fn for fn in fns}


# ---------------------------------------------------------------------------
# End-to-end: instance-field taint recovers the gptcache deserialization miss
# ---------------------------------------------------------------------------

def test_instance_field_taint_fires_deserialization():
    # __init__ stores a param in self.data_path; init() pickle-loads a file
    # opened at that field via `with ... as f`. The sink method has no bare
    # parameter of its own — the taint crosses the method boundary.
    src = """\
        import pickle
        class MapDataManager:
            def __init__(self, data_path, max_size):
                self.data = {}
                self.data_path = data_path
                self.init()
            def init(self):
                with open(self.data_path, "rb") as f:
                    self.data = pickle.load(f)
    """
    findings = detect_insecure_deserialization(_agent_with_source(src))
    assert any(f.id == "AG-DESERIALIZE" for f in findings)
    hit = next(f for f in findings if f.id == "AG-DESERIALIZE")
    assert "init" in hit.title


def test_instance_field_direct_pickle_load_fires():
    # Field read passed straight into pickle.load (no intermediate `with`).
    src = """\
        import pickle
        class Loader:
            def __init__(self, blob):
                self.blob = blob
            def run(self):
                return pickle.loads(self.blob)
    """
    findings = detect_insecure_deserialization(_agent_with_source(src))
    assert any(f.id == "AG-DESERIALIZE" for f in findings)


# ---------------------------------------------------------------------------
# Precision guards — must NOT fire (protect the 0.0% FP rate)
# ---------------------------------------------------------------------------

def test_promptflow_shape_bare_param_with_open_does_not_fire():
    # REGRESSION GUARD: a purely intraprocedural param -> `with open(...) as f`
    # -> pickle.load(f) flow. The benign corpus (promptflow FAISSIndex.load) has
    # byte-identical code, so the with-binding step must NOT taint a bare-param
    # binding. Only instance-field delivery is in scope.
    src = """\
        import os, pickle
        class FAISSIndex:
            def load(self, path):
                with open(os.path.join(path, "index.pkl"), "rb") as f:
                    self.docs = pickle.load(f)
    """
    findings = detect_insecure_deserialization(_agent_with_source(src))
    assert not any(f.id == "AG-DESERIALIZE" for f in findings)


def test_field_from_hardcoded_constant_does_not_fire():
    # self.path is a hardcoded constant, never param-derived → no taint.
    src = """\
        import pickle
        class C:
            def __init__(self):
                self.path = "/etc/app/model.pkl"
            def load(self):
                with open(self.path, "rb") as f:
                    return pickle.load(f)
    """
    findings = detect_insecure_deserialization(_agent_with_source(src))
    assert not any(f.id == "AG-DESERIALIZE" for f in findings)


def test_safe_load_of_tainted_field_does_not_fire():
    # yaml.safe_load of a tainted field is safe → not flagged.
    src = """\
        import yaml
        class C:
            def __init__(self, cfg_path):
                self.cfg_path = cfg_path
            def load(self):
                with open(self.cfg_path) as f:
                    return yaml.safe_load(f)
    """
    findings = detect_insecure_deserialization(_agent_with_source(src))
    assert not any(f.id == "AG-DESERIALIZE" for f in findings)


# ---------------------------------------------------------------------------
# Unit: analysis.cross_function_taint internals (soundness properties)
# ---------------------------------------------------------------------------

def test_field_taint_for_class_only_param_derived_fields():
    fns = _funcs("""\
        class C:
            def __init__(self, user_path):
                self.user_path = user_path      # param-derived  -> tainted
                self.const = "fixed.txt"         # constant       -> NOT tainted
            def m(self):
                pass
    """)
    cls = fns["__init__"]._ag_class
    fields = cft.field_taint_for_class(cls)
    assert "user_path" in fields
    assert "const" not in fields


def test_self_receiver_never_added_to_tainted():
    # Reading a tainted field must NOT taint the bare `self` name (which would
    # make EVERY self.* reference match — an over-taint that destroys precision).
    fns = _funcs("""\
        class C:
            def __init__(self, p):
                self.p = p
            def read(self):
                x = self.p
                y = self.other      # different field, NOT tainted
                return x, y
    """)
    tainted, params = compute_taint(fns["read"])
    assert "self.p" in tainted
    assert "self" not in tainted
    assert "self.other" not in tainted
    # effective params non-empty so `if not params: continue` guards pass through
    assert params  # contains the referenced field token


def test_staticmethod_has_no_instance_receiver():
    fns = _funcs("""\
        class C:
            @staticmethod
            def sm(data_path):
                return data_path
    """)
    assert cft._self_name(fns["sm"]) is None


def test_with_binding_only_propagates_from_field_not_bare_param():
    # Bare-param context in a with-item does NOT taint the binding (precision);
    # a field-derived context DOES.
    bare = _funcs("""\
        def f(path):
            with open(path) as fh:
                return fh
    """)["f"]
    t_bare = cft.local_taint(bare, {"path"})
    assert "fh" not in t_bare   # bare param -> NOT propagated through with-as

    fielded = _funcs("""\
        class C:
            def m(self):
                with open(self.p) as fh:
                    return fh
    """)["m"]
    t_field = cft.local_taint(fielded, {"self.p"})
    assert "fh" in t_field      # field token -> propagated


def test_module_level_function_unchanged_no_field_taint():
    # A plain module-level function: behaves as single-function taint, and has
    # no enclosing class, so no field tokens appear.
    fn = _funcs("""\
        def g(cmd):
            x = cmd
            return x
    """)["g"]
    tainted, params = compute_taint(fn)
    assert "cmd" in tainted and "x" in tainted
    assert params == {"cmd"}
    assert not any("." in t for t in tainted)


def test_is_tainted_matches_field_token_backward_compatible():
    expr = ast.parse("open(self.data_path)", mode="eval").body
    assert is_tainted(expr, {"self.data_path"}) is True
    assert is_tainted(expr, {"self"}) is True          # bare Name still matched
    assert is_tainted(expr, {"unrelated"}) is False
