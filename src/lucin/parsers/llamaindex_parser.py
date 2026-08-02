"""Parser for LlamaIndex class-method tools (BaseToolSpec).

LlamaIndex exposes tools in a way the generic parser misses entirely: a class
that subclasses ``BaseToolSpec`` whose *methods* become agent tools. Which
methods are exposed is declared explicitly by the ``spec_functions`` class
attribute (a list of method-name strings). When ``spec_functions`` is omitted,
LlamaIndex's ``BaseToolSpec`` defaults to exposing every public method.

    from llama_index.core.tools.tool_spec.base import BaseToolSpec

    class OpenAPIToolSpec(BaseToolSpec):
        spec_functions = ["load_openapi_spec"]      # <- explicit tool registry

        def __init__(self, url=None): ...            # not a tool
        def load_openapi_spec(self): ...             # <- THIS is the tool

Why this matters for Lucin: the generic parser only recognises tools by
@tool decorators, OpenAI function schemas, or heuristic function names. A
``BaseToolSpec`` method like ``load_openapi_spec`` matches none of those, so the
whole file parsed to ZERO agents and no detector ever ran on it — the real
vulnerability was invisible, counted as a miss for a reason that had nothing to
do with the detectors.

SOUNDNESS (precision is sacred here):
  We only treat a method as a tool when there is a real, explicit registration
  signal — the class subclasses a ``*ToolSpec`` base. We never treat arbitrary
  class methods as tools. When ``spec_functions`` is declared we expose exactly
  those methods; otherwise we expose public (non-underscore) methods, which is
  precisely what LlamaIndex's BaseToolSpec does at runtime. ``__init__`` / dunder
  / private (``_``-prefixed) methods are never exposed as tools.
"""

import ast
from pathlib import Path

from lucin._fs import iter_files
from lucin.models import Agent, Tool
from lucin.parsers.body_inspector import inspect_function_body, is_fetch_only_function
from lucin.parsers.langchain_parser import classify_tool_capabilities


def parse_llamaindex(target: Path) -> list[Agent]:
    """Parse LlamaIndex BaseToolSpec class-method tool definitions."""
    agents: list[Agent] = []

    if target.is_file():
        files = [target] if target.suffix == ".py" else []
    else:
        files = iter_files(target, "*.py")

    for py_file in files:
        try:
            content = py_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        if not _is_llamaindex_toolspec_file(content):
            continue

        agents.extend(_parse_toolspec_classes(content, str(py_file)))

    return agents


def _is_llamaindex_toolspec_file(content: str) -> bool:
    """Cheap gate: only look at files that reference a ToolSpec base class."""
    return "BaseToolSpec" in content or "ToolSpec" in content


def _parse_toolspec_classes(content: str, filepath: str) -> list[Agent]:
    agents: list[Agent] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return agents

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        if not _is_toolspec_subclass(node):
            continue

        # Map method name -> def node (class body only, not nested functions).
        methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods[item.name] = item

        tool_names = _resolve_tool_method_names(node, methods)

        tools: list[Tool] = []
        for name in tool_names:
            m = methods.get(name)
            if m is None:
                continue
            tools.append(_method_to_tool(m, filepath))

        agents.append(Agent(
            name=node.name,
            framework="llamaindex",
            tools=tools,
            source_file=filepath,
            has_memory=_has_persistence(content),
        ))

    return agents


def _is_toolspec_subclass(node: ast.ClassDef) -> bool:
    """True if the class subclasses a ``*ToolSpec`` base (e.g. BaseToolSpec).

    Matches ``class X(BaseToolSpec)`` and ``class X(pkg.BaseToolSpec)``. We key on
    the base-class name ending in ``ToolSpec`` — the explicit framework signal —
    rather than guessing from method shapes.
    """
    for base in node.bases:
        base_name = ""
        if isinstance(base, ast.Name):
            base_name = base.id
        elif isinstance(base, ast.Attribute):
            base_name = base.attr
        if base_name.endswith("ToolSpec"):
            return True
    return False


def _resolve_tool_method_names(
    node: ast.ClassDef,
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[str]:
    """Which methods this ToolSpec exposes as tools.

    Priority 1: an explicit ``spec_functions = [...]`` string list (LlamaIndex's
    own tool registry). Priority 2 (fallback, matching BaseToolSpec's runtime
    default): all public, non-dunder instance methods.
    """
    spec = _find_spec_functions(node)
    if spec is not None:
        # Only names that actually resolve to a method in this class.
        return [n for n in spec if n in methods]

    # Fallback: public methods only (BaseToolSpec's default behaviour). Exclude
    # dunder/private and the constructor — never LLM-reachable tool entry points.
    return [
        name for name in methods
        if not name.startswith("_")
    ]


def _find_spec_functions(node: ast.ClassDef) -> list[str] | None:
    """Extract the ``spec_functions`` class attribute as a list of names.

    Returns None if not declared or not a plain string list (we do not guess at
    dynamically-built registries — we fall back to public methods instead).
    """
    for item in node.body:
        if not isinstance(item, ast.Assign):
            continue
        for tgt in item.targets:
            if isinstance(tgt, ast.Name) and tgt.id == "spec_functions":
                if isinstance(item.value, (ast.List, ast.Tuple)):
                    names: list[str] = []
                    for el in item.value.elts:
                        # Flat form: "method_name"
                        if isinstance(el, ast.Constant) and isinstance(el.value, str):
                            names.append(el.value)
                        # Paired form: ("sync_name", "async_name") — LlamaIndex exposes
                        # both the sync and async methods as tools; take every string.
                        elif isinstance(el, (ast.Tuple, ast.List)):
                            names.extend(
                                sub.value for sub in el.elts
                                if isinstance(sub, ast.Constant) and isinstance(sub.value, str)
                            )
                    return names
                return None
    return None


def _method_to_tool(node: ast.FunctionDef | ast.AsyncFunctionDef, filepath: str) -> Tool:
    description = ast.get_docstring(node) or ""
    capabilities = classify_tool_capabilities(node.name, description)
    body_caps = inspect_function_body(node)
    capabilities = list(set(capabilities + body_caps))
    fetch_only = is_fetch_only_function(node) or node.name.lower().startswith("fetch_")
    return Tool(
        name=node.name,
        description=description[:200],
        capabilities=capabilities,
        is_fetch_only=fetch_only,
        source_file=filepath,
        source_line=node.lineno,
    )


def _has_persistence(content: str) -> bool:
    patterns = [
        "memory", "persist", "vectorstore", "vector_store", "index.load",
        "chromadb", "chroma", "faiss", "pinecone", "retriever", "embedding",
    ]
    low = content.lower()
    return sum(1 for p in patterns if p in low) >= 2
