"""Parser for LangChain agent definitions."""

import ast
import re
from pathlib import Path

from lucin._fs import iter_files
from lucin.models import Agent, Tool, ToolCapability
from lucin.parsers.body_inspector import (
    build_import_alias_map,
    inspect_function_body,
    inspect_function_body_with_callees,
)

# Tool names/patterns that indicate dangerous capabilities
# These are ordered from most dangerous to least
# NOTE: "system" removed — too many false positives ("ticketing system", "billing system")
# Instead we use "os.system", "system_call", "run_system" which are unambiguous
EXEC_PATTERNS = [
    "shell", "bash", "exec", "run_command", "subprocess",
    "os_exec", "system_call", "run_system", "os.system",
    "terminal", "run_code", "eval", "spawn",
]
# NOTE: "execute" REMOVED as a standalone name/description token (corpus batch-5,
# 2026-07-29). It is too polysemous in LLM tooling — it fires on benign methods and
# docstrings that "execute tool calls" / "execute a strategy" / "execute a function"
# (mirascope Response.execute_tools, semantic-router _execute_sync_strategy, retry
# docstring "Execute a function with retry logic", toolkit docstring "can execute a
# specific tool call"). None involve OS/shell/code execution. Genuine OS/code exec is
# still signalled by shell/bash/subprocess/run_command/os.system/eval/spawn/terminal/
# run_code above, by the "command" name token below, and — most importantly — by
# body_inspector detecting real subprocess/os.system/eval/exec/compile calls regardless
# of the function name. "exec" is kept: _word_match is token-bounded so it matches
# "exec_tool"/"os_exec" but NOT "execute". Recall corpus stays 5/5 (verified).

# "command" matched in TOOL NAMES only (not descriptions) to avoid
# "this command will..." style false positives
EXEC_NAME_ONLY_PATTERNS = [
    "command",  # tool named "command" or "run_command" is exec-related
]

# Patterns that look like exec but are actually data operations (EXCLUSIONS)
# Corpus-derived (Griptape 2026-07-28): execute_futures_dict uses concurrent.futures,
# not subprocess — the word "execute" in function names for concurrency utilities FPs.
EXEC_FALSE_POSITIVES = [
    "sql", "query", "database", "db_", "select", "fetch_data",
    "read_table", "get_records", "execute_query", "run_query",
    # Concurrency utilities (concurrent.futures, asyncio futures)
    "execute_futures", "futures",
    # Test/benchmark utilities
    "execute_test", "run_test", "execute_benchmark",
    # Search/orchestration methods on data classes (corpus: instructor, dspy)
    # execute() on a SearchQuery/MultiSearch class means "run the search", not exec code
    "multi_search", "search_query", "segment_search",
    # Callback/event methods (corpus: dspy callbacks)
    "execute_start_callbacks", "execute_end_callbacks", "_execute_callbacks",
    "start_callbacks", "end_callbacks",
]

NETWORK_PATTERNS = [
    "http", "fetch", "request", "curl", "api_call", "webhook",
    "web_search", "browse", "scrape", "download", "upload",
    "search_internet", "search_web", "internet",
    "send_email", "send_message", "post_to", "notify",
]

FILE_READ_PATTERNS = [
    "read_file", "load_file", "open_file", "get_file", "cat_file",
    "file_read", "read_document", "get_content",
]

FILE_WRITE_PATTERNS = [
    "write_file", "save_file", "create_file", "file_write",
    "write_document", "save_to", "overwrite", "append_file",
]

FILE_DELETE_PATTERNS = [
    "delete_file", "remove_file", "rm_file", "unlink",
]

DB_READ_PATTERNS = [
    "sql", "query", "database", "db_read", "select", "fetch_data",
    "read_table", "get_records", "execute_query", "run_query",
    "list_tables", "describe_table", "get_schema",
]

DB_WRITE_PATTERNS = [
    "insert", "update", "delete_record", "drop_table", "truncate",
    "create_table", "alter_table", "db_write",
]


def _word_match(pattern: str, text: str) -> bool:
    """Check if pattern appears as a word/token in text (not as substring of another word).

    'system' matches 'run system command' but NOT 'filesystem'.
    'exec' matches 'exec_tool' but NOT 'execute_query' (handled separately).
    """
    import re
    # Match pattern as whole word or connected by underscore/hyphen
    return bool(re.search(r'(?:^|[\s_\-./])' + re.escape(pattern) + r'(?:$|[\s_\-./])', text))


def classify_tool_capabilities(tool_name: str, description: str = "", parameters: dict | None = None) -> list[ToolCapability]:
    """Infer tool capabilities from name, description, AND parameter schema.

    Three-layer classification (per SkillSieve hierarchical triage):
    1. Name/description keywords (fast, catches obvious cases)
    2. Parameter schema analysis (catches capabilities hidden in neutral names)
    3. Priority system: specific patterns override generic ones

    Schema analysis (Fix #4 from algorithm verification):
    A tool accepting {url: string, body: string} is NETWORK-capable
    regardless of whether its name mentions "http" or "fetch".
    """
    capabilities = []
    combined = (tool_name + " " + description).lower()

    # === SCHEMA-BASED CLASSIFICATION (per SkillSieve research) ===
    # Analyze parameter names/types for capability signals
    if parameters:
        schema_caps = _classify_from_schema(parameters)
        capabilities.extend(schema_caps)

    # Bare "execute" with no other context is an orchestration method (corpus lesson:
    # instructor SearchQuery.execute(), dspy callbacks, asyncio patterns).
    # Only flag "execute" if paired with other exec signals (shell, code, subprocess).
    if tool_name.lower() in ("execute", "_execute") and not any(
        p in combined for p in ("shell", "code", "subprocess", "command", "bash")
    ):
        return capabilities  # bare "execute" alone = orchestration, not code exec

    # Check for code execution — but exclude DB operations that use "execute"
    is_db_operation = any(p in combined for p in EXEC_FALSE_POSITIVES)
    has_exec = any(_word_match(p, combined) for p in EXEC_PATTERNS)
    # Also check name-only patterns (match in tool name but not description)
    has_exec_in_name = any(_word_match(p, tool_name.lower()) for p in EXEC_NAME_ONLY_PATTERNS)
    if (has_exec or has_exec_in_name) and not is_db_operation:
        capabilities.append(ToolCapability.EXECUTE_CODE)

    # Network access
    if any(p in combined for p in NETWORK_PATTERNS):
        capabilities.append(ToolCapability.NETWORK_ACCESS)

    # File read
    if any(p in combined for p in FILE_READ_PATTERNS):
        capabilities.append(ToolCapability.READ_DATA)
        capabilities.append(ToolCapability.FILE_SYSTEM)

    # File write
    if any(p in combined for p in FILE_WRITE_PATTERNS):
        capabilities.append(ToolCapability.WRITE_DATA)
        capabilities.append(ToolCapability.FILE_SYSTEM)

    # File delete (treated as write since it's destructive)
    if any(p in combined for p in FILE_DELETE_PATTERNS):
        capabilities.append(ToolCapability.WRITE_DATA)
        capabilities.append(ToolCapability.FILE_SYSTEM)

    # Database read/write.
    # Two problems with the old plain-substring `in` match, both fixed here (corpus batch-5):
    #  (1) substring matched "selection"/"selected"/"updated" inside prose → use token-
    #      boundary _word_match.
    #  (2) the bare single-word SQL verbs select/insert/update/delete/truncate are also
    #      common ENGLISH words that appear as whole tokens in prose docstrings ("update the
    #      model", "delete the item"). Matching them anywhere manufactured WRITE_DATA on
    #      benign generators (guidance gen() docstring contains the word "update" → falsely
    #      tagged destructive → AG-006 FP). So — mirroring EXEC_NAME_ONLY_PATTERNS — these
    #      ambiguous verbs only count when they appear in the tool NAME, not the description.
    # Unambiguous tokens (sql, query, run_query, drop_table, delete_record, db_write, ...)
    # still match in name+description, preserving recall on real DB tools.
    _DB_AMBIGUOUS_VERBS = {"select", "insert", "update", "delete", "truncate"}
    name_lc = tool_name.lower()
    db_read_strong = [p for p in DB_READ_PATTERNS if p not in _DB_AMBIGUOUS_VERBS]
    db_write_strong = [p for p in DB_WRITE_PATTERNS if p not in _DB_AMBIGUOUS_VERBS]
    db_read_verbs = [p for p in DB_READ_PATTERNS if p in _DB_AMBIGUOUS_VERBS]
    db_write_verbs = [p for p in DB_WRITE_PATTERNS if p in _DB_AMBIGUOUS_VERBS]

    if (any(_word_match(p, combined) for p in db_read_strong)
            or any(_word_match(p, name_lc) for p in db_read_verbs)):
        capabilities.append(ToolCapability.READ_DATA)

    if (any(_word_match(p, combined) for p in db_write_strong)
            or any(_word_match(p, name_lc) for p in db_write_verbs)):
        capabilities.append(ToolCapability.WRITE_DATA)

    # Deduplicate
    return list(set(capabilities))


def parse_langchain(target: Path) -> list[Agent]:
    """Parse LangChain agent definitions from Python source files."""
    agents = []
    python_files = iter_files(target, "*.py")

    for py_file in python_files:
        try:
            source = py_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        # Skip files that don't look like LangChain agent code
        if "langchain" not in source and "langgraph" not in source:
            continue

        file_agents = _extract_agents_from_source(source, str(py_file))
        agents.extend(file_agents)

    return agents


def _extract_agents_from_source(source: str, filepath: str) -> list[Agent]:
    """Extract agent definitions from Python source code."""
    agents = []
    tools = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return agents

    # Build function definition map for body inspection
    # Includes both top-level functions AND class methods
    func_map = {}
    for node in ast.walk(tree):
        # E2: async def tools are just as real as sync ones — handle both.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_map[node.name] = node
        elif isinstance(node, ast.ClassDef):
            # Add class methods with both "method" and "Class.method" keys
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_map[item.name] = item
                    func_map[f"{node.name}.{item.name}"] = item

    # Build import alias map for resolving aliased dangerous calls
    import_aliases = build_import_alias_map(tree)

    # Find tool definitions (@tool decorator or Tool() instantiation)
    for node in ast.walk(tree):
        tool = _try_extract_tool(node, source, filepath, func_map, import_aliases)
        if tool:
            tools.append(tool)

    # Check for LangGraph patterns (ToolNode, StateGraph, builder.compile)
    if not tools and "langgraph" in source:
        langgraph_agent = _try_extract_langgraph_agent(tree, source, filepath)
        if langgraph_agent:
            agents.append(langgraph_agent)
            return agents

    # Find agent creation patterns
    agent_names = _find_agent_names(tree, source)

    if tools:
        # If we found tools but no explicit agent name, use the filename
        name = agent_names[0] if agent_names else Path(filepath).stem
        agents.append(
            Agent(
                name=name,
                framework="langchain",
                tools=tools,
                source_file=filepath,
                has_human_in_loop=_has_human_in_loop(source),
                can_spawn_subagents=_can_spawn_subagents(source),
                has_memory=_has_memory(source),
            )
        )

    return agents


def _try_extract_langgraph_agent(tree: ast.Module, source: str, filepath: str) -> Agent | None:
    """Extract agent info from LangGraph patterns.

    LangGraph uses:
    - StateGraph(State, ...) for graph definition
    - ToolNode(TOOLS) for tool execution nodes
    - builder.compile(name="...") for creating the runnable
    - bind_tools(TOOLS) for model tool binding
    - interrupt_before/interrupt_after for human-in-the-loop

    The challenge: tools are typically imported from another module (TOOLS constant),
    so we can't see their definitions. We still create an agent record to enable
    structural detectors (missing controls, delegation, etc.).
    """
    tools = []
    agent_name = "langgraph_agent"

    # Look for ToolNode(...) or bind_tools(...) calls
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            # ToolNode(TOOLS) — the tools variable reference
            if func_name == "ToolNode" and node.args:
                tools_arg = node.args[0]
                if isinstance(tools_arg, ast.Name):
                    # Tools are a variable (imported constant) — create placeholder
                    tools.append(Tool(
                        name=f"(imported: {tools_arg.id})",
                        description="Tools imported from external module — cannot determine capabilities statically",
                        capabilities=[],  # Unknown — could be anything
                        source_file=filepath,
                        source_line=node.lineno if hasattr(node, 'lineno') else 0,
                    ))
                elif isinstance(tools_arg, ast.List):
                    # Inline tool list
                    for elt in tools_arg.elts:
                        if isinstance(elt, ast.Name):
                            cap = classify_tool_capabilities(elt.id, "")
                            tools.append(Tool(
                                name=elt.id,
                                description="",
                                capabilities=cap,
                                source_file=filepath,
                                source_line=elt.lineno if hasattr(elt, 'lineno') else 0,
                            ))

            # builder.compile(name="ReAct Agent")
            if func_name == "compile":
                name_arg = _extract_kwarg_str(node, "name")
                if name_arg:
                    agent_name = name_arg

    # If we detected LangGraph patterns but no explicit tools, still create agent
    # because the structural detectors (human-in-loop, etc.) still apply
    if tools or "ToolNode" in source or "bind_tools" in source:
        return Agent(
            name=agent_name,
            framework="langgraph",
            tools=tools,
            source_file=filepath,
            has_human_in_loop=_has_human_in_loop(source),
            can_spawn_subagents="add_node" in source,  # Graph nodes = potential sub-agents
        )

    return None


def _try_extract_tool(node: ast.AST, source: str, filepath: str, func_map: dict | None = None, import_aliases: dict | None = None) -> Tool | None:
    """Try to extract a tool definition from an AST node.

    Now with function body inspection: when a Tool references a function (func=my_func),
    we inspect that function's body for dangerous API calls that reveal hidden capabilities.
    This catches the "innocent name, dangerous body" evasion pattern.

    Import alias resolution: `from os import popen as runner` → `runner()` is resolved
    to `os.popen` before checking against dangerous call signatures.
    """
    aliases = import_aliases or {}

    # Pattern 1: @tool decorator (sync OR async def — E2)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for decorator in node.decorator_list:
            decorator_name = ""
            if isinstance(decorator, ast.Name):
                decorator_name = decorator.id
            elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
                decorator_name = decorator.func.id

            if decorator_name == "tool":
                description = ast.get_docstring(node) or ""
                capabilities = classify_tool_capabilities(node.name, description)
                # BODY INSPECTION with alias resolution + one-hop call following
                if func_map:
                    body_caps = inspect_function_body_with_callees(node, func_map, aliases)
                else:
                    body_caps = inspect_function_body(node, import_aliases=aliases)
                capabilities = list(set(capabilities + body_caps))
                from lucin.parsers.body_inspector import is_fetch_only_function
                fetch_only = (is_fetch_only_function(node, import_aliases=aliases)
                             or node.name.lower().startswith("fetch_"))
                return Tool(
                    name=node.name,
                    description=description,
                    capabilities=capabilities,
                    is_fetch_only=fetch_only,
                    source_file=filepath,
                    source_line=node.lineno,
                )

    # Pattern 2: Tool(name=..., func=...) or StructuredTool.from_function(...)
    if isinstance(node, ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in ("Tool", "StructuredTool", "from_function"):
            name = _extract_kwarg_str(node, "name") or "unnamed_tool"
            description = _extract_kwarg_str(node, "description") or ""
            capabilities = classify_tool_capabilities(name, description)

            # BODY INSPECTION with alias resolution + one-hop call following
            if func_map:
                func_ref = _extract_func_reference(node)
                if func_ref and func_ref in func_map:
                    body_caps = inspect_function_body_with_callees(
                        func_map[func_ref], func_map, aliases
                    )
                    capabilities = list(set(capabilities + body_caps))

            return Tool(
                name=name,
                description=description,
                capabilities=capabilities,
                source_file=filepath,
                source_line=node.lineno if hasattr(node, "lineno") else 0,
            )

    return None


def _extract_func_reference(tool_call: ast.Call) -> str | None:
    """Extract the function name from Tool(func=my_func) or Tool(..., my_func, ...).

    Handles:
    - Tool(func=my_function) → "my_function"
    - Tool(name="x", func=my_function) → "my_function"
    - Tool(name="x", func=MyClass.method) → "MyClass.method"
    - Tool(name="x", func=obj.method) → "method" (fallback)
    """
    # Check keyword argument: func=my_func
    for kw in tool_call.keywords:
        if kw.arg == "func":
            if isinstance(kw.value, ast.Name):
                return kw.value.id
            elif isinstance(kw.value, ast.Attribute):
                # MyClass.method or obj.method
                if isinstance(kw.value.value, ast.Name):
                    # Return "ClassName.method" for class method lookup
                    return f"{kw.value.value.id}.{kw.value.attr}"
                return kw.value.attr

    # Check positional arguments (some patterns use Tool(name, func, desc))
    for arg in tool_call.args:
        if isinstance(arg, ast.Name):
            return arg.id
        elif isinstance(arg, ast.Attribute):
            if isinstance(arg.value, ast.Name):
                return f"{arg.value.id}.{arg.attr}"
            return arg.attr

    return None


def _extract_kwarg_str(call_node: ast.Call, kwarg_name: str) -> str | None:
    """Extract a string keyword argument from a function call."""
    for kw in call_node.keywords:
        if kw.arg == kwarg_name and isinstance(kw.value, ast.Constant):
            return str(kw.value.value)
    return None


def _find_agent_names(tree: ast.Module, source: str) -> list[str]:
    """Find agent variable names from common patterns."""
    names = []
    patterns = [
        r"(\w+)\s*=\s*(?:create_react_agent|AgentExecutor|create_openai_tools_agent)",
        r"(\w+)\s*=\s*.*\.create_agent\(",
        r"agent_name\s*=\s*[\"']([^\"']+)[\"']",
    ]
    for pattern in patterns:
        matches = re.findall(pattern, source)
        names.extend(matches)
    return names


def _has_human_in_loop(source: str) -> bool:
    """Check if agent has human-in-the-loop configured."""
    indicators = [
        "human_in_the_loop", "HumanApprovalCallbackHandler",
        "human_approval", "require_approval", "ask_human",
        "interrupt_before", "interrupt_after",
    ]
    return any(ind in source for ind in indicators)


def _has_memory(source: str) -> bool:
    """Check if agent has persistent memory/state (RAG, vector store, sessions).

    Uses expanded heuristic: presence of 2+ memory-related patterns indicates
    the agent has persistent state that could be poisoned.
    """
    patterns = [
        "memory", "persist", "save_state", "checkpoint",
        "history", "session", "conversation_buffer", "chat_history",
        "vectorstore", "vector_store", "faiss", "pinecone", "chromadb",
        "chroma", "weaviate", "qdrant", "milvus", "pgvector",
        "embedding", "retriever", "retrieval", "rag",
        "knowledge_base", "knowledgebase", "load_local",
        "save_local", "sqlite", "redis",
    ]
    source_lower = source.lower()
    matches = sum(1 for p in patterns if p in source_lower)
    return matches >= 2


def _can_spawn_subagents(source: str) -> bool:
    """Check if agent can create sub-agents.

    Fixed: AgentExecutor is a loop, not sub-agent spawning.
    Only flag if there are ACTUAL delegation/multi-agent patterns.
    """
    # Actual sub-agent/delegation indicators (not just agent creation)
    delegation_indicators = [
        "spawn", "sub_agent", "child_agent", "delegate",
        "handoff", "transfer_to", "create_agent(",  # Dynamic creation
        "AgentTeam", "GroupChat",  # Multi-agent patterns
    ]
    # Multiple distinct Agent() definitions in same file = multi-agent
    import re
    agent_defs = len(re.findall(r"(?:create_react_agent|create_openai_tools_agent|AgentExecutor)\s*\(", source))

    has_delegation = any(ind in source for ind in delegation_indicators)
    # create_react_agent + AgentExecutor = 1 agent (they pair together)
    # Only flag as multi-agent if there are 3+ creation calls (2+ distinct agents)
    has_multiple_agents = agent_defs >= 3

    return has_delegation or has_multiple_agents


def _classify_from_schema(parameters: dict) -> list[ToolCapability]:
    """Classify tool capabilities from parameter schema (SkillSieve approach).

    A tool's parameters reveal its TRUE capabilities regardless of naming:
    - {url: str, body: str} → NETWORK_ACCESS
    - {command: str} or {code: str} → EXECUTE_CODE
    - {path: str, content: str} → WRITE_DATA + FILE_SYSTEM
    - {query: str} with "sql" or "database" context → READ_DATA

    This catches tools with misleading names (e.g., "format_text" that
    actually takes a "command" parameter and executes it).
    """
    capabilities = []

    # Flatten parameter names from various schema formats
    param_names = set()
    if isinstance(parameters, dict):
        # OpenAI-style: {"type": "object", "properties": {"url": {...}}}
        props = parameters.get("properties", {})
        if isinstance(props, dict):
            param_names.update(k.lower() for k in props.keys())

        # Simple dict of params: {"url": "string", "body": "string"}
        if not props:
            param_names.update(k.lower() for k in parameters.keys())

    if not param_names:
        return capabilities

    # Network capability signals
    network_params = {"url", "endpoint", "uri", "host", "webhook", "api_url", "base_url"}
    if param_names & network_params:
        # Has a URL-like parameter = likely network access
        if any(p in param_names for p in ["body", "data", "payload", "method", "headers"]):
            capabilities.append(ToolCapability.NETWORK_ACCESS)

    # Execution capability signals
    exec_params = {"command", "cmd", "code", "script", "expression", "program"}
    if param_names & exec_params:
        capabilities.append(ToolCapability.EXECUTE_CODE)

    # File system signals
    file_write_params = {"content", "data", "text"}
    file_path_params = {"path", "filepath", "file_path", "filename"}
    if param_names & file_path_params:
        if param_names & file_write_params:
            capabilities.append(ToolCapability.WRITE_DATA)
            capabilities.append(ToolCapability.FILE_SYSTEM)
        else:
            capabilities.append(ToolCapability.READ_DATA)
            capabilities.append(ToolCapability.FILE_SYSTEM)

    # Database signals
    db_params = {"query", "sql", "statement"}
    if param_names & db_params:
        capabilities.append(ToolCapability.READ_DATA)

    return list(set(capabilities))
