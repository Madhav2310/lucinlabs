"""Generic Python agent detector — finds tools in ANY Python code.

This is the catch-all parser. When no framework-specific parser matches,
this one looks for universal patterns that indicate "this code defines
an AI agent with tools":

1. Any function decorated with @tool (LangChain, CrewAI, custom)
2. Any function registered as a tool (OpenAI function_calling schema)
3. Any class with methods named like tools
4. OpenAI Assistants/Agents SDK patterns (client.beta.assistants.create)
5. Function definitions with "tool" in their docstring or name
6. JSON schemas that look like function definitions

The philosophy: if it LOOKS like a tool, we should analyze it.
False positives here are acceptable because we'd rather scan too much
than miss a real vulnerability in an unsupported framework.
"""

import ast
import json
import re
from pathlib import Path

from lucin._fs import iter_files
from lucin.models import Agent, Tool, ToolCapability
from lucin.parsers.langchain_parser import classify_tool_capabilities


def parse_generic(target: Path) -> list[Agent]:
    """Find agent/tool patterns in any Python file."""
    agents = []

    if target.is_file():
        files = [target] if target.suffix == ".py" else []
    else:
        files = iter_files(target, "*.py")

    for py_file in files:
        try:
            content = py_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        # Skip if already matched by a specific parser
        if _is_known_framework(content):
            continue

        tools = _find_generic_tools(content, str(py_file))
        if tools:
            # Create an agent from discovered tools
            agent_name = py_file.stem
            agents.append(Agent(
                name=agent_name,
                framework="generic",
                tools=tools,
                agent_evidence=_collect_agent_evidence(content, tools),
                server_surface=has_server_surface(content),
                source_file=str(py_file),
                has_human_in_loop=_has_human_oversight(content),
                can_spawn_subagents=_can_spawn(content),
                has_memory=_has_persistence(content),
            ))

    # Also check for OpenAI Assistants JSON configs
    if target.is_dir():
        for json_file in iter_files(target, "*.json"):
            try:
                content = json_file.read_text(encoding="utf-8")
                data = json.loads(content)
                assistant_agent = _parse_openai_assistant_json(data, str(json_file))
                if assistant_agent:
                    agents.append(assistant_agent)
            except (json.JSONDecodeError, UnicodeDecodeError, PermissionError):
                continue

    return agents


def _collect_agent_evidence(content: str, tools: list[Tool]) -> list[str]:
    """Why do we believe this FILE defines an agent (beyond a tool-ish name)?

    The generic parser is intentionally aggressive: `_looks_like_tool_function`
    matches on names like "execute"/"query"/"fetch", so it also "discovers" agents
    inside build scripts, benchmark harnesses, pydantic schema modules,
    prompt-string files and `fake_tools/`. Findings on those files are noise —
    measured 3 TP / 28 FP (9.7%) with 38 unadjudicable across 81 real agent repos.

    Returning an EMPTY list means: the only signal was a function name.
    """
    ev: list[str] = []
    low = content.lower()

    # 1) An explicit tool decorator is the strongest local signal.
    if re.search(r"@(tool|function_tool|agent_tool)\b", content):
        ev.append("@tool decorator")
    # 2) A class deriving from a Tool/Toolkit base (SuperAGI/CAMEL/LlamaIndex style).
    if re.search(r"class\s+\w+\s*\([^)]*\b(BaseTool|BaseToolkit|Tool|Toolkit|BaseToolSpec)\b",
                 content):
        ev.append("Tool base class")
    # 3) A real LLM client call — the thing that makes tool use an *agent*.
    if re.search(r"\b(openai|anthropic|litellm|ollama|cohere|mistralai|google\.generativeai"
                 r"|chat\.completions|ChatCompletion|generate_content|invoke_model)\b",
                 content):
        ev.append("LLM client")
    # 4) A tool registry / dispatch table.
    if re.search(r"\b(tools\s*=\s*\[|available_tools|register_tool|tool_registry"
                 r"|function_map|TOOL_MAP|toolkits\s*=)", content):
        ev.append("tool registry")
    # 5) MCP wiring.
    if "mcpservers" in low or "modelcontextprotocol" in low:
        ev.append("MCP config")
    # 6) An explicit agent/assistant construction.
    if re.search(r"\b(Agent|Assistant|Crew|AgentExecutor|Swarm)\s*\(", content):
        ev.append("agent constructor")
    # NOTE: an HTTP server is deliberately NOT agent evidence — see
    # `has_server_surface`. Conflating them made every Flask/FastAPI app an "agent",
    # which is exactly the mislabelling a third-party benchmark caught (13 of 22 pure
    # web apps reported as agents).
    return ev


def has_server_surface(content: str) -> bool:
    """Does this file CONSTRUCT an HTTP server?

    A separate question from "is this an agent". It licenses the server-posture rules
    (AG-NOAUTH, AG-CORS) — which exist precisely to judge an exposed server — without
    claiming an agent exists. A pydantic-schema or prompt-string module constructs
    nothing and gets neither.
    """
    return bool(re.search(r"\b(FastAPI|Flask|APIRouter|CORSMiddleware|add_middleware"
                          r"|app\.route|uvicorn|starlette)\b", content))


def _is_known_framework(content: str) -> bool:
    """Check if this file would be caught by a framework-specific parser."""
    # If it's clearly LangChain, CrewAI, AutoGen, or MCP — skip generic
    known_patterns = [
        "from langchain", "from langgraph", "import langchain",
        "from crewai", "import crewai", "CrewBase",
        "from autogen", "import autogen", "AssistantAgent", "UserProxyAgent",
        "mcpServers", "modelcontextprotocol",
        "from swarm import", "from agents import Agent",
        "from pydantic_ai", "import pydantic_ai",
        "from google.adk", "from google.adk.agents",
        # LlamaIndex class-method tools are owned by the llamaindex parser.
        "BaseToolSpec",
    ]
    return any(p in content for p in known_patterns)


def _find_generic_tools(content: str, filepath: str) -> list[Tool]:
    """Find tool-like functions in generic Python code."""
    tools = []

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return tools

    for node in ast.walk(tree):
        tool = None

        # Pattern 1: @tool decorator (works for any framework using this convention).
        # E2: async def tools count too.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                dec_name = ""
                if isinstance(dec, ast.Name):
                    dec_name = dec.id
                elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                    dec_name = dec.func.id
                elif isinstance(dec, ast.Attribute):
                    dec_name = dec.attr

                if dec_name.lower() in ("tool", "function_tool", "agent_tool"):
                    tool = _func_to_tool(node, filepath, tree)
                    break

        # Pattern 2: OpenAI-style function definitions in tools list
        if isinstance(node, ast.Dict):
            tool = _try_parse_openai_function_schema(node, filepath)

        # Pattern 3: Functions whose name strongly suggests they're agent tools.
        # E2 SCOPE NOTE: this is the deliberately-aggressive NAME heuristic (the
        # catch-all for unknown frameworks). It stays SYNC-only on purpose: real
        # async agent tools are declared via @tool/@function_tool (Pattern 1,
        # which DOES handle async), whereas most async functions in the wild are
        # framework internals — abstract-method stubs (`async def run_bash(...):
        # pass`), ORM/data-layer methods, API handlers — that this name heuristic
        # would mis-flag. Extending the heuristic to async re-introduced 17 benign
        # false positives (vanna abstract tool stubs, chainlit data layer, etc.)
        # with zero recall gain, so async tools are caught by decorator, not name.
        if isinstance(node, ast.FunctionDef) and tool is None:
            if _looks_like_tool_function(node):
                tool = _func_to_tool(node, filepath, tree)

        if tool:
            tools.append(tool)

    return tools


def _body_is_inspectable(node: "ast.FunctionDef | ast.AsyncFunctionDef") -> bool:
    """True iff the function has a REAL body we could draw conclusions from.

    A stub (`pass` / `...` / docstring-only) or an abstract/overload declaration
    tells us nothing, so a name-based capability guess must NOT be vetoed by the
    absence of evidence there — absence of a body is not evidence of safety.
    """
    body = [s for s in node.body
            if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                    and isinstance(s.value.value, str))]          # drop docstring
    if not body:
        return False
    if len(body) == 1 and isinstance(body[0], (ast.Pass, ast.Raise)):
        return False
    if len(body) == 1 and isinstance(body[0], ast.Expr) and isinstance(
            body[0].value, ast.Constant) and body[0].value.value is Ellipsis:
        return False
    return True


def _func_to_tool(node: "ast.FunctionDef | ast.AsyncFunctionDef", filepath: str,
                  tree: "ast.Module | None" = None) -> Tool:
    """Convert a function definition to a Tool model."""
    from lucin.parsers.body_inspector import (
        exec_is_body_confirmed,
        inspect_function_body,
        is_fetch_only_function,
    )
    description = ast.get_docstring(node) or ""
    name_caps = classify_tool_capabilities(node.name, description)
    # ALSO ATTEMPTED AND REVERTED (2026-07-30): callee-aware body inspection here
    # (`inspect_function_body_with_callees`, one hop through local helpers). It
    # did NOT recover the recall cases it was meant to (they hide behind `self.*`
    # methods), and because it only ADDS capabilities it inflated the broad-corpus
    # finding count 429 -> 456 (AG-001 +14, AG-006 +10, AG-005a/b +9) AND BROKE
    # THE FLAGSHIP PRECISION GATE: benign corpus went 52/52 clean / 0 adjudicated
    # FP -> 51/52 / 3 FP. Precision is the brand, so it is reverted. Any future
    # callee-following must be validated against `build_benign_corpus.py` FIRST.
    body_caps = inspect_function_body(node)
    capabilities = list(set(name_caps + body_caps))

    # Grade the EXECUTE_CODE evidence (severity only — the capability set above is
    # deliberately unchanged, so this cannot create findings or regress the
    # benign-corpus gate). Deep read follows local + `self.*` callees.
    exec_confirmed: bool | None = None
    arg_filtered = False
    if ToolCapability.EXECUTE_CODE in capabilities:
        if _body_is_inspectable(node):
            exec_confirmed = exec_is_body_confirmed(node, tree)
        # else: stub/abstract body — no evidence either way, leave None.
        # Kind-scoped sanitizer/barrier check (the biggest measured precision lever;
        # Artemis ablation: weak sanitizer rules => 9.2x more FPs). "guarded" means
        # every exec sink is shell-free argv, literal, or shlex.quote-wrapped — so
        # applying our OWN recommended fix now actually clears the finding.
        from lucin.analysis.sanitizers import exec_guard_status
        from lucin.parsers.body_inspector import build_import_alias_map
        try:
            aliases = build_import_alias_map(tree) if tree is not None else None
            arg_filtered = exec_guard_status(node, aliases) == "guarded"
        except Exception:       # noqa: BLE001 — never let analysis break a scan
            arg_filtered = False

    # NOTE (2026-07-30) — `name_caps | body_caps` means a NAME-inferred
    # EXECUTE_CODE can never be withdrawn by reading the body. Measured on 81
    # real agent repos, that union is AG-001's dominant false-positive driver
    # (92 of 429 HIGH/CRIT findings): it fires CRITICAL on
    # `printable_shell_command` (body: `oslex.join` — shell ESCAPING, the SAFE
    # path), `_format_shell_call` (a console formatter), `decode_execute` (parses
    # model output), and even a static analyzer that merely *looks for*
    # `shell=True`.
    #
    # ATTEMPTED AND REVERTED: letting body evidence veto the name guess killed
    # those FPs but caused a MEASURED 6-POINT RECALL REGRESSION (76% -> 70%),
    # losing 4 REAL cases (camel terminal/docker/code-exec, promptflow REPL).
    # Root cause: those are CLASS-BASED toolkits whose exec hides behind
    # `self._docker_exec(...)`, and callee resolution keys on bare function
    # names, so `self.*` never resolves — "no exec found" was absence of
    # evidence, not evidence of absence. Missing real RCE to cut noise is the
    # wrong trade for a security scanner, so the veto is NOT applied.
    #
    # CORRECT FIX (next pass, needs its own validation): (1) resolve `self.*`
    # method callees within the enclosing class, then (2) grade SEVERITY by
    # evidence — body-confirmed exec = CRITICAL, name-only inference =
    # MEDIUM/INFO. The finding still reports (recall preserved) without
    # inflating CRITICAL counts. See plan/80_EXECUTION_SPRINT.md.
    fetch_only = is_fetch_only_function(node) or node.name.lower().startswith("fetch_")
    return Tool(
        name=node.name,
        description=description[:200],
        capabilities=capabilities,
        is_fetch_only=fetch_only,
        exec_body_confirmed=exec_confirmed,
        has_argument_filtering=arg_filtered,
        source_file=filepath,
        source_line=node.lineno,
    )


def _looks_like_tool_function(node: ast.FunctionDef) -> bool:
    """Heuristic: does this function look like an agent tool?

    We're deliberately aggressive here — better to scan too much
    than miss a real tool in an unknown framework.
    """
    name = node.name.lower()
    docstring = (ast.get_docstring(node) or "").lower()

    # Strong indicators in the name
    strong_name_patterns = [
        "execute", "shell", "bash", "run_command",
        "fetch", "http_request", "api_call",
        "read_file", "write_file", "delete_file",
        "query", "sql", "database",
        "send_email", "send_message",
        "search", "scrape", "download",
    ]
    if any(p in name for p in strong_name_patterns):
        return True

    # Indicators in the docstring that suggest this is an exposed tool
    tool_docstring_patterns = [
        "tool", "function that", "use this to",
        "returns the result", "executes",
        "sends a request", "queries the",
    ]
    if any(p in docstring for p in tool_docstring_patterns):
        return True

    return False


def _try_parse_openai_function_schema(node: ast.Dict, filepath: str) -> Tool | None:
    """Try to parse an OpenAI-style function definition dict.

    Pattern:
    {"type": "function", "function": {"name": "...", "description": "..."}}
    """
    # This is complex AST matching — simplified version
    # In practice, we'd look for the pattern in the source text
    return None  # TODO: implement full AST dict parsing


def _parse_openai_assistant_json(data: dict, filepath: str) -> Agent | None:
    """Parse an OpenAI Assistants API configuration JSON.

    Looks for patterns like:
    {"model": "gpt-4", "tools": [{"type": "function", "function": {...}}]}
    or
    {"assistant_id": "...", "tools": [...]}
    """
    # Check if this looks like an assistant config
    if not isinstance(data, dict):
        return None

    has_model = "model" in data
    has_tools = "tools" in data
    has_instructions = "instructions" in data
    has_assistant_id = "assistant_id" in data or "id" in data

    if not (has_tools and (has_model or has_assistant_id or has_instructions)):
        return None

    tools_data = data.get("tools", [])
    if not isinstance(tools_data, list):
        return None

    tools = []
    for tool_def in tools_data:
        if not isinstance(tool_def, dict):
            continue

        tool_type = tool_def.get("type", "")

        if tool_type == "function":
            func_def = tool_def.get("function", {})
            name = func_def.get("name", "unnamed")
            description = func_def.get("description", "")
            params = func_def.get("parameters", {})
            capabilities = classify_tool_capabilities(name, description, parameters=params)
            tools.append(Tool(
                name=name,
                description=description[:200],
                capabilities=capabilities,
                parameters=params,
                source_file=filepath,
            ))
        elif tool_type == "code_interpreter":
            tools.append(Tool(
                name="code_interpreter",
                description="OpenAI Code Interpreter — executes Python code",
                capabilities=[ToolCapability.EXECUTE_CODE, ToolCapability.FILE_SYSTEM],
                source_file=filepath,
            ))
        elif tool_type == "file_search":
            tools.append(Tool(
                name="file_search",
                description="OpenAI File Search — searches uploaded files",
                capabilities=[ToolCapability.READ_DATA],
                source_file=filepath,
            ))

    if not tools:
        return None

    name = data.get("name", data.get("assistant_id", Path(filepath).stem))
    return Agent(
        name=name,
        framework="openai",
        tools=tools,
        has_memory=True,  # Assistants have thread memory
        source_file=filepath,
    )


def _has_human_oversight(content: str) -> bool:
    """Check for human oversight patterns in generic code."""
    patterns = ["human", "approval", "confirm", "verify", "ask_user", "input("]
    return sum(1 for p in patterns if p in content.lower()) >= 2


def _can_spawn(content: str) -> bool:
    """Check if code can spawn sub-agents."""
    patterns = ["spawn", "create_agent", "delegate", "sub_agent", "child"]
    return any(p in content.lower() for p in patterns)


def _has_persistence(content: str) -> bool:
    """Check for persistence/memory patterns.

    Expanded to catch RAG agents, vector stores, session-based memory,
    conversation history, and other persistent state patterns.
    """
    patterns = [
        # Explicit memory
        "memory", "persist", "save_state", "checkpoint",
        # Conversation/session
        "history", "session", "conversation_buffer", "chat_history",
        # Vector stores / RAG
        "vectorstore", "vector_store", "faiss", "pinecone", "chromadb",
        "chroma", "weaviate", "qdrant", "milvus", "pgvector",
        "embedding", "retriever", "retrieval",
        # Knowledge bases
        "knowledge_base", "knowledgebase", "index.load", "load_local",
        # File-based persistence
        "save_local", "write_text", "json.dump",
        # Database-backed memory
        "sqlite", "redis", "memcache",
    ]
    content_lower = content.lower()
    return sum(1 for p in patterns if p in content_lower) >= 2  # Need 2+ indicators
