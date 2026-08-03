"""Parser for Pydantic AI agent definitions.

Pydantic AI (16.5K+ GitHub stars) uses a distinctive pattern:
- Agent('model', deps_type=Deps, instructions="...")
- @agent.tool decorator with RunContext[Deps] parameter
- @agent.instructions for dynamic system prompts
- @agent.output_validator for output validation

Key patterns to recognize:
1. `Agent('openai:gpt-4', deps_type=Deps)` — agent creation
2. `@my_agent.tool` — tool registration (different from LangChain's @tool)
3. `async def my_tool(ctx: RunContext[Deps], arg: str) -> str:` — tool function signature
4. `Agent(output_type=SomeModel)` — structured output

The security-relevant aspects:
- Tools have access to dependencies (Deps) which may include DB connections, HTTP clients
- RunContext provides the tool with access to shared state
- No built-in sandboxing or permission model
- Tools can make network calls, DB queries, file operations via deps
"""

import ast
from pathlib import Path

from lucin._fs import iter_files
from lucin.models import Agent, Tool, ToolCapability
from lucin.parsers.body_inspector import inspect_function_body
from lucin.parsers.langchain_parser import classify_tool_capabilities


def parse_pydantic_ai(target: Path) -> list[Agent]:
    """Parse Pydantic AI agent definitions."""
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

        if not _is_pydantic_ai_file(content):
            continue

        file_agents = _parse_pydantic_ai_agents(content, str(py_file))
        agents.extend(file_agents)

    return agents


def _is_pydantic_ai_file(content: str) -> bool:
    """Check if this file uses Pydantic AI."""
    return (
        "from pydantic_ai" in content
        or "import pydantic_ai" in content
    )


def _parse_pydantic_ai_agents(content: str, filepath: str) -> list[Agent]:
    """Parse all Pydantic AI Agent() definitions and their tools."""
    agents = []

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return agents

    # First pass: find all Agent() assignments and their variable names
    agent_vars = {}  # variable_name -> Agent creation node
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = node.value
            if _get_call_name(call) == "Agent" and _is_pydantic_ai_agent(call):
                var_name = _get_assign_name(node)
                if var_name:
                    agent_vars[var_name] = call

    if not agent_vars:
        return agents

    # Second pass: find all @agent_var.tool decorated functions
    func_map = {}  # all function defs
    agent_tools = {name: [] for name in agent_vars}  # agent_name -> [tools]

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            func_map[node.name] = node

            # Check decorators for @agent_name.tool pattern
            for dec in node.decorator_list:
                agent_name = _get_agent_tool_decorator(dec, agent_vars)
                if agent_name:
                    # This function is a tool for this agent
                    tool = _extract_pydantic_ai_tool(node, filepath)
                    agent_tools[agent_name].append(tool)

    # Build Agent objects
    for var_name, call_node in agent_vars.items():
        # Extract agent metadata
        _get_positional_str(call_node, 0) or "unknown"
        instructions = _get_keyword_str(call_node, "instructions") or ""
        agent_name = var_name

        # Determine if agent has memory (deps with DB/session patterns)
        has_memory = _has_memory_deps(content, call_node)

        # Check for sub-agents/handoffs
        can_delegate = "handoff" in content.lower() or "sub_agent" in content.lower()

        tools = agent_tools.get(var_name, [])

        agents.append(Agent(
            name=agent_name,
            framework="pydantic_ai",
            tools=tools,
            source_file=filepath,
            has_human_in_loop=_has_human_oversight(instructions, content),
            can_spawn_subagents=can_delegate,
            has_memory=has_memory,
        ))

    return agents


def _extract_pydantic_ai_tool(node: ast.FunctionDef | ast.AsyncFunctionDef, filepath: str) -> Tool:
    """Extract a tool from a Pydantic AI @agent.tool decorated function."""
    docstring = ast.get_docstring(node) or ""
    name = node.name

    # Classify from name and docstring
    capabilities = classify_tool_capabilities(name, docstring)

    # Body inspection — what does this tool ACTUALLY do?
    body_caps = inspect_function_body(node)
    capabilities = list(set(capabilities + body_caps))

    # Check if this is an async function making HTTP calls (common in pydantic-ai)
    if isinstance(node, ast.AsyncFunctionDef):
        # Async tools often make HTTP requests via deps.client
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                if child.attr in ("get", "post", "put", "delete", "patch"):
                    if ToolCapability.NETWORK_ACCESS not in capabilities:
                        capabilities.append(ToolCapability.NETWORK_ACCESS)

    return Tool(
        name=name,
        description=docstring[:200],
        capabilities=capabilities,
        source_file=filepath,
        source_line=node.lineno,
    )


def _is_pydantic_ai_agent(call: ast.Call) -> bool:
    """Distinguish Pydantic AI Agent from other Agent classes.

    Pydantic AI's Agent takes a model string as first arg:
    Agent('openai:gpt-4', deps_type=Deps)

    vs OpenAI Swarm's Agent which takes name= keyword:
    Agent(name="Triage Agent", instructions="...")
    """
    # Check for model string as first positional arg (pydantic-ai pattern)
    if call.args and isinstance(call.args[0], ast.Constant):
        model_str = str(call.args[0].value)
        # Pydantic AI models are like "openai:gpt-4", "anthropic:claude-3", "google:gemini"
        if ":" in model_str or "gpt" in model_str or "claude" in model_str or "gemini" in model_str:
            return True

    # Check for deps_type keyword (unique to pydantic-ai)
    for kw in call.keywords:
        if kw.arg in ("deps_type", "output_type", "retries"):
            return True

    return False


def _get_agent_tool_decorator(decorator: ast.expr, agent_vars: dict) -> str | None:
    """Check if a decorator is @agent_name.tool and return the agent variable name.

    Matches:
    - @my_agent.tool
    - @weather_agent.tool
    - @support_agent.tool
    """
    if isinstance(decorator, ast.Attribute) and decorator.attr == "tool":
        if isinstance(decorator.value, ast.Name):
            if decorator.value.id in agent_vars:
                return decorator.value.id
    # Also match @agent_name.tool()  (with parens)
    if isinstance(decorator, ast.Call):
        if isinstance(decorator.func, ast.Attribute) and decorator.func.attr == "tool":
            if isinstance(decorator.func.value, ast.Name):
                if decorator.func.value.id in agent_vars:
                    return decorator.func.value.id
    return None


def _has_memory_deps(content: str, call_node: ast.Call) -> bool:
    """Check if agent's deps suggest persistent state."""
    # Look for deps_type keyword
    for kw in call_node.keywords:
        if kw.arg == "deps_type" and isinstance(kw.value, ast.Name):
            # Check if the deps class contains DB/session/memory patterns
            memory_indicators = [
                "conn", "connection", "db", "database", "session",
                "pool", "redis", "mongo", "store", "cache",
                "vectorstore", "index", "memory",
            ]
            # Search for the deps class definition in the file
            content_lower = content.lower()
            return any(ind in content_lower for ind in memory_indicators)
    return False


def _has_human_oversight(instructions: str, content: str) -> bool:
    """Check for human-in-the-loop indicators."""
    indicators = [
        "require_confirmation", "human_approval", "ask_user",
        "confirm before", "check with user",
    ]
    combined = (instructions + " " + content).lower()
    return any(ind in combined for ind in indicators)


# === Helper functions ===

def _get_call_name(call: ast.Call) -> str | None:
    """Get the function/class name from a Call node."""
    if isinstance(call.func, ast.Name):
        return call.func.id
    elif isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _get_assign_name(node: ast.Assign) -> str | None:
    """Get the variable name from an assignment."""
    if node.targets and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    return None


def _get_keyword_str(call: ast.Call, keyword: str) -> str | None:
    """Get a string keyword argument value."""
    for kw in call.keywords:
        if kw.arg == keyword:
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
    return None


def _get_positional_str(call: ast.Call, index: int) -> str | None:
    """Get a string positional argument."""
    if len(call.args) > index:
        arg = call.args[index]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    return None
