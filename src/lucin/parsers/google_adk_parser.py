"""Parser for Google ADK (Agent Development Kit) agents.

Google's official agent framework. Key patterns:
- from google.adk import Agent (or from google.adk.agents import Agent)
- Agent(name="x", tools=[func1, func2], sub_agents=[child1, child2])
- FunctionTool(func=x, require_confirmation=True)
- ToolContext as a parameter in tool functions (stateful tools)

Security-relevant aspects:
- sub_agents create delegation chains (AG-014 risk)
- FunctionTool without require_confirmation = no human gate
- ToolContext.state provides persistent state (memory poisoning risk)
"""

import ast
from pathlib import Path

from lucin._fs import iter_files
from lucin.models import Agent, Tool
from lucin.parsers.body_inspector import (
    build_import_alias_map,
    inspect_function_body,
)
from lucin.parsers.langchain_parser import classify_tool_capabilities


def parse_google_adk(target: Path) -> list[Agent]:
    """Parse Google ADK agent definitions."""
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

        if not _is_google_adk_file(content):
            continue

        file_agents = _parse_adk_agents(content, str(py_file))
        agents.extend(file_agents)

    return agents


def _is_google_adk_file(content: str) -> bool:
    """Check if this file uses Google ADK."""
    return "from google.adk" in content or "from google.adk.agents" in content


def _parse_adk_agents(content: str, filepath: str) -> list[Agent]:
    """Parse all Agent() definitions in a Google ADK file."""
    agents = []

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return agents

    # Build maps
    func_map = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            func_map[node.name] = node

    import_aliases = build_import_alias_map(tree)

    # Find all Agent() assignments
    agent_vars = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = node.value
            call_name = _get_call_name(call)
            if call_name == "Agent":
                var_name = node.targets[0].id if node.targets and isinstance(node.targets[0], ast.Name) else None
                if var_name:
                    agent_vars[var_name] = call

    # Parse each agent
    for var_name, call in agent_vars.items():
        name = _get_keyword_str(call, "name") or var_name
        _get_keyword_str(call, "description") or ""
        _get_keyword_str(call, "instruction") or ""

        # Parse tools
        tools = []
        tools_arg = _get_keyword_value(call, "tools")
        if isinstance(tools_arg, ast.List):
            for elt in tools_arg.elts:
                tool = _resolve_adk_tool(elt, func_map, import_aliases, filepath)
                if tool:
                    tools.append(tool)

        # Parse sub_agents (delegation)
        has_sub_agents = False
        sub_agents_arg = _get_keyword_value(call, "sub_agents")
        if isinstance(sub_agents_arg, ast.List) and sub_agents_arg.elts:
            has_sub_agents = True

        # Check for ToolContext usage (indicates stateful tools)
        has_memory = "tool_context" in content.lower() or "toolcontext" in content.lower()

        # Check for human confirmation
        has_confirmation = "require_confirmation" in content and "True" in content

        agents.append(Agent(
            name=name,
            framework="google_adk",
            tools=tools,
            source_file=filepath,
            has_human_in_loop=has_confirmation,
            can_spawn_subagents=has_sub_agents,
            has_memory=has_memory,
        ))

    return agents


def _resolve_adk_tool(node: ast.expr, func_map: dict, aliases: dict, filepath: str) -> Tool | None:
    """Resolve a Google ADK tool reference.

    Handles:
    - Plain function reference: tools=[my_func]
    - FunctionTool wrapper: tools=[FunctionTool(func=x, require_confirmation=True)]
    """
    if isinstance(node, ast.Name):
        # Plain function reference
        func_name = node.id
        if func_name in func_map:
            func_node = func_map[func_name]
            docstring = ast.get_docstring(func_node) or ""
            capabilities = classify_tool_capabilities(func_name, docstring)
            # Body inspection
            body_caps = inspect_function_body(func_node, import_aliases=aliases)
            capabilities = list(set(capabilities + body_caps))
            return Tool(
                name=func_name,
                description=docstring[:200],
                capabilities=capabilities,
                source_file=filepath,
                source_line=func_node.lineno,
                has_human_approval="require_confirmation" in (docstring or ""),
            )
        else:
            capabilities = classify_tool_capabilities(func_name, "")
            return Tool(
                name=func_name,
                description="(imported function)",
                capabilities=capabilities,
                source_file=filepath,
            )

    elif isinstance(node, ast.Call):
        # FunctionTool(func=x, require_confirmation=True)
        call_name = _get_call_name(node)
        if call_name == "FunctionTool":
            # Extract the wrapped function
            func_ref = _get_keyword_value(node, "func")
            has_confirm = False
            for kw in node.keywords:
                if kw.arg == "require_confirmation":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        has_confirm = True

            if isinstance(func_ref, ast.Name) and func_ref.id in func_map:
                func_node = func_map[func_ref.id]
                docstring = ast.get_docstring(func_node) or ""
                capabilities = classify_tool_capabilities(func_ref.id, docstring)
                body_caps = inspect_function_body(func_node, import_aliases=aliases)
                capabilities = list(set(capabilities + body_caps))
                return Tool(
                    name=func_ref.id,
                    description=docstring[:200],
                    capabilities=capabilities,
                    source_file=filepath,
                    source_line=func_node.lineno,
                    has_human_approval=has_confirm,
                )

    return None


def _get_call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    elif isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _get_keyword_str(call: ast.Call, keyword: str) -> str | None:
    for kw in call.keywords:
        if kw.arg == keyword and isinstance(kw.value, ast.Constant):
            return str(kw.value.value)
    return None


def _get_keyword_value(call: ast.Call, keyword: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == keyword:
            return kw.value
    return None
