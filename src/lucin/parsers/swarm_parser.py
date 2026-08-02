"""Parser for OpenAI Swarm and Agents SDK frameworks.

Handles:
1. OpenAI Swarm: `from swarm import Agent` + `Agent(name=..., functions=[...])`
2. OpenAI Agents SDK: `from agents import Agent, Runner` + `Agent(tools=[...])`

These are two distinct but related frameworks:
- Swarm (educational, Jan 2024): lightweight multi-agent orchestration
- Agents SDK (production, 2025+): official successor with guardrails/handoffs
"""

import ast
import re
from pathlib import Path

from lucin._fs import iter_files
from lucin.models import Agent, Tool, ToolCapability
from lucin.parsers.langchain_parser import classify_tool_capabilities


def parse_swarm(target: Path) -> list[Agent]:
    """Parse OpenAI Swarm and Agents SDK agent definitions."""
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

        if _is_swarm_file(content):
            agents.extend(_parse_swarm_agents(content, str(py_file)))
        elif _is_agents_sdk_file(content):
            agents.extend(_parse_agents_sdk(content, str(py_file)))

    return agents


def _is_swarm_file(content: str) -> bool:
    """Check if this file uses OpenAI Swarm."""
    return "from swarm import" in content or "from swarm " in content


def _is_agents_sdk_file(content: str) -> bool:
    """Check if this file uses OpenAI Agents SDK."""
    return (
        ("from agents import" in content or "from agents " in content)
        and ("Agent" in content)
        and ("Runner" in content or "Tool" in content)
    )


def _parse_swarm_agents(content: str, filepath: str) -> list[Agent]:
    """Parse Swarm Agent(...) definitions."""
    agents = []

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return agents

    # First pass: collect all function definitions (potential tools)
    func_defs = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            func_defs[node.name] = node

    # Second pass: find Agent(...) assignments
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue

        # Look for: variable = Agent(...)
        if not (node.value and isinstance(node.value, ast.Call)):
            continue

        call = node.value
        func_name = _get_call_name(call)
        if func_name != "Agent":
            continue

        # Extract Agent parameters
        agent_name = _get_keyword_str(call, "name") or _get_assign_name(node)
        instructions = _get_keyword_str(call, "instructions") or ""
        functions_arg = _get_keyword_value(call, "functions")

        # Parse functions list
        tools = []
        if isinstance(functions_arg, ast.List):
            for elt in functions_arg.elts:
                tool = _resolve_function_tool(elt, func_defs, filepath)
                if tool:
                    tools.append(tool)

        # Check for transfer functions (delegation capability)
        can_delegate = False
        transfer_targets = []
        for tool in tools:
            if "transfer" in tool.name.lower():
                can_delegate = True
                transfer_targets.append(tool.name)

        agents.append(Agent(
            name=agent_name or "unnamed_agent",
            framework="swarm",
            tools=tools,
            source_file=filepath,
            has_human_in_loop=_check_human_loop(instructions),
            can_spawn_subagents=can_delegate,
            has_memory=False,  # Swarm is stateless by design
        ))

    # Third pass: check for runtime function assignment
    # Pattern: agent.functions = [...] or agent.functions.append(...)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target_node in node.targets:
                if (isinstance(target_node, ast.Attribute)
                    and target_node.attr == "functions"
                    and isinstance(node.value, ast.List)):
                    # Find which agent this belongs to
                    agent_var = _get_attr_name(target_node)
                    if agent_var:
                        _augment_agent_tools(
                            agents, agent_var, node.value, func_defs, filepath
                        )

    return agents


def _parse_agents_sdk(content: str, filepath: str) -> list[Agent]:
    """Parse OpenAI Agents SDK Agent(...) definitions."""
    agents = []

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return agents

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue

        if not (node.value and isinstance(node.value, ast.Call)):
            continue

        call = node.value
        func_name = _get_call_name(call)
        if func_name != "Agent":
            continue

        agent_name = _get_keyword_str(call, "name") or _get_assign_name(node)
        instructions = _get_keyword_str(call, "instructions") or ""
        tools_arg = _get_keyword_value(call, "tools")

        tools = []
        if isinstance(tools_arg, ast.List):
            for elt in tools_arg.elts:
                tool = _resolve_sdk_tool(elt, filepath)
                if tool:
                    tools.append(tool)

        agents.append(Agent(
            name=agent_name or "unnamed_agent",
            framework="openai_agents_sdk",
            tools=tools,
            source_file=filepath,
            has_human_in_loop=_check_human_loop(instructions),
            can_spawn_subagents="handoff" in content.lower() or "transfer" in content.lower(),
            has_memory="thread" in content.lower() or "memory" in content.lower(),
        ))

    return agents


def _resolve_function_tool(node: ast.expr, func_defs: dict, filepath: str) -> Tool | None:
    """Resolve a Swarm function reference to a Tool."""
    if isinstance(node, ast.Name):
        # Direct function reference: functions=[my_func]
        func_name = node.id
        func_node = func_defs.get(func_name)
        if func_node:
            docstring = ast.get_docstring(func_node) or ""
            capabilities = classify_tool_capabilities(func_name, docstring)
            return Tool(
                name=func_name,
                description=docstring[:200],
                capabilities=capabilities,
                source_file=filepath,
                source_line=func_node.lineno,
            )
        else:
            # Function imported from elsewhere — infer from name
            capabilities = classify_tool_capabilities(func_name, "")
            return Tool(
                name=func_name,
                description="(imported function)",
                capabilities=capabilities,
                source_file=filepath,
                source_line=node.lineno if hasattr(node, 'lineno') else 0,
            )
    return None


def _resolve_sdk_tool(node: ast.expr, filepath: str) -> Tool | None:
    """Resolve an Agents SDK tool reference."""
    # Pattern: WebSearchTool(...), FileSearchTool(...), CodeInterpreterTool(...)
    if isinstance(node, ast.Call):
        tool_class = _get_call_name(node)
        if tool_class:
            return _classify_sdk_tool(tool_class, filepath, getattr(node, 'lineno', 0))
    elif isinstance(node, ast.Name):
        # Variable reference
        return Tool(
            name=node.id,
            description="(tool reference)",
            capabilities=classify_tool_capabilities(node.id, ""),
            source_file=filepath,
        )
    return None


def _classify_sdk_tool(class_name: str, filepath: str, line: int) -> Tool:
    """Classify an Agents SDK tool class into capabilities."""
    name_lower = class_name.lower()

    # Known Agents SDK tool classes
    if "websearch" in name_lower or "web_search" in name_lower:
        return Tool(
            name=class_name,
            description="Web search tool — queries the internet",
            capabilities=[ToolCapability.NETWORK_ACCESS, ToolCapability.READ_DATA],
            source_file=filepath,
            source_line=line,
        )
    elif "codeinterpreter" in name_lower or "code_interpreter" in name_lower:
        return Tool(
            name=class_name,
            description="Code interpreter — executes Python code in sandbox",
            capabilities=[ToolCapability.EXECUTE_CODE, ToolCapability.FILE_SYSTEM],
            has_sandbox=True,
            source_file=filepath,
            source_line=line,
        )
    elif "filesearch" in name_lower or "file_search" in name_lower:
        return Tool(
            name=class_name,
            description="File search tool — searches uploaded files",
            capabilities=[ToolCapability.READ_DATA],
            source_file=filepath,
            source_line=line,
        )
    elif "computer" in name_lower:
        return Tool(
            name=class_name,
            description="Computer use tool — controls mouse/keyboard",
            capabilities=[ToolCapability.EXECUTE_CODE, ToolCapability.FILE_SYSTEM,
                         ToolCapability.NETWORK_ACCESS],
            source_file=filepath,
            source_line=line,
        )
    else:
        return Tool(
            name=class_name,
            description=f"(Agents SDK tool: {class_name})",
            capabilities=classify_tool_capabilities(class_name, ""),
            source_file=filepath,
            source_line=line,
        )


# === Helper functions ===

def _get_call_name(call: ast.Call) -> str | None:
    """Get the function/class name from a Call node."""
    if isinstance(call.func, ast.Name):
        return call.func.id
    elif isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _get_keyword_str(call: ast.Call, keyword: str) -> str | None:
    """Get a string keyword argument value."""
    for kw in call.keywords:
        if kw.arg == keyword:
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
            elif isinstance(kw.value, ast.JoinedStr):
                # f-string — just return placeholder
                return "(dynamic)"
    return None


def _get_keyword_value(call: ast.Call, keyword: str) -> ast.expr | None:
    """Get a keyword argument AST node."""
    for kw in call.keywords:
        if kw.arg == keyword:
            return kw.value
    return None


def _get_assign_name(node: ast.Assign) -> str | None:
    """Get the variable name from an assignment."""
    if node.targets and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    return None


def _get_attr_name(node: ast.Attribute) -> str | None:
    """Get the object name from an attribute access (e.g., agent.functions -> agent)."""
    if isinstance(node.value, ast.Name):
        return node.value.id
    return None


def _augment_agent_tools(
    agents: list[Agent], agent_var: str,
    value: ast.List, func_defs: dict, filepath: str
):
    """Add tools to an existing agent from runtime assignment."""
    for agent in agents:
        # Match by variable name (approximate — the agent_name might differ)
        if agent_var.replace("_", " ").lower() in agent.name.lower().replace("_", " "):
            for elt in value.elts:
                tool = _resolve_function_tool(elt, func_defs, filepath)
                if tool:
                    agent.tools.append(tool)
            # Update delegation capability
            if any("transfer" in t.name.lower() for t in agent.tools):
                agent.can_spawn_subagents = True
            break


def _check_human_loop(instructions: str) -> bool:
    """Check if instructions mention human oversight."""
    indicators = [
        "ask for", "confirm", "user confirmation",
        "human approval", "check with", "verify with user",
    ]
    return any(ind in instructions.lower() for ind in indicators)
