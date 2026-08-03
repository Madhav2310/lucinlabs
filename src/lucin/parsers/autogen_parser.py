"""Parser for Microsoft AutoGen agent definitions.

AutoGen uses Python-based conversation configurations:
- AssistantAgent: AI agents that can call tools
- UserProxyAgent: Proxies for human interaction (often with code execution)
- GroupChat: Multi-agent orchestration
- Tool registration via register_for_llm / register_for_execution

Security concerns specific to AutoGen:
- UserProxyAgent often has code_execution_config with Docker or local execution
- GroupChat allows agents to invoke each other without clear boundaries
- Tool functions are registered at runtime, making static analysis harder

Reference: AutoGen (microsoft/autogen) — part of Microsoft Agent Framework 1.0
"""

import ast
from pathlib import Path

from lucin._fs import iter_files
from lucin.models import Agent, Tool, ToolCapability
from lucin.parsers.langchain_parser import classify_tool_capabilities


def parse_autogen(target: Path) -> list[Agent]:
    """Parse AutoGen agent definitions from Python source files."""
    agents = []
    python_files = iter_files(target, "*.py")

    for py_file in python_files:
        try:
            content = py_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        # Skip files without AutoGen imports
        if "autogen" not in content and "AssistantAgent" not in content:
            continue

        file_agents = _extract_autogen_agents(content, str(py_file))
        agents.extend(file_agents)

    return agents


def _extract_autogen_agents(source: str, filepath: str) -> list[Agent]:
    """Extract AutoGen agent definitions from Python source."""
    agents = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return agents

    # Track registered tools (function_name -> Tool)
    registered_tools = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func_name = _get_call_name(node)

        # Detect AssistantAgent(...) or UserProxyAgent(...)
        if func_name in ("AssistantAgent", "UserProxyAgent", "ConversableAgent"):
            agent = _parse_agent_call(node, func_name, filepath, source)
            if agent:
                agents.append(agent)

        # Detect tool registration: register_for_llm / register_for_execution
        if func_name in ("register_for_llm", "register_for_execution", "register_function"):
            tool = _parse_tool_registration(node, filepath)
            if tool:
                registered_tools[tool.name] = tool

    # Associate registered tools with agents
    # (In AutoGen, tools are registered globally then associated)
    if registered_tools and agents:
        for agent in agents:
            # AutoGen agents typically share all registered tools
            agent.tools.extend(registered_tools.values())

    return agents


def _parse_agent_call(node: ast.Call, agent_type: str, filepath: str, source: str) -> Agent | None:
    """Parse an Agent constructor call."""
    name = _get_kwarg_str(node, "name") or agent_type.lower()

    # Check for code execution config (UserProxyAgent-specific)
    has_code_exec = False
    code_exec_config = _get_kwarg_node(node, "code_execution_config")
    if code_exec_config:
        has_code_exec = True

    # Also check if UserProxyAgent (almost always has exec capability)
    if agent_type == "UserProxyAgent":
        has_code_exec = True

    # Extract tools from llm_config.functions or tools parameter
    tools = []
    if has_code_exec:
        tools.append(Tool(
            name="code_execution",
            description="AutoGen code execution capability (runs Python/shell code)",
            capabilities=[ToolCapability.EXECUTE_CODE, ToolCapability.FILE_SYSTEM],
            source_file=filepath,
            source_line=node.lineno if hasattr(node, "lineno") else 0,
        ))

    # Check for human_input_mode
    human_input = _get_kwarg_str(node, "human_input_mode")
    has_human_in_loop = human_input in ("ALWAYS", "TERMINATE") if human_input else False

    # Check for is_termination_msg (indicates some oversight)
    has_termination = "is_termination_msg" in source[node.col_offset:node.end_col_offset] if hasattr(node, "end_col_offset") else False

    return Agent(
        name=name,
        framework="autogen",
        tools=tools,
        has_human_in_loop=has_human_in_loop or has_termination,
        can_spawn_subagents=agent_type == "UserProxyAgent",  # Proxies can delegate
        has_memory=True,  # AutoGen agents maintain conversation history
        source_file=filepath,
    )


def _parse_tool_registration(node: ast.Call, filepath: str) -> Tool | None:
    """Parse a tool registration call."""
    # Pattern: @agent.register_for_llm(description="...")
    # Pattern: register_function(func, agent=..., description="...")
    description = _get_kwarg_str(node, "description") or ""
    name = _get_kwarg_str(node, "name") or ""

    # Try to get the function being registered
    if not name and node.args:
        first_arg = node.args[0]
        if isinstance(first_arg, ast.Name):
            name = first_arg.id
        elif isinstance(first_arg, ast.Attribute):
            name = first_arg.attr

    if not name:
        return None

    capabilities = classify_tool_capabilities(name, description)

    return Tool(
        name=name,
        description=description,
        capabilities=capabilities,
        source_file=filepath,
        source_line=node.lineno if hasattr(node, "lineno") else 0,
    )


def _get_call_name(node: ast.Call) -> str:
    """Get the function name from a Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _get_kwarg_str(node: ast.Call, kwarg_name: str) -> str | None:
    """Extract a string keyword argument."""
    for kw in node.keywords:
        if kw.arg == kwarg_name and isinstance(kw.value, ast.Constant):
            return str(kw.value.value)
    return None


def _get_kwarg_node(node: ast.Call, kwarg_name: str):
    """Get the AST node for a keyword argument."""
    for kw in node.keywords:
        if kw.arg == kwarg_name:
            return kw.value
    return None
