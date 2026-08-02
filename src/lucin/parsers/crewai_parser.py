"""Parser for CrewAI agent definitions.

CrewAI uses a YAML-based configuration system with two primary files:
- config/agents.yaml: Defines agents with roles, goals, tools, LLM settings
- config/tasks.yaml: Defines tasks with descriptions, agents, expected output

The crew.py file wires everything together using the @CrewBase decorator.

This parser handles both:
1. YAML config files (config/agents.yaml, config/tasks.yaml)
2. Python crew definitions (crew.py with @CrewBase decorator)
3. Inline Python definitions (Agent(), Task(), Crew() classes)

Reference: CrewAI v1.14+ (49K stars, 6.7K forks as of April 2026)
"""

import ast
import re
from pathlib import Path

import yaml

from lucin._fs import iter_files
from lucin.models import Agent, Tool, ToolCapability, MCPServer
from lucin.parsers.langchain_parser import classify_tool_capabilities


# CrewAI-specific tool patterns
CREWAI_BUILTIN_TOOLS = {
    "SerperDevTool": (ToolCapability.NETWORK_ACCESS, ToolCapability.READ_DATA),
    "ScrapeWebsiteTool": (ToolCapability.NETWORK_ACCESS, ToolCapability.READ_DATA),
    "WebsiteSearchTool": (ToolCapability.NETWORK_ACCESS, ToolCapability.READ_DATA),
    "FileReadTool": (ToolCapability.READ_DATA, ToolCapability.FILE_SYSTEM),
    "FileWriterTool": (ToolCapability.WRITE_DATA, ToolCapability.FILE_SYSTEM),
    "DirectoryReadTool": (ToolCapability.READ_DATA, ToolCapability.FILE_SYSTEM),
    "DirectorySearchTool": (ToolCapability.READ_DATA, ToolCapability.FILE_SYSTEM),
    "CodeInterpreterTool": (ToolCapability.EXECUTE_CODE,),
    "CodeDocsSearchTool": (ToolCapability.READ_DATA,),
    "CSVSearchTool": (ToolCapability.READ_DATA,),
    "DOCXSearchTool": (ToolCapability.READ_DATA,),
    "EXASearchTool": (ToolCapability.NETWORK_ACCESS, ToolCapability.READ_DATA),
    "GithubSearchTool": (ToolCapability.NETWORK_ACCESS, ToolCapability.READ_DATA),
    "JSONSearchTool": (ToolCapability.READ_DATA,),
    "MDXSearchTool": (ToolCapability.READ_DATA,),
    "PDFSearchTool": (ToolCapability.READ_DATA,),
    "PGSearchTool": (ToolCapability.READ_DATA,),
    "TXTSearchTool": (ToolCapability.READ_DATA,),
    "XMLSearchTool": (ToolCapability.READ_DATA,),
    "YoutubeChannelSearchTool": (ToolCapability.NETWORK_ACCESS, ToolCapability.READ_DATA),
    "YoutubeVideoSearchTool": (ToolCapability.NETWORK_ACCESS, ToolCapability.READ_DATA),
    "BrowserbaseLoadTool": (ToolCapability.NETWORK_ACCESS, ToolCapability.READ_DATA),
    "ComposioTool": (ToolCapability.NETWORK_ACCESS,),  # Depends on action
    "LlamaIndexTool": (ToolCapability.READ_DATA,),
    "RagTool": (ToolCapability.READ_DATA,),
    "DallETool": (ToolCapability.NETWORK_ACCESS,),
    "VisionTool": (ToolCapability.READ_DATA,),
}


def parse_crewai(target: Path) -> list[Agent]:
    """Parse CrewAI agent definitions from YAML configs and Python files."""
    agents = []

    if target.is_file():
        if target.suffix in (".yaml", ".yml"):
            agents.extend(_parse_crewai_yaml(target))
        elif target.suffix == ".py":
            agents.extend(_parse_crewai_python(target))
    else:
        # Search for CrewAI config patterns in directory
        # Pattern 1: config/agents.yaml
        config_dir = target / "config"
        if config_dir.exists():
            agents_yaml = config_dir / "agents.yaml"
            if not agents_yaml.exists():
                agents_yaml = config_dir / "agents.yml"
            if agents_yaml.exists():
                agents.extend(_parse_crewai_yaml(agents_yaml))

        # Pattern 2: agents.yaml at root
        for yaml_name in ["agents.yaml", "agents.yml"]:
            yaml_path = target / yaml_name
            if yaml_path.exists():
                agents.extend(_parse_crewai_yaml(yaml_path))

        # Pattern 3: Python files with CrewAI imports
        for py_file in iter_files(target, "*.py"):
            try:
                content = py_file.read_text(encoding="utf-8")
                if "crewai" in content.lower() or "CrewBase" in content:
                    agents.extend(_parse_crewai_python(py_file))
            except (UnicodeDecodeError, PermissionError):
                continue

    return agents


def _parse_crewai_yaml(yaml_path: Path) -> list[Agent]:
    """Parse a CrewAI agents.yaml OR generic agent YAML config file."""
    agents = []

    try:
        content = yaml_path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
    except (yaml.YAMLError, UnicodeDecodeError, PermissionError):
        return agents

    if not isinstance(data, dict):
        return agents

    # Check if this is a generic agent YAML (SWE-agent, custom configs)
    # Pattern: has "agent" top-level key with "tools" sub-key
    if "agent" in data and isinstance(data["agent"], dict):
        generic_agent = _parse_generic_yaml_agent(data, str(yaml_path))
        if generic_agent:
            agents.append(generic_agent)
            return agents

    for agent_key, agent_config in data.items():
        if not isinstance(agent_config, dict):
            continue

        # Extract agent properties
        role = agent_config.get("role", agent_key)
        goal = agent_config.get("goal", "")
        backstory = agent_config.get("backstory", "")

        # Extract tools
        tools = []
        tools_config = agent_config.get("tools", [])
        if isinstance(tools_config, list):
            for tool_ref in tools_config:
                tool_name = str(tool_ref)
                capabilities = _get_crewai_tool_capabilities(tool_name)
                tools.append(Tool(
                    name=tool_name,
                    description=f"CrewAI tool: {tool_name}",
                    capabilities=list(capabilities),
                    source_file=str(yaml_path),
                ))

        # Check for memory
        has_memory = agent_config.get("memory", False)

        # Check for delegation
        allow_delegation = agent_config.get("allow_delegation", False)

        agents.append(Agent(
            name=agent_key,
            framework="crewai",
            tools=tools,
            has_memory=bool(has_memory),
            can_spawn_subagents=bool(allow_delegation),
            has_human_in_loop=agent_config.get("human_input", False),
            source_file=str(yaml_path),
        ))

    return agents


def _parse_crewai_python(py_file: Path) -> list[Agent]:
    """Parse CrewAI agent definitions from Python source code."""
    agents = []

    try:
        content = py_file.read_text(encoding="utf-8")
    except (UnicodeDecodeError, PermissionError):
        return agents

    if "crewai" not in content.lower():
        return agents

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return agents

    # Find Agent() instantiations
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Match: Agent(...) or crewai.Agent(...)
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name != "Agent":
            continue

        # Extract Agent kwargs
        agent_name = _get_kwarg_value(node, "role") or _get_kwarg_value(node, "name") or "crewai_agent"
        goal = _get_kwarg_value(node, "goal") or ""
        allow_delegation = _get_kwarg_bool(node, "allow_delegation")
        memory = _get_kwarg_bool(node, "memory")
        human_input = _get_kwarg_bool(node, "human_input")

        # Extract tools
        tools = _extract_tools_from_call(node, content, str(py_file))

        agents.append(Agent(
            name=agent_name,
            framework="crewai",
            tools=tools,
            has_memory=memory,
            can_spawn_subagents=allow_delegation,
            has_human_in_loop=human_input,
            source_file=str(py_file),
        ))

    return agents


def _parse_generic_yaml_agent(data: dict, filepath: str) -> Agent | None:
    """Parse a generic YAML agent config (SWE-agent, custom frameworks).

    Recognizes:
    - agent.tools.enable_bash_tool: true → EXECUTE_CODE
    - agent.tools.bundles: [...] → tools from bundles
    - agent.tools.env_variables → environment access
    """
    agent_config = data.get("agent", {})
    if not isinstance(agent_config, dict):
        return None

    tools_config = agent_config.get("tools", {})
    tools = []

    if isinstance(tools_config, dict):
        # enable_bash_tool: true → shell access
        if tools_config.get("enable_bash_tool", False):
            tools.append(Tool(
                name="bash_tool",
                description="Bash shell execution (enable_bash_tool: true)",
                capabilities=[ToolCapability.EXECUTE_CODE, ToolCapability.FILE_SYSTEM],
                source_file=filepath,
            ))

        # Tool bundles (SWE-agent pattern)
        bundles = tools_config.get("bundles", [])
        if isinstance(bundles, list):
            for bundle in bundles:
                bundle_path = bundle.get("path", "") if isinstance(bundle, dict) else str(bundle)
                if "edit" in bundle_path.lower():
                    tools.append(Tool(
                        name=f"bundle:{bundle_path}",
                        description=f"Tool bundle: {bundle_path}",
                        capabilities=[ToolCapability.WRITE_DATA, ToolCapability.FILE_SYSTEM],
                        source_file=filepath,
                    ))
                elif "registry" in bundle_path.lower():
                    tools.append(Tool(
                        name=f"bundle:{bundle_path}",
                        description=f"Tool bundle: {bundle_path}",
                        capabilities=[ToolCapability.READ_DATA, ToolCapability.FILE_SYSTEM],
                        source_file=filepath,
                    ))

        # env_variables → may expose secrets
        env_vars = tools_config.get("env_variables", {})
        if env_vars:
            tools.append(Tool(
                name="env_access",
                description=f"Access to {len(env_vars)} environment variables",
                capabilities=[ToolCapability.READ_DATA],
                source_file=filepath,
            ))

    if not tools:
        return None

    # Extract name from templates or file
    name = "agent"
    templates = agent_config.get("templates", {})
    if isinstance(templates, dict):
        sys_template = templates.get("system_template", "")
        if "computer" in sys_template.lower() or "bash" in sys_template.lower():
            name = "coding_agent"

    return Agent(
        name=name,
        framework="yaml_config",
        tools=tools,
        has_memory=False,
        can_spawn_subagents=False,
        has_human_in_loop=False,
        source_file=filepath,
    )


def _get_crewai_tool_capabilities(tool_name: str) -> tuple:
    """Get capabilities for a known CrewAI tool."""
    # Check exact match first
    if tool_name in CREWAI_BUILTIN_TOOLS:
        return CREWAI_BUILTIN_TOOLS[tool_name]

    # Check partial match (e.g., "SerperDevTool()" contains "SerperDevTool")
    for known_tool, capabilities in CREWAI_BUILTIN_TOOLS.items():
        if known_tool in tool_name:
            return capabilities

    # Fall back to generic classification
    generic_caps = classify_tool_capabilities(tool_name)
    return tuple(generic_caps) if generic_caps else ()


def _extract_tools_from_call(node: ast.Call, source: str, filepath: str) -> list[Tool]:
    """Extract tools from an Agent() constructor call.

    Handles:
    - Tool instantiation: tools=[ScrapeWebsiteTool()]
    - Variable reference: tools=[my_tool]
    - Class.method reference: tools=[SearchTools.search_internet]  (cross-file pattern)
    - Mixed: tools=[SearchTools.search_internet, BrowserTools.scrape_website, CalculatorTool()]
    """
    tools = []

    for kw in node.keywords:
        if kw.arg != "tools":
            continue

        if isinstance(kw.value, ast.List):
            for elt in kw.value.elts:
                tool_name = ""
                full_name = ""

                if isinstance(elt, ast.Call):
                    # Tool instantiation: ScrapeWebsiteTool() or CalculatorTool()
                    if isinstance(elt.func, ast.Name):
                        tool_name = elt.func.id
                    elif isinstance(elt.func, ast.Attribute):
                        tool_name = elt.func.attr
                        if isinstance(elt.func.value, ast.Name):
                            full_name = f"{elt.func.value.id}.{elt.func.attr}"
                elif isinstance(elt, ast.Name):
                    # Variable reference: my_tool_instance
                    tool_name = elt.id
                elif isinstance(elt, ast.Attribute):
                    # Class.method pattern: SearchTools.search_internet
                    # This is the cross-file pattern we were missing!
                    tool_name = elt.attr
                    if isinstance(elt.value, ast.Name):
                        full_name = f"{elt.value.id}.{elt.attr}"

                if tool_name:
                    # Try builtin lookup first with full name, then short name
                    capabilities = _get_crewai_tool_capabilities(full_name or tool_name)
                    if not capabilities:
                        # Heuristic: classify from the METHOD name
                        # "search_internet" → NETWORK_ACCESS
                        # "scrape_and_summarize_website" → NETWORK_ACCESS
                        # "calculate" → safe
                        capabilities = tuple(classify_tool_capabilities(tool_name, ""))
                    tools.append(Tool(
                        name=full_name or tool_name,
                        description=f"CrewAI tool: {full_name or tool_name}",
                        capabilities=list(capabilities),
                        source_file=filepath,
                        source_line=node.lineno if hasattr(node, "lineno") else 0,
                    ))

    return tools


def _get_kwarg_value(node: ast.Call, kwarg_name: str) -> str | None:
    """Extract a string keyword argument value from a function call."""
    for kw in node.keywords:
        if kw.arg == kwarg_name:
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
            elif isinstance(kw.value, ast.JoinedStr):
                # f-string — can't easily extract, return placeholder
                return f"<{kwarg_name}>"
    return None


def _get_kwarg_bool(node: ast.Call, kwarg_name: str) -> bool:
    """Extract a boolean keyword argument value."""
    for kw in node.keywords:
        if kw.arg == kwarg_name:
            if isinstance(kw.value, ast.Constant):
                return bool(kw.value.value)
            elif isinstance(kw.value, ast.Name):
                return kw.value.id == "True"
    return False
