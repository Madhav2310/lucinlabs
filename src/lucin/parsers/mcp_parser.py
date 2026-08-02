"""Parser for MCP server configurations."""

import json
from pathlib import Path

import yaml

from lucin._fs import iter_files
from lucin.models import Agent, MCPServer, Tool, ToolCapability
from lucin.parsers.langchain_parser import classify_tool_capabilities


# Common MCP config file names
MCP_CONFIG_FILES = [
    "mcp.json",
    "mcp_config.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "mcp-servers.yaml",
    "mcp-servers.yml",
]


def parse_mcp_config(target: Path) -> list[Agent]:
    """Parse MCP server configurations from config files."""
    agents = []

    if target.is_file():
        config_files = [target]
    else:
        config_files = []
        for name in MCP_CONFIG_FILES:
            found = iter_files(target, name)
            config_files.extend(found)

    for config_file in config_files:
        # Per-file crash isolation (E1): a single malformed config (odd shapes
        # like a non-dict `headers` block) must not abort parsing of the rest.
        try:
            parsed = _parse_single_config(config_file)
        except Exception:  # noqa: BLE001 — one bad file must not kill the parser
            parsed = None
        if parsed:
            agents.append(parsed)

    return agents


def _parse_single_config(config_file: Path) -> Agent | None:
    """Parse a single MCP configuration file."""
    try:
        content = config_file.read_text(encoding="utf-8")
    except (UnicodeDecodeError, PermissionError):
        return None

    # Parse JSON or YAML
    data = None
    if config_file.suffix in (".json",):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return None
    elif config_file.suffix in (".yaml", ".yml"):
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError:
            return None
    else:
        # Try JSON first, then YAML
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError:
                return None

    if not data or not isinstance(data, dict):
        return None

    # Extract MCP servers
    mcp_servers = []
    servers_data = data.get("mcpServers", data.get("servers", data.get("mcp_servers", {})))

    if isinstance(servers_data, dict):
        for server_name, server_config in servers_data.items():
            server = _parse_server_entry(server_name, server_config, str(config_file))
            mcp_servers.append(server)

    if not mcp_servers:
        return None

    # Aggregate all tools across servers into a single agent view
    all_tools = []
    for server in mcp_servers:
        all_tools.extend(server.tools)

    return Agent(
        name=config_file.parent.name or "mcp-agent",
        framework="mcp",
        tools=all_tools,
        mcp_servers=mcp_servers,
        source_file=str(config_file),
    )


def _parse_server_entry(name: str, config: dict, filepath: str) -> MCPServer:
    """Parse a single MCP server entry."""
    if not isinstance(config, dict):
        return MCPServer(name=name)

    # Determine transport
    command = config.get("command", "")
    url = config.get("url", "")
    transport = "stdio"
    if url:
        transport = "streamable_http" if "http" in url.lower() else "sse"

    # Check for authentication. `headers` may be malformed (non-dict) in
    # hand-written configs — guard the nested lookup so it degrades to "no auth"
    # instead of raising (E1 crash-isolation, defence in depth).
    headers = config.get("headers")
    header_auth = headers.get("Authorization") if isinstance(headers, dict) else None
    has_auth = bool(
        config.get("auth")
        or config.get("authentication")
        or header_auth
        or config.get("oauth")
    )

    # Check for TLS
    has_tls = "https" in url.lower() if url else False

    # Extract tools if listed
    tools = []
    tools_data = config.get("tools", [])
    if isinstance(tools_data, list):
        for tool_entry in tools_data:
            if isinstance(tool_entry, str):
                capabilities = classify_tool_capabilities(tool_entry)
                tools.append(Tool(
                    name=tool_entry,
                    capabilities=capabilities,
                    source_file=filepath,
                ))
            elif isinstance(tool_entry, dict):
                tool_name = tool_entry.get("name", "unnamed")
                description = tool_entry.get("description", "")
                capabilities = classify_tool_capabilities(tool_name, description)
                tools.append(Tool(
                    name=tool_name,
                    description=description,
                    capabilities=capabilities,
                    parameters=tool_entry.get("parameters", tool_entry.get("inputSchema", {})),
                    source_file=filepath,
                ))

    # Extract env vars — these are often the richest source of secrets
    env_vars: dict[str, str] = {}
    raw_env = config.get("env", {})
    if isinstance(raw_env, dict):
        env_vars = {k: str(v) for k, v in raw_env.items()}

    return MCPServer(
        name=name,
        url=url,
        transport=transport,
        has_authentication=has_auth,
        has_tls=has_tls,
        tools=tools,
        env_vars=env_vars,
    )
