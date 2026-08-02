"""Test: Dynamic tool registration patterns.
Many real agents don't define tools statically — they register them at runtime
from plugins, databases, or configuration files.

This tests whether our scanner can detect tools that are:
1. Registered from a loop
2. Created by a factory function
3. Loaded from a plugin system
4. Generated from a schema/config
"""
from langchain.agents import AgentExecutor, create_react_agent
from langchain_openai import ChatOpenAI
from langchain.tools import Tool, StructuredTool
from langchain import hub
from pydantic import BaseModel, Field
from typing import Callable
import os
import json


llm = ChatOpenAI(model="gpt-4")
prompt = hub.pull("hwchase17/react")


# === Pattern 1: Tool factory function ===
def make_db_tool(table_name: str) -> Tool:
    """Factory that creates a query tool for a specific table."""
    def query_func(sql: str) -> str:
        import sqlite3
        conn = sqlite3.connect(os.environ.get("DB_PATH", "app.db"))
        return str(conn.execute(sql).fetchall())

    return Tool(
        name=f"query_{table_name}",
        func=query_func,
        description=f"Execute SQL query against the {table_name} table."
    )


# === Pattern 2: Tools registered from config ===
TOOL_CONFIG = {
    "file_reader": {
        "description": "Read any file from the filesystem",
        "func": lambda path: open(path).read()
    },
    "web_fetcher": {
        "description": "Fetch content from a URL",
        "func": lambda url: __import__('urllib.request', fromlist=['urlopen']).urlopen(url).read().decode()
    },
    "env_reader": {
        "description": "Read an environment variable",
        "func": lambda key: os.environ.get(key, "NOT SET")
    }
}


# === Pattern 3: Tools from a loop (common in plugin systems) ===
tools = []

# Register DB tools for all tables
for table in ["users", "orders", "payments", "credentials"]:
    tools.append(make_db_tool(table))

# Register config-based tools
for name, config in TOOL_CONFIG.items():
    tools.append(Tool(
        name=name,
        func=config["func"],
        description=config["description"]
    ))


# === Pattern 4: StructuredTool with schema ===
class EmailInput(BaseModel):
    to: str = Field(description="Recipient email address")
    subject: str = Field(description="Email subject")
    body: str = Field(description="Email body")
    attachments: list[str] = Field(default=[], description="File paths to attach")


def send_email(to: str, subject: str, body: str, attachments: list[str] = []) -> str:
    """Send an email with optional attachments."""
    import smtplib
    from email.mime.text import MIMEText
    msg = MIMEText(body)
    msg['To'] = to
    msg['Subject'] = subject
    server = smtplib.SMTP(os.environ.get("SMTP_HOST", "smtp.company.com"), 587)
    server.login(os.environ.get("SMTP_USER"), os.environ.get("SMTP_PASS"))
    server.send_message(msg)
    return f"Email sent to {to}"


email_tool = StructuredTool.from_function(
    func=send_email,
    name="send_email",
    description="Send an email to anyone with optional file attachments.",
    args_schema=EmailInput,
)
tools.append(email_tool)


# === Pattern 5: Decorator-based tool registration ===
registered_tools = []

def register_tool(name: str, description: str):
    """Decorator to register a function as a tool."""
    def decorator(func: Callable):
        registered_tools.append(Tool(name=name, func=func, description=description))
        return func
    return decorator


@register_tool("run_script", "Execute a Python script file")
def run_script(script_path: str) -> str:
    """Run a Python script and return its output."""
    import subprocess
    result = subprocess.run(["python", script_path], capture_output=True, text=True)
    return result.stdout + result.stderr


@register_tool("kubectl", "Execute kubectl commands against the cluster")
def kubectl_command(command: str) -> str:
    """Run a kubectl command."""
    import subprocess
    return subprocess.run(f"kubectl {command}", shell=True, capture_output=True, text=True).stdout


tools.extend(registered_tools)

# Create the agent
agent = create_react_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools, verbose=True, max_iterations=20)
