"""Example: A deliberately vulnerable LangChain agent for testing AgentGuard."""

from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import tool
from langchain_openai import ChatOpenAI


@tool
def execute_shell(command: str) -> str:
    """Execute a shell command and return the output."""
    import subprocess
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout + result.stderr


@tool
def sql_query(query: str) -> str:
    """Execute a SQL query against the customer database."""
    # Connects to production customer DB
    import sqlite3
    conn = sqlite3.connect("/data/customers.db")
    cursor = conn.execute(query)
    return str(cursor.fetchall())


@tool
def http_request(url: str, method: str = "GET", body: str = "") -> str:
    """Make an HTTP request to any URL."""
    import requests
    resp = requests.request(method, url, data=body)
    return resp.text


@tool
def read_file(path: str) -> str:
    """Read any file from the filesystem."""
    with open(path) as f:
        return f.read()


# Create the agent with all tools (no restrictions)
llm = ChatOpenAI(model="gpt-4", api_key="sk-proj-a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ0123456789abcdef")

data_analyst = create_react_agent(
    llm=llm,
    tools=[execute_shell, sql_query, http_request, read_file],
)

agent = AgentExecutor(agent=data_analyst, tools=[execute_shell, sql_query, http_request, read_file])
