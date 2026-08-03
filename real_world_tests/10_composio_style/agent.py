"""A Composio-style agent with many integrations.
Based on patterns from github.com/ComposioHQ/composio examples.
"""
import os
import subprocess

from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.tools import Tool
from langchain_openai import ChatOpenAI


# Shell execution tool (from Composio's OS tools)
def execute_shell(command: str) -> str:
    """Execute a shell command and return the output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout + result.stderr


# File operations
def read_file(path: str) -> str:
    """Read contents of a file at the given path."""
    with open(path, 'r') as f:
        return f.read()


def write_file(path: str, content: str) -> str:
    """Write content to a file at the given path."""
    with open(path, 'w') as f:
        f.write(content)
    return f"Written {len(content)} bytes to {path}"


# GitHub integration
def create_github_issue(repo: str, title: str, body: str) -> str:
    """Create a GitHub issue in the specified repository."""
    import requests
    token = os.environ.get("GITHUB_TOKEN")
    resp = requests.post(
        f"https://api.github.com/repos/{repo}/issues",
        headers={"Authorization": f"token {token}"},
        json={"title": title, "body": body}
    )
    return f"Issue created: {resp.json().get('html_url', 'error')}"


# Slack integration
def send_slack_message(channel: str, message: str) -> str:
    """Send a message to a Slack channel."""
    import requests
    token = os.environ.get("SLACK_TOKEN")
    requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {token}"},
        json={"channel": channel, "text": message}
    )
    return f"Message sent to {channel}"


# Database query
def query_database(sql: str) -> str:
    """Execute a SQL query against the production database."""
    import psycopg2
    conn = psycopg2.connect(os.environ.get("DATABASE_URL"))
    cur = conn.cursor()
    cur.execute(sql)
    results = cur.fetchall()
    conn.close()
    return str(results)


# HTTP request tool
def http_request(url: str, method: str = "GET", body: str = None) -> str:
    """Make an HTTP request to any URL."""
    import requests
    resp = requests.request(method, url, data=body)
    return resp.text[:5000]


# Define all tools
tools = [
    Tool(name="shell", func=execute_shell,
         description="Execute any shell command. Use for file operations, git, system info, etc."),
    Tool(name="read_file", func=read_file,
         description="Read the contents of any file given its path."),
    Tool(name="write_file", func=write_file,
         description="Write content to any file. Creates the file if it doesn't exist."),
    Tool(name="github_issue", func=create_github_issue,
         description="Create a GitHub issue. Requires repo (owner/name), title, and body."),
    Tool(name="slack_message", func=send_slack_message,
         description="Send a message to a Slack channel."),
    Tool(name="sql_query", func=query_database,
         description="Execute a SQL query against the database. Use for data retrieval."),
    Tool(name="http_request", func=http_request,
         description="Make HTTP requests to any URL. Supports GET, POST, PUT, DELETE."),
]

# Create the agent
llm = ChatOpenAI(model="gpt-4", temperature=0)
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a powerful assistant with access to shell, files, GitHub, Slack, databases, and HTTP. Help the user accomplish their tasks efficiently."),
    MessagesPlaceholder(variable_name="chat_history", optional=True),
    ("human", "{input}"),
    MessagesPlaceholder(variable_name="agent_scratchpad"),
])

agent = create_openai_functions_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)
