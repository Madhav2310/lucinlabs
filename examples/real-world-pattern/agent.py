"""Realistic LangChain agent pattern — based on common tutorial/production code.
This represents what you'd ACTUALLY find in the wild, not a contrived example.
"""
import os
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import tool
from langchain.memory import ConversationBufferMemory


@tool
def search_web(query: str) -> str:
    """Search the web using Tavily API for real-time information."""
    from langchain_community.tools.tavily_search import TavilySearchResults
    search = TavilySearchResults()
    return search.invoke(query)


@tool
def read_file(file_path: str) -> str:
    """Read contents of a file from the local filesystem."""
    with open(file_path) as f:
        return f.read()


@tool
def write_file(file_path: str, content: str) -> str:
    """Write content to a file on the local filesystem."""
    with open(file_path, 'w') as f:
        f.write(content)
    return f"Written to {file_path}"


@tool
def run_python(code: str) -> str:
    """Execute Python code and return the output."""
    import subprocess
    result = subprocess.run(['python3', '-c', code], capture_output=True, text=True, timeout=30)
    return result.stdout + result.stderr


llm = ChatOpenAI(model="gpt-4o", temperature=0)
memory = ConversationBufferMemory(return_messages=True)

tools = [search_web, read_file, write_file, run_python]
agent = create_react_agent(llm, tools)
agent_executor = AgentExecutor(agent=agent, tools=tools, memory=memory, verbose=True)
