"""
Real-world-style agent combining:
- RAG pipeline without sanitization (indirect prompt injection surface)
- SQL query tool with direct parameter injection
- Docker execution for "sandboxed" code running
- No HITL, no telemetry

This is the pattern you'd see in a "data assistant" agent built by an
ML engineer who understands LLMs but not agent security.
"""

import os
import subprocess
from langchain.vectorstores import Chroma
from langchain.embeddings import OpenAIEmbeddings
from langchain.llms import OpenAI
from langchain.agents import initialize_agent, AgentType, Tool
from langchain.tools import BaseTool
import sqlite3


# --- RAG-based context retrieval (no sanitization) ---

def retrieve_context(query: str) -> str:
    """Search the company knowledge base for relevant documents."""
    embeddings = OpenAIEmbeddings()
    vectorstore = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)
    documents = vectorstore.similarity_search(query, k=5)
    context = "\n\n".join(doc.page_content for doc in documents)
    llm = OpenAI()
    # VULNERABILITY: context from vector store injected directly into LLM prompt
    return llm.complete(f"Based on the following context, answer the question:\n\n{context}\n\nQuestion: {query}")


# --- SQL query tool (injection vulnerability) ---

def query_database(sql_query: str) -> str:
    """Run a read-only SQL query against the analytics database.

    Use this to answer questions about sales, users, and metrics.
    """
    conn = sqlite3.connect("analytics.db")
    cur = conn.cursor()
    # VULNERABILITY: raw parameter to cursor.execute — SQL injection
    cur.execute(sql_query)
    rows = cur.fetchall()
    conn.close()
    return str(rows[:100])


# --- Docker execution for "sandboxed" analysis ---

def run_analysis(script: str, image: str = "python:3.11-slim") -> str:
    """Run a Python analysis script in a Docker container for safety.

    Executes code in an isolated container environment.
    """
    # VULNERABILITY: agent-controlled script and image — container escape possible
    result = subprocess.run(
        ["docker", "run", "--rm", "-v", "/tmp/scripts:/scripts", image,
         "python", "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout + result.stderr


tools = [
    Tool(
        name="retrieve_context",
        func=retrieve_context,
        description="Search the company knowledge base for information",
    ),
    Tool(
        name="query_database",
        func=query_database,
        description="Run SQL queries against the analytics database",
    ),
    Tool(
        name="run_analysis",
        func=run_analysis,
        description="Execute Python analysis code in a Docker container",
    ),
]

llm = OpenAI(
    openai_api_key=os.getenv("OPENAI_API_KEY", "sk-placeholder-dev-key"),
    temperature=0
)

agent = initialize_agent(
    tools=tools,
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    verbose=True,
)
