"""Test: RAG agent with memory and vector store access.
This pattern is extremely common — agents that query a knowledge base
and can potentially be poisoned through their RAG pipeline.

Tests whether we detect:
1. Memory/RAG poisoning risk (AG-013)
2. Unbounded data retrieval (AG-019)
3. Potential data exfiltration through RAG results
"""
import os

from langchain import hub
from langchain.agents import AgentExecutor, create_react_agent
from langchain.chains import RetrievalQA
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.tools import Tool
from langchain_community.vectorstores import FAISS
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

llm = ChatOpenAI(model="gpt-4", temperature=0)
prompt = hub.pull("hwchase17/react")
embeddings = OpenAIEmbeddings()

# Vector store loaded from disk (could be poisoned)
vectorstore = FAISS.load_local("./company_knowledge_base", embeddings)
retriever = vectorstore.as_retriever(search_kwargs={"k": 20})

# RAG chain — retrieves from vector store and generates answer
qa_chain = RetrievalQA.from_chain_type(
    llm=llm,
    chain_type="stuff",
    retriever=retriever,
    return_source_documents=True,
)


def search_knowledge_base(query: str) -> str:
    """Search the company knowledge base for relevant information."""
    result = qa_chain.invoke({"query": query})
    return result["result"]


def add_to_knowledge_base(content: str, metadata: str = "") -> str:
    """Add new content to the company knowledge base."""
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000)
    chunks = text_splitter.split_text(content)
    vectorstore.add_texts(chunks, metadatas=[{"source": metadata}] * len(chunks))
    vectorstore.save_local("./company_knowledge_base")
    return f"Added {len(chunks)} chunks to knowledge base"


def get_conversation_history(session_id: str) -> str:
    """Retrieve conversation history for a session."""
    import json
    history_file = f"./sessions/{session_id}.json"
    if os.path.exists(history_file):
        with open(history_file) as f:
            return json.dumps(json.load(f), indent=2)
    return "No history found"


def save_conversation(session_id: str, message: str) -> str:
    """Save a message to conversation history."""
    import json
    history_file = f"./sessions/{session_id}.json"
    history = []
    if os.path.exists(history_file):
        with open(history_file) as f:
            history = json.load(f)
    history.append({"role": "assistant", "content": message})
    os.makedirs("./sessions", exist_ok=True)
    with open(history_file, "w") as f:
        json.dump(history, f)
    return "Saved"


# External API tool (potential exfil vector)
def notify_team(channel: str, message: str) -> str:
    """Send a notification to the team via webhook."""
    import json
    import urllib.request
    webhook_url = os.environ.get("SLACK_WEBHOOK", "https://hooks.slack.com/services/T00/B00/xxx")
    data = json.dumps({"channel": channel, "text": message}).encode()
    req = urllib.request.Request(webhook_url, data=data, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req)
    return f"Notification sent to {channel}"


tools = [
    Tool(name="knowledge_search", func=search_knowledge_base,
         description="Search the company knowledge base. Use for internal docs, policies, procedures."),
    Tool(name="knowledge_add", func=add_to_knowledge_base,
         description="Add new content to the knowledge base. Provide the text content to add."),
    Tool(name="history_get", func=get_conversation_history,
         description="Get conversation history for a session ID."),
    Tool(name="history_save", func=save_conversation,
         description="Save a message to conversation history."),
    Tool(name="notify_team", func=notify_team,
         description="Send a notification to a Slack channel."),
]

agent = create_react_agent(llm, tools, prompt)
executor = AgentExecutor(
    agent=agent, tools=tools, verbose=True,
    memory=None,  # Using custom session-based memory above
    max_iterations=15,
    handle_parsing_errors=True,
)
