"""Vulnerable fixture: RAG pipeline injecting vector store content into LLM.
Expected: AG-RAG-NO-SANITIZE fires on answer_question function.
Pattern: every RAG tutorial in the corpus — LangChain similarity_search → LLM.
"""
from langchain.agents import tool
from langchain.embeddings import OpenAIEmbeddings
from langchain.llms import OpenAI
from langchain.vectorstores import FAISS


@tool
def answer_question(query: str) -> str:
    """Answer a question using the company knowledge base.

    Searches for relevant documents and generates an answer.
    """
    embeddings = OpenAIEmbeddings()
    vectorstore = FAISS.load_local("./kb", embeddings)
    # VULNERABLE: no sanitization between vector store and LLM
    documents = vectorstore.similarity_search(query, k=5)
    context = "\n".join(doc.page_content for doc in documents)
    llm = OpenAI()
    return llm.complete(
        f"Answer based on the following context:\n\n{context}\n\nQuestion: {query}"
    )
