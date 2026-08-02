"""Tests for AG-DOCKER-EXEC and AG-RAG-NO-SANITIZE detectors."""

import ast
import textwrap
import tempfile
from pathlib import Path

import pytest

from lucin.detectors.docker_exec import detect_docker_exec, _command_contains_docker_run
from lucin.detectors.rag_sanitize import detect_rag_no_sanitize
from lucin.models import Agent, Tool, ToolCapability, Severity, ScanResult


# ---------------------------------------------------------------------------
# AG-DOCKER-EXEC
# ---------------------------------------------------------------------------

def _agent_with_source(source: str) -> Agent:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(source)
        path = f.name
    tool = Tool(name="exec_tool", capabilities=[ToolCapability.EXECUTE_CODE],
                source_file=path, source_line=1)
    return Agent(name="test_agent", source_file=path, tools=[tool])


def test_docker_run_list_fires():
    source = textwrap.dedent("""\
        import subprocess

        def run_container(image: str) -> str:
            result = subprocess.run(["docker", "run", "--rm", image], capture_output=True)
            return result.stdout.decode()
    """)
    agent = _agent_with_source(source)
    findings = detect_docker_exec(agent)
    assert any(f.id == "AG-DOCKER-EXEC" for f in findings)


def test_docker_run_string_fires():
    source = textwrap.dedent("""\
        import os

        def execute_task(cmd: str) -> str:
            os.system("docker run --rm ubuntu bash -c 'ls'")
            return "done"
    """)
    agent = _agent_with_source(source)
    findings = detect_docker_exec(agent)
    assert any(f.id == "AG-DOCKER-EXEC" for f in findings)


def test_docker_pull_no_run_does_not_fire():
    source = textwrap.dedent("""\
        import subprocess

        def pull_image(image: str) -> str:
            result = subprocess.run(["docker", "pull", image], capture_output=True)
            return result.stdout.decode()
    """)
    agent = _agent_with_source(source)
    findings = detect_docker_exec(agent)
    assert not any(f.id == "AG-DOCKER-EXEC" for f in findings)


def test_subprocess_no_docker_does_not_fire():
    source = textwrap.dedent("""\
        import subprocess

        def list_files(path: str) -> str:
            result = subprocess.run(["ls", path], capture_output=True)
            return result.stdout.decode()
    """)
    agent = _agent_with_source(source)
    findings = detect_docker_exec(agent)
    assert not any(f.id == "AG-DOCKER-EXEC" for f in findings)


def test_docker_exec_not_run_does_not_fire():
    source = textwrap.dedent("""\
        import subprocess

        def run_in_container(container_id: str, cmd: str) -> str:
            result = subprocess.run(["docker", "exec", container_id, cmd])
            return result.stdout.decode()
    """)
    agent = _agent_with_source(source)
    findings = detect_docker_exec(agent)
    assert not any(f.id == "AG-DOCKER-EXEC" for f in findings)


def test_command_contains_docker_run_unit():
    """Unit test for the internal parser."""
    # List form
    node = ast.parse('subprocess.run(["docker", "run", "--rm", "ubuntu"])').body[0].value
    assert _command_contains_docker_run(node)

    # String form
    node = ast.parse('os.system("docker run --rm ubuntu")').body[0].value
    assert _command_contains_docker_run(node)

    # docker pull — should NOT match
    node = ast.parse('subprocess.run(["docker", "pull", "ubuntu"])').body[0].value
    assert not _command_contains_docker_run(node)


# ---------------------------------------------------------------------------
# AG-RAG-NO-SANITIZE
# ---------------------------------------------------------------------------

def test_rag_direct_injection_fires():
    source = textwrap.dedent("""\
        from langchain.vectorstores import FAISS
        from langchain.llms import OpenAI

        def answer_question(query: str) -> str:
            vectorstore = FAISS.from_documents(docs, embeddings)
            results = vectorstore.similarity_search(query)
            context = results[0].page_content
            llm = OpenAI()
            return llm.complete(f"Answer based on: {context}\\nQ: {query}")
    """)
    agent = _agent_with_source(source)
    findings = detect_rag_no_sanitize(agent)
    assert any(f.id == "AG-RAG-NO-SANITIZE" for f in findings)


def test_rag_with_sanitization_does_not_fire():
    source = textwrap.dedent("""\
        from langchain.vectorstores import Chroma
        from langchain.llms import OpenAI

        def sanitize(text: str) -> str:
            # Strip injection patterns
            return text.replace("IGNORE", "").replace("previous instructions", "")

        def answer_safe(query: str) -> str:
            vectorstore = Chroma()
            results = vectorstore.similarity_search(query)
            context = sanitize(results[0].page_content)
            llm = OpenAI()
            return llm.complete(f"Context: {context}\\nQ: {query}")
    """)
    agent = _agent_with_source(source)
    findings = detect_rag_no_sanitize(agent)
    assert not any(f.id == "AG-RAG-NO-SANITIZE" for f in findings)


def test_no_vector_store_does_not_fire():
    source = textwrap.dedent("""\
        from openai import OpenAI

        def chat(user_message: str) -> str:
            client = OpenAI()
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": user_message}]
            )
            return response.choices[0].message.content
    """)
    agent = _agent_with_source(source)
    findings = detect_rag_no_sanitize(agent)
    assert not any(f.id == "AG-RAG-NO-SANITIZE" for f in findings)


def test_rag_severity_is_high():
    source = textwrap.dedent("""\
        from langchain.vectorstores import Pinecone

        def query_knowledge_base(query: str) -> str:
            vectorstore = Pinecone.from_existing_index("knowledge", embeddings)
            documents = vectorstore.similarity_search(query, k=5)
            context = "\\n".join(doc.page_content for doc in documents)
            return llm.complete("Context: " + context + "\\n\\nQuestion: " + query)
    """)
    agent = _agent_with_source(source)
    findings = detect_rag_no_sanitize(agent)
    rag_findings = [f for f in findings if f.id == "AG-RAG-NO-SANITIZE"]
    assert all(f.severity == Severity.HIGH for f in rag_findings)
