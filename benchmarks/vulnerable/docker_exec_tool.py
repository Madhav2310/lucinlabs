"""Vulnerable fixture: docker run in agent tool body.
Expected: AG-DOCKER-EXEC fires on run_code function.
Pattern: OpenAI Agents Dapr example — subprocess with variable docker args.
"""
import subprocess

from langchain.agents import tool


@tool
def run_code(code: str, image: str = "python:3.11-slim") -> str:
    """Run Python code in a Docker container for safety.

    Executes arbitrary Python code in an isolated container.
    """
    # VULNERABLE: agent-controlled image and code — container escape possible
    result = subprocess.run(
        ["docker", "run", "--rm", image, "python", "-c", code],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout + result.stderr
