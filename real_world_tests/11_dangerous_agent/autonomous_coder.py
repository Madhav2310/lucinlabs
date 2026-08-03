"""An autonomous coding agent similar to OpenHands/SWE-agent patterns.
Based on patterns from All-Hands-AI/OpenHands and SWE-agent.
This represents the most dangerous real-world agent pattern:
full shell + file + network access with minimal guardrails.
"""
import os
import subprocess
from pathlib import Path

import requests
from langchain import hub
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain_openai import ChatOpenAI

# === TOOLS ===

def bash_execute(command: str) -> str:
    """Execute a bash command and return stdout + stderr.
    WARNING: This executes arbitrary commands with the user's full permissions.
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=os.environ.get("WORKSPACE", "/tmp/workspace")
        )
        output = result.stdout
        if result.stderr:
            output += f"\nSTDERR: {result.stderr}"
        if result.returncode != 0:
            output += f"\nExit code: {result.returncode}"
        return output[:10000]  # Truncate very long outputs
    except subprocess.TimeoutExpired:
        return "Command timed out after 120 seconds"
    except Exception as e:
        return f"Error: {str(e)}"


def file_read(path: str) -> str:
    """Read a file from the workspace."""
    try:
        return Path(path).read_text()[:50000]
    except Exception as e:
        return f"Error reading {path}: {e}"


def file_write(path: str, content: str) -> str:
    """Write content to a file in the workspace."""
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return f"Successfully wrote {len(content)} chars to {path}"
    except Exception as e:
        return f"Error writing {path}: {e}"


def file_edit(path: str, old_text: str, new_text: str) -> str:
    """Edit a file by replacing old_text with new_text."""
    try:
        content = Path(path).read_text()
        if old_text not in content:
            return f"Error: old_text not found in {path}"
        new_content = content.replace(old_text, new_text, 1)
        Path(path).write_text(new_content)
        return f"Successfully edited {path}"
    except Exception as e:
        return f"Error editing {path}: {e}"


def web_browse(url: str) -> str:
    """Fetch a URL and return its content."""
    try:
        resp = requests.get(url, timeout=30, headers={
            "User-Agent": "Mozilla/5.0 (autonomous-agent)"
        })
        return resp.text[:20000]
    except Exception as e:
        return f"Error fetching {url}: {e}"


def git_operations(command: str) -> str:
    """Execute git commands in the workspace."""
    return bash_execute(f"cd $WORKSPACE && git {command}")


def run_tests(test_path: str = "") -> str:
    """Run pytest on the workspace. Optionally specify a test file."""
    cmd = f"cd $WORKSPACE && python -m pytest {test_path} -v --tb=short 2>&1"
    return bash_execute(cmd)


def install_package(package: str) -> str:
    """Install a Python package via pip."""
    return bash_execute(f"pip install {package}")


# All tools available to the agent
tools = [
    Tool(name="bash", func=bash_execute,
         description="Execute any bash command. Use for system operations, running scripts, etc."),
    Tool(name="read_file", func=file_read,
         description="Read the contents of a file."),
    Tool(name="write_file", func=file_write,
         description="Write content to a file. Creates parent directories if needed."),
    Tool(name="edit_file", func=file_edit,
         description="Edit a file by replacing specific text. Provide old_text and new_text."),
    Tool(name="browse", func=web_browse,
         description="Fetch a URL and return its content. Use for documentation, APIs, etc."),
    Tool(name="git", func=git_operations,
         description="Execute git commands: status, diff, add, commit, push, log, etc."),
    Tool(name="test", func=run_tests,
         description="Run pytest tests. Optionally specify a test file path."),
    Tool(name="pip_install", func=install_package,
         description="Install a Python package. Use when imports fail."),
]

# Create the agent
llm = ChatOpenAI(model="gpt-4-turbo", temperature=0)
prompt = hub.pull("hwchase17/react")

agent = create_react_agent(llm, tools, prompt)
executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True,
    max_iterations=50,  # Allow many iterations for complex tasks
    handle_parsing_errors=True,
)


def run_task(task_description: str):
    """Run the autonomous coding agent on a task."""
    result = executor.invoke({
        "input": f"""You are an autonomous software engineering agent. Your task:

{task_description}

You have full access to bash, file operations, git, web browsing, and package installation.
Work step by step:
1. Understand the codebase (read files, look at structure)
2. Make necessary changes
3. Test your changes
4. Commit if tests pass
"""
    })
    return result


if __name__ == "__main__":
    import sys
    task = sys.argv[1] if len(sys.argv) > 1 else "Fix the failing tests"
    run_task(task)
