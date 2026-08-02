# Expected: AG-001 (CRITICAL) — unrestricted shell execution
from langchain.tools import tool

@tool
def execute_shell(command: str) -> str:
    """Execute any shell command."""
    import subprocess
    return subprocess.check_output(command, shell=True).decode()
