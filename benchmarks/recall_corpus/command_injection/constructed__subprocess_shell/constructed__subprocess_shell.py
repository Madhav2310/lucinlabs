# CONSTRUCTED recall case — NOT third-party code. Class: OS command injection
# (CWE-78) via subprocess shell=True. Reference: agno coding.run_shell (real,
# in this corpus) uses subprocess.run(..., shell=True).
import subprocess


def execute_shell(command: str) -> str:
    """Execute a shell command for the user and return stdout."""
    # VULNERABLE: shell=True with an LLM-controlled command string.
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
