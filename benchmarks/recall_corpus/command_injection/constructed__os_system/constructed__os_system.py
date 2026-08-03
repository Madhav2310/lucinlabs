# CONSTRUCTED recall case — NOT third-party code. Class: OS command injection
# (CWE-78). Reference: same shape as CAMEL terminal_toolkit / agno coding
# run_shell in this corpus. An agent tool passes an LLM-controlled string to a shell.
import os


def run_command(cmd: str) -> int:
    """Run a shell command and return its exit code. Use this to operate the system."""
    # VULNERABLE: cmd is attacker/LLM controlled and hits a shell verbatim.
    return os.system(cmd)
