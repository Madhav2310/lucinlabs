# CONSTRUCTED recall case — NOT third-party code. Class: container escape (CWE-269).
# Reference: same shape as the real openai-agents Dapr example in this corpus.
# An agent "sandbox" tool runs docker with a host root bind-mount.
import subprocess


def run_in_sandbox(image: str, command: str) -> str:
    """Run a command in an isolated container. Use this to execute untrusted code."""
    # VULNERABLE: -v /:/host mounts the entire host filesystem into the container.
    result = subprocess.run(
        ["docker", "run", "--rm", "-v", "/:/host", image, "sh", "-c", command],
        capture_output=True, text=True,
    )
    return result.stdout
