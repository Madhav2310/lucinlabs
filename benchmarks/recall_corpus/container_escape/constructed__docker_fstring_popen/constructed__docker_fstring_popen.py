# CONSTRUCTED recall case — NOT third-party code. Class: container escape (CWE-269)
# via a dynamic `docker run` command through subprocess.Popen.
import subprocess


def run_command(image: str, args: str) -> str:
    """Use this tool to launch a containerized job for the agent."""
    # VULNERABLE: LLM-controlled image + args interpolated into a docker run command.
    proc = subprocess.Popen(
        f"docker run {image} {args}", shell=True,
        stdout=subprocess.PIPE, text=True,
    )
    out, _ = proc.communicate()
    return out
