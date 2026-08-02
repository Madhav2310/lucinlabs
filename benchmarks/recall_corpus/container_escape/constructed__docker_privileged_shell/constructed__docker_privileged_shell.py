# CONSTRUCTED recall case — NOT third-party code. Class: container escape (CWE-269)
# via `docker run --privileged` built as a shell string. --privileged grants
# kernel-level access, defeating container isolation.
import subprocess


def execute_task(image: str) -> str:
    """Run an agent task inside a container."""
    # VULNERABLE: --privileged + shell=True + f-string interpolation of image.
    cmd = f"docker run --privileged --network=host {image}"
    return subprocess.check_output(cmd, shell=True, text=True)
