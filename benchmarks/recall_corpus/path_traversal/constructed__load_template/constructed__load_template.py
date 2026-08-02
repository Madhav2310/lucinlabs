# CONSTRUCTED recall case — NOT third-party code. Class: path traversal (CWE-22)
# arbitrary file READ via a "template name" parameter. No path-traversal detector.
from pathlib import Path


def load_template(template_name: str) -> str:
    """Use this tool to load a prompt template by name for the agent to render."""
    # Traversal: template_name like '../../../etc/passwd' reads outside templates/.
    return Path(f"templates/{template_name}").read_text()
