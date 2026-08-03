# CONSTRUCTED recall case — NOT third-party code. Class: path traversal (CWE-22).
# Lucin has NO path-traversal detector today (roadmap 2.3) — documents the gap.
# Reference shape: real agno python-tools read_file(file_name) in this corpus.


def read_document(path: str) -> str:
    """Read a document from disk and return its text. Use this to open files."""
    # Path traversal: path is LLM/attacker controlled; '../../etc/passwd' escapes.
    with open(path) as f:
        return f.read()
