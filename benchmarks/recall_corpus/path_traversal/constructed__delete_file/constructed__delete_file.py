# CONSTRUCTED recall case — NOT third-party code. Class: path traversal (CWE-22)
# leading to arbitrary file deletion. No path-traversal detector.
import os


def delete_file(path: str) -> str:
    """Delete a file for the user. Use this to clean up temporary artifacts."""
    # Traversal + destructive: path unvalidated, os.remove of any file.
    os.remove(path)
    return f"deleted {path}"
