# CONSTRUCTED recall case — NOT third-party code. Class: path traversal (CWE-22),
# arbitrary file WRITE. No path-traversal detector — documents the gap.


def write_report(filename: str, content: str) -> str:
    """Write a report file for the user. Use this to save generated documents."""
    # Traversal: filename controls the write target; '../../.bashrc' overwrites.
    with open(filename, "w") as f:
        f.write(content)
    return f"wrote {filename}"
