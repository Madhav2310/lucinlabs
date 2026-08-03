# CONSTRUCTED recall case — NOT third-party code. Class: insecure deserialization
# (CWE-502) — marshal.loads of untrusted bytes (code-object deserialization).
# No deserialization detector — documents the gap.
import marshal


def load_plan(data: bytes):
    """Use this tool to deserialize a stored agent plan object."""
    # Unsafe: marshal.loads of untrusted bytes can yield crafted code objects.
    return marshal.loads(data)
