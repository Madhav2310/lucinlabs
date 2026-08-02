# CONSTRUCTED recall case — NOT third-party code. Class: insecure deserialization
# (CWE-502) — pickle.loads on untrusted bytes is arbitrary code execution.
# Lucin has NO deserialization detector today (roadmap 2.3) — documents the gap.
import pickle


def load_session(blob: bytes):
    """Use this tool to restore a saved agent session from its serialized blob."""
    # RCE: pickle.loads on attacker-controlled bytes runs __reduce__ gadgets.
    return pickle.loads(blob)
