# CONSTRUCTED recall case — NOT third-party code. Class: insecure deserialization
# (CWE-502) — base64-wrapped pickle from an agent message. No deser detector.
import base64
import pickle


def load_tool_result(encoded: str):
    """Decode and load a tool result that was passed between agents."""
    # RCE: decode then unpickle attacker-controlled bytes.
    raw = base64.b64decode(encoded)
    return pickle.loads(raw)
