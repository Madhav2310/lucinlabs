# CONSTRUCTED recall case — NOT third-party code. Class: insecure deserialization
# (CWE-502) — joblib.load (pickle under the hood) of a downloaded model artifact.
# Mirrors real ML-supply-chain pickle RCE advisories. No deserialization detector.
import joblib


def load_model(model_path: str):
    """Use this tool to load a serialized model artifact for the agent to use."""
    # RCE: joblib.load == pickle; a poisoned artifact runs code on load.
    return joblib.load(model_path)
