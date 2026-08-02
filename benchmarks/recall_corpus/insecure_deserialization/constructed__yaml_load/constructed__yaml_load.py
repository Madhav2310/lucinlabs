# CONSTRUCTED recall case — NOT third-party code. Class: insecure deserialization
# (CWE-502) via yaml.load without SafeLoader (arbitrary Python object construction).
# No deserialization detector — documents the gap.
import yaml


def load_config(config_text: str) -> dict:
    """Use this tool to parse a YAML configuration provided by the user."""
    # RCE: yaml.load (full loader) executes !!python/object tags in input.
    return yaml.load(config_text, Loader=yaml.Loader)
