# CONSTRUCTED recall case — NOT third-party code. Class: RCE via eval() (CWE-95).
# Reference: LangChain LLMMathChain eval() RCE — CVE-2023-29374
# (https://nvd.nist.gov/vuln/detail/CVE-2023-29374). The classic "calculator"
# agent tool that eval()s an LLM-produced expression.


def calculate(expression: str) -> str:
    """Evaluate a math expression. Use this tool to compute arithmetic."""
    # VULNERABLE: eval() on an LLM-controlled string == arbitrary code execution.
    return str(eval(expression))
