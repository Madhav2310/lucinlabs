"""Adversarial test: Can we bypass AG-007 (secrets detection)?

Real-world developers hide secrets in ways that pattern matching misses.
"""
import base64

from langchain import hub
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4")
prompt = hub.pull("hwchase17/react")

# === BYPASS ATTEMPT 1: Base64 encoded API key ===
_encoded_key = "c2stcHJvai1hN2IyYzlkNGUxZjhnM2g2aTVqMGsxbDJtM240bzVwNnE3cjhzOXQ="
API_KEY = base64.b64decode(_encoded_key).decode()

# === BYPASS ATTEMPT 2: Split across multiple variables ===
_prefix = "ghp_"
_part1 = "a8Bk3mNp"
_part2 = "Qr7sT2uV"
_part3 = "wXyZ1cDe"
_part4 = "FgHiJkLm4n5o"
GITHUB_TOKEN = _prefix + _part1 + _part2 + _part3 + _part4

# === BYPASS ATTEMPT 3: Reversed string ===
_reversed = "WBWQ4GNK7FXJR3YAIKA"  # AKIAY3RJXF7KN2QG4BWB reversed
AWS_KEY = _reversed[::-1]

# === BYPASS ATTEMPT 4: XOR obfuscation ===
_obfuscated = bytes([ord(c) ^ 0x42 for c in "secretpass123"])
DB_PASSWORD = bytes([b ^ 0x42 for b in _obfuscated]).decode()

# === BYPASS ATTEMPT 5: Environment variable fallback with hardcoded default ===
import os

OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "sk-proj-a7b2c9d4e1f8g3h6i5j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6")

# === BYPASS ATTEMPT 6: Loaded from a local file that's committed ===
# In real code, the .env file might be accidentally committed
from pathlib import Path

if Path(".secrets.json").exists():
    import json
    _secrets = json.loads(Path(".secrets.json").read_text())
else:
    _secrets = {"stripe_key": "sk_live_4eC39HqLyjWDarjtT1zdp7dc"}

STRIPE_KEY = _secrets.get("stripe_key", "")

# === Innocent-looking tool using the hidden keys ===
def query_api(endpoint: str) -> str:
    """Query our internal API for data."""
    import urllib.request
    req = urllib.request.Request(
        f"https://api.openai.com/v1/{endpoint}",
        headers={"Authorization": f"Bearer {OPENAI_KEY}"}
    )
    return urllib.request.urlopen(req).read().decode()

api_tool = Tool(
    name="internal_api",
    func=query_api,
    description="Query the internal API. Provide the endpoint path."
)

tools = [api_tool]
agent = create_react_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools, verbose=True)
