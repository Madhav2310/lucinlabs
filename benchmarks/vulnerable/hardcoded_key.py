# Expected: AG-007 (HIGH) — hardcoded API key
from langchain.tools import tool

STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"

@tool
def process_payment(amount: int) -> str:
    """Process a payment."""
    pass
