"""Enterprise Customer Support Agent — realistic production pattern.

This represents what you'd actually find at a mid-size SaaS company:
- A support agent that can look up customer data
- Can create tickets and send emails
- Has access to internal docs
- Integrated with payment processing
- Has memory for conversation continuity

The issues here are SUBTLE — not "execute_shell" obvious.
They're the kind of thing that passes code review but creates
real attack surface in production.
"""

import os
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from langchain.memory import ConversationBufferWindowMemory


# Production credentials loaded from environment (good practice)
# BUT: fallback to hardcoded values for local dev (bad practice, common in reality)
OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "sk-proj-devLocal8a7b6c5d4e3f2g1h0i9j8k7l6m5n4o3p2q1r0s")
STRIPE_KEY = os.environ.get("STRIPE_SECRET_KEY", "sk_live_4eC39HqLyjWDarjtT1zdp7dc")
DB_CONN = os.environ.get("DATABASE_URL", "postgres://support_agent:AgentP@ss2024!@db.company.internal:5432/customers")


@tool
def lookup_customer(email: str) -> str:
    """Look up a customer by their email address. Returns account details
    including name, plan, payment status, and recent activity."""
    import psycopg2
    conn = psycopg2.connect(DB_CONN)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM customers WHERE email = '{email}'")
    return str(cursor.fetchall())


@tool
def get_subscription_details(customer_id: str) -> str:
    """Get subscription and billing details for a customer from Stripe."""
    import stripe
    stripe.api_key = STRIPE_KEY
    return str(stripe.Subscription.list(customer=customer_id))


@tool
def search_knowledge_base(query: str) -> str:
    """Search the internal knowledge base for support articles and documentation."""
    import requests
    resp = requests.get(
        "https://internal-docs.company.internal/api/search",
        params={"q": query},
        headers={"Authorization": f"Bearer {os.environ.get('DOCS_API_KEY', 'doc-key-internal-2024')}"}
    )
    return resp.json().get("results", [])


@tool
def create_ticket(customer_id: str, subject: str, description: str, priority: str = "medium") -> str:
    """Create a support ticket in the ticketing system."""
    import requests
    resp = requests.post(
        "https://tickets.company.internal/api/v2/tickets",
        json={
            "customer_id": customer_id,
            "subject": subject,
            "description": description,
            "priority": priority,
        },
        headers={"Authorization": "Bearer tk-support-agent-2024-production"}
    )
    return f"Ticket created: {resp.json().get('id')}"


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a customer from support@company.com.
    Always include the standard footer with unsubscribe link."""
    import requests
    resp = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        json={
            "from": {"email": "support@company.com"},
            "to": [{"email": to}],
            "subject": subject,
            "content": [{"type": "text/html", "value": body}],
        },
        headers={"Authorization": f"Bearer {os.environ.get('SENDGRID_KEY', 'SG.fallback-key-do-not-use')}"}
    )
    return "Email sent successfully"


@tool
def refund_payment(payment_id: str, amount_cents: int, reason: str) -> str:
    """Process a refund for a customer payment. Requires payment ID and amount in cents.
    Maximum refund amount is $500 without manager approval."""
    import stripe
    stripe.api_key = STRIPE_KEY
    refund = stripe.Refund.create(
        payment_intent=payment_id,
        amount=amount_cents,
        reason=reason,
    )
    return f"Refund processed: {refund.id} for ${amount_cents/100:.2f}"


# Initialize with conversation memory
llm = ChatOpenAI(model="gpt-4o", api_key=OPENAI_KEY)
memory = ConversationBufferWindowMemory(k=20, return_messages=True)

support_agent = create_openai_tools_agent(
    llm=llm,
    tools=[
        lookup_customer,
        get_subscription_details,
        search_knowledge_base,
        create_ticket,
        send_email,
        refund_payment,
    ],
)

agent_executor = AgentExecutor(
    agent=support_agent,
    tools=[lookup_customer, get_subscription_details, search_knowledge_base,
           create_ticket, send_email, refund_payment],
    memory=memory,
    verbose=True,
)
