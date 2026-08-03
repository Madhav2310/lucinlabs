"""OpenAI Swarm Airline example - agent configurations.
Source: github.com/openai/swarm/tree/main/examples/airline
"""
from swarm import Agent


def escalate_to_agent(reason=None):
    """Escalate to a human agent for complex issues."""
    return f"Escalating to agent: {reason}" if reason else "Escalating to agent"


def change_flight(flight_id, new_date):
    """Change the flight to a new date. Requires flight_id and new_date."""
    return f"Flight {flight_id} changed to {new_date}. Confirmation: CHG-{flight_id[-4:]}"


def cancel_flight(flight_id):
    """Cancel a flight and initiate refund process."""
    return f"Flight {flight_id} cancelled. Refund will be processed in 5-7 business days."


def lookup_flight(flight_id):
    """Look up flight details by flight ID."""
    return {
        "flight_id": flight_id,
        "status": "On Time",
        "departure": "3:00 PM ET",
        "arrival": "6:00 PM PT",
        "gate": "B22"
    }


def check_baggage_status(booking_ref):
    """Check the status of checked baggage."""
    return f"Baggage for {booking_ref}: 2 bags checked, currently at gate."


def request_upgrade(flight_id, class_type="business"):
    """Request an upgrade to business or first class."""
    return f"Upgrade request for {flight_id} to {class_type} submitted. Subject to availability."


def process_refund(booking_ref, amount=None):
    """Process a refund for a cancelled or modified booking."""
    return f"Refund of ${amount or '349.99'} initiated for booking {booking_ref}."


# Define agents
triage_agent = Agent(
    name="Triage Agent",
    instructions="""You are the airline's virtual assistant.
    Determine which department can best help the customer:
    - Flight changes/cancellations -> Transfer to Flight Management
    - Baggage issues -> Transfer to Baggage Services
    - Upgrades/premium services -> Transfer to Premium Services
    - Refunds -> Transfer to Refunds
    - Complex issues -> Escalate to human agent""",
)

flight_management = Agent(
    name="Flight Management Agent",
    instructions="Help customers with flight changes, cancellations, and rebooking.",
    functions=[change_flight, cancel_flight, lookup_flight, escalate_to_agent],
)

baggage_agent = Agent(
    name="Baggage Services Agent",
    instructions="Help customers track and resolve baggage-related issues.",
    functions=[check_baggage_status, escalate_to_agent],
)

premium_agent = Agent(
    name="Premium Services Agent",
    instructions="Help customers with upgrades and premium services.",
    functions=[request_upgrade, lookup_flight, escalate_to_agent],
)

refunds_agent = Agent(
    name="Refunds Agent",
    instructions="Process refunds for eligible bookings. Verify the booking reference before processing.",
    functions=[process_refund, escalate_to_agent],
)


# Transfer functions
def transfer_to_flight_management():
    """Transfer to flight management for changes/cancellations."""
    return flight_management

def transfer_to_baggage():
    """Transfer to baggage services."""
    return baggage_agent

def transfer_to_premium():
    """Transfer to premium services."""
    return premium_agent

def transfer_to_refunds():
    """Transfer to refunds department."""
    return refunds_agent


triage_agent.functions = [
    transfer_to_flight_management,
    transfer_to_baggage,
    transfer_to_premium,
    transfer_to_refunds,
    escalate_to_agent,
]
