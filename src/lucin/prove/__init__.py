"""PROVE layer — adversarial payload generation from static findings.

Blueprint §5.1: "For each static trifecta/injection finding, generate a targeted
attack placed exactly on the reachable path the AIFG identified."

Usage:
    from lucin.prove import generate_payloads
    from lucin.scanner import scan_target

    result = scan_target(Path("my_agent.py"))
    payloads = generate_payloads(result.findings)
    for p in payloads:
        print(p.describe())
"""

from lucin.prove.payload_generator import (
    AdversarialPayload,
    PayloadVariant,
    generate_from_finding,
    generate_payloads,
)

__all__ = [
    "AdversarialPayload",
    "PayloadVariant",
    "generate_payloads",
    "generate_from_finding",
]
