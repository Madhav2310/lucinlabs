"""Lucin Red Team Module — Active security testing for AI agents.

Unlike the static scanner which reads configs, the red team module
ACTUALLY TESTS your agents by:
1. Sending prompt injection payloads
2. Attempting data exfiltration via tool calls
3. Testing privilege escalation paths
4. Checking if guardrails hold under adversarial pressure

This is the difference between "your config looks risky" and
"I just proved an attacker can steal your data in 3 steps."
"""
