"""Agent-to-agent identity binding and message authentication.

Blueprint §6.4: "Authenticate agent↔agent messages; detect spoofed agents
in discovery."

Problem: in multi-agent systems (AutoGen, CrewAI, OpenAI Swarm), when Agent A
delegates to Agent B, there is typically NO verification that:
1. The message actually came from Agent A (not a prompt-injected impersonator)
2. Agent B is who A thinks it is (not a malicious agent injected into discovery)

This module implements HMAC-based message authentication for agent-to-agent
communication. It is NOT a replacement for network security (TLS, mutual auth)
— it is a *behavioral* layer on top of the existing message bus.

Usage:
    registry = IdentityRegistry()
    alice = registry.register("alice", secret_key=b"alice-key-32bytes-xxxxxxxxxxxxxxx")
    bob   = registry.register("bob",   secret_key=b"bob-key-32bytes-xxxxxxxxxxxxxxxxx")

    # Agent A sends a message
    msg = sign_message(alice, "Hello Bob, please process order #123", recipient="bob")

    # Agent B verifies before acting
    ok = verify_message(msg, alice, bob)
    if ok:
        process_order(123)
    else:
        raise SpoofedAgentError(msg)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any


class SpoofedAgentError(RuntimeError):
    """Raised when a message fails authentication — possible spoofed agent."""
    pass


@dataclass
class AgentIdentity:
    """Registered identity for one agent.

    secret_key is kept in memory only — never serialized to disk.
    In production this would be bound to a hardware key or vault secret.
    """
    agent_id:    str
    secret_key:  bytes          # shared secret for HMAC signing
    role:        str = ""       # role name (e.g. "customer-support")
    capabilities: list[str] = field(default_factory=list)  # allowed tool names

    def public_id(self) -> dict:
        """Safe-to-share identity — no secret key."""
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "capabilities": self.capabilities,
        }


@dataclass
class SignedMessage:
    """An agent-to-agent message with HMAC signature.

    Fields:
        sender_id:    agent_id of the sender
        recipient_id: agent_id of the intended recipient
        content:      message payload (any JSON-serializable value)
        timestamp:    Unix time of signing (replay attack detection)
        nonce:        Random bytes (replay attack detection)
        signature:    HMAC-SHA256 of canonical message body
    """
    sender_id:    str
    recipient_id: str
    content:      Any
    timestamp:    float
    nonce:        str
    signature:    str

    def canonical_body(self) -> bytes:
        """Canonical serialization for HMAC verification — deterministic."""
        body = {
            "sender_id":    self.sender_id,
            "recipient_id": self.recipient_id,
            "content":      self.content,
            "timestamp":    self.timestamp,
            "nonce":        self.nonce,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign_message(sender: AgentIdentity, content: Any,
                 recipient: str = "") -> SignedMessage:
    """Create a signed message from sender to recipient."""
    nonce = os.urandom(16).hex()
    now = time.time()

    msg = SignedMessage(
        sender_id=sender.agent_id,
        recipient_id=recipient,
        content=content,
        timestamp=now,
        nonce=nonce,
        signature="",
    )
    sig = hmac.new(sender.secret_key, msg.canonical_body(), hashlib.sha256).hexdigest()
    msg.signature = sig
    return msg


def verify_message(msg: SignedMessage,
                   sender: AgentIdentity,
                   recipient: AgentIdentity | None = None,
                   max_age_s: float = 60.0) -> bool:
    """Verify a signed message.

    Checks:
      1. HMAC signature is valid (message authenticity)
      2. Message is not expired (replay protection)
      3. Recipient matches (if provided)

    Returns True if all checks pass; False otherwise.
    """
    # Verify recipient
    if recipient is not None and msg.recipient_id != recipient.agent_id:
        return False

    # Verify timestamp (replay protection)
    age = time.time() - msg.timestamp
    if age > max_age_s or age < -5:  # allow 5s clock skew
        return False

    # Verify HMAC
    expected = hmac.new(
        sender.secret_key, msg.canonical_body(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, msg.signature)


class IdentityRegistry:
    """Central registry of agent identities for a multi-agent system.

    In production this would be backed by a vault or KMS. For GUARD
    integration, this is the source of truth for which agents are
    legitimate and what capabilities they have.
    """

    def __init__(self):
        self._agents: dict[str, AgentIdentity] = {}
        # Replay protection: remember every (sender_id, nonce) pair we have
        # accepted, with the time it was consumed. A captured, still-fresh
        # message replayed inside the max_age window is rejected because its
        # nonce is already spent. Entries older than the window are pruned on
        # each verify (they can no longer pass the freshness check anyway), so
        # this stays bounded by the number of messages seen within one window.
        self._consumed_nonces: dict[tuple[str, str], float] = {}

    def _prune_consumed(self, now: float, max_age_s: float) -> None:
        """Drop spent nonces older than the freshness window."""
        cutoff = now - max_age_s
        stale = [k for k, t in self._consumed_nonces.items() if t < cutoff]
        for k in stale:
            del self._consumed_nonces[k]

    def register(self, agent_id: str,
                 secret_key: bytes | None = None,
                 role: str = "",
                 capabilities: list[str] | None = None) -> AgentIdentity:
        """Register a new agent. Auto-generates a secret key if not provided."""
        key = secret_key or os.urandom(32)
        identity = AgentIdentity(
            agent_id=agent_id,
            secret_key=key,
            role=role,
            capabilities=capabilities or [],
        )
        self._agents[agent_id] = identity
        return identity

    def get(self, agent_id: str) -> AgentIdentity | None:
        return self._agents.get(agent_id)

    def verify(self, msg: SignedMessage, max_age_s: float = 60.0) -> bool:
        """Verify a signed message against the registry.

        Enforces single-use nonces: a message that is otherwise valid but whose
        (sender_id, nonce) has already been accepted within the freshness window
        is rejected as a replay. Returns False (equivalent to spoofed) if the
        sender is not registered.
        """
        sender = self._agents.get(msg.sender_id)
        if sender is None:
            return False
        recipient = self._agents.get(msg.recipient_id) if msg.recipient_id else None
        if not verify_message(msg, sender, recipient, max_age_s=max_age_s):
            return False

        # Signature + freshness passed. Enforce replay protection: the nonce may
        # only be spent once inside the window. Prune expired nonces first so the
        # cache stays bounded.
        now = time.time()
        self._prune_consumed(now, max_age_s)
        key = (msg.sender_id, msg.nonce)
        if key in self._consumed_nonces:
            return False  # replay: this nonce was already accepted
        self._consumed_nonces[key] = now
        return True

    def registered_agents(self) -> list[str]:
        return list(self._agents.keys())
