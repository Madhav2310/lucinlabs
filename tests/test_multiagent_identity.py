"""Tests for Agent Identity and Message Authentication."""

import time

from lucin.multiagent.identity import IdentityRegistry, sign_message, verify_message


def test_sign_and_verify():
    registry = IdentityRegistry()
    alice = registry.register("alice", secret_key=b"alice-key-1234567890123456789012")
    bob = registry.register("bob", secret_key=b"bob-key-123456789012345678901234")

    # Alice sends a message to Bob
    msg = sign_message(alice, "Hello Bob", recipient="bob")

    # Verify via standalone func
    assert verify_message(msg, alice, bob) is True

    # Verify via registry
    assert registry.verify(msg) is True

def test_verify_rejects_tampered_message():
    registry = IdentityRegistry()
    alice = registry.register("alice")
    registry.register("bob")   # side effect only: makes "bob" a known recipient

    msg = sign_message(alice, "Send $10 to charity", recipient="bob")
    msg.content = "Send $1000 to attacker"  # Tampering

    assert registry.verify(msg) is False

def test_verify_rejects_replay():
    registry = IdentityRegistry()
    alice = registry.register("alice")
    registry.register("bob")   # side effect only: makes "bob" a known recipient

    msg = sign_message(alice, "Authorize payment", recipient="bob")

    # First time works
    assert registry.verify(msg) is True

    # Second time with same nonce is rejected (replay attack)
    assert registry.verify(msg) is False

def test_verify_rejects_expired():
    registry = IdentityRegistry()
    alice = registry.register("alice")

    msg = sign_message(alice, "Hello")
    msg.timestamp = time.time() - 100  # Expired

    assert registry.verify(msg, max_age_s=60.0) is False
