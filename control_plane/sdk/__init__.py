"""Lucin GUARD client SDK.

`guard_client` wraps a tool call, consults the local IFC decision, ENFORCES it
fail-closed (a BLOCK verdict denies the tool before it runs — raising
`GuardBlocked`), and emits a REDACTED telemetry event to the hosted ingestion
endpoint. Enforcement is local/in-process (50_ §3.1) and does not depend on the
network. Redaction happens client-side, BEFORE egress (50_ §3.2, §4.1): only
labels/hashes/stats leave; raw args/returns never do.

Out of the box the decision hook defaults to ALLOW, so nothing is blocked until a
real gate is wired (see guard_client.GuardClient) — the enforcement PATH is real
and tested; the default decision SOURCE is a no-op stub.
"""

from control_plane.sdk.guard_client import GuardBlocked, GuardClient, redact_to_event

__all__ = ["GuardBlocked", "GuardClient", "redact_to_event"]
