"""Lucin SaaS platform (the hosted product around the OSS engine).

SCAFFOLD — see control_plane/README.md for the "real vs stubbed" honesty section.

This package is the backend/platform described in `plan/50_technical_architecture.md`:
a FastAPI app + Postgres(+RLS)/TimescaleDB data model + GUARD telemetry ingestion,
built ON TOP OF the single `lucin.aifg.AIFG` engine (imported, never forked).

The non-negotiable architectural invariant (§1, §5 of 50_): there is exactly ONE
`lucin.aifg.AIFG` implementation and ONE `IFCLabel` lattice, imported by both
the OSS CLI and this server. This package NEVER redefines them.
"""

__version__ = "0.0.1-scaffold"
