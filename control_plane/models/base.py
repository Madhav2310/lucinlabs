"""SQLAlchemy declarative base + the tenant-isolation mixin (50_ §2.2, §2.4).

Stack note: SQLAlchemy 2.0 (typed `Mapped[...]` style). SQLAlchemy is an
OPTIONAL/absent dep in the shared venv at scaffold time — see control_plane/README.md
for the install line. These models are written against SQLAlchemy 2.0 so they are
real ORM classes (not pseudocode); they parse import-clean and become live once
`sqlalchemy` is installed.

--- Postgres Row-Level Security (RLS) — the load-bearing isolation control ---

Every tenant-scoped table carries `tenant_id` (NOT NULL) AND is protected by an
RLS policy in the database, NOT only by app-layer `WHERE tenant_id` filters
(50_ §2.2 "RLS is defense-in-depth, not the only defense"). The migration that
creates each such table must also run, roughly:

    ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;
    ALTER TABLE <table> FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON <table>
        USING (tenant_id = current_setting('app.tenant_id')::uuid);

The app sets `app.tenant_id` per request from the authenticated principal
(api/deps.py). A missing/blank `app.tenant_id` makes the cast fail / match no
rows => fail-closed (deny all). A background worker MUST set it identically
(50_ §4.2) or it processes zero rows — same guarantee as the API path.

TODO(stage-1): ship these RLS statements as an Alembic migration + a CI
cross-tenant isolation test (50_ §7 Stage-1 DoD: "tenant A cannot read B's
findings"). That test is a hard-stop gate, not a nicety.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

# NOTE: `sqlalchemy` may not be installed in the scaffold venv. This module is
# written against SQLAlchemy 2.0; see control_plane/README.md for the install.
from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base for all platform ORM models."""


class TimestampMixin:
    """created_at / updated_at on every table (audit + debugging)."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class TenantMixin:
    """Adds the `tenant_id` column that every tenant-scoped table MUST carry.

    `tenant_id == org_id` at MVP (50_ §2.4). Every tenant-scoped ORM model MUST
    inherit this mixin (enforced by tests/test_control_plane.py) so that:
      * the column name/type/FK are identical on every table (the RLS policy
        string above and the app-layer `WHERE tenant_id` filter in
        control_plane/db.py both assume this uniform column), and
      * you cannot add a tenant table that silently omits `tenant_id`.

    The FK to `orgs.id` lives here (via `declared_attr` so each subclass gets its
    own column) — one definition, uniformly enforced, referential-integrity
    included. `orgs` and `users` are NOT tenant-scoped and do NOT inherit this.
    """

    @declared_attr
    def tenant_id(cls) -> Mapped[uuid.UUID]:  # noqa: N805
        return mapped_column(
            PG_UUID(as_uuid=True),
            ForeignKey("orgs.id"),
            nullable=False,
            index=True,
        )


def new_uuid() -> uuid.UUID:
    return uuid.uuid4()


# Convenience column factory for primary keys (uuid, server-generatable).
def pk_column() -> Mapped[uuid.UUID]:
    return mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=new_uuid)


# Short string column helper for readability.
def short_str(length: int = 255, **kw) -> Mapped[str]:
    return mapped_column(String(length), **kw)
