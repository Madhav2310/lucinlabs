"""Tenant-scoped DB access: the app-layer defense-in-depth filter (50_ §2.2, §2.4).

There are TWO independent isolation layers, and we NEVER rely on either alone:

  1. **Postgres RLS** — the DB rejects cross-tenant rows because every request runs
     `SET LOCAL app.tenant_id = <principal.tenant_id>` and every tenant-scoped table
     has `USING (tenant_id = current_setting('app.tenant_id')::uuid)` (see
     `models/base.py`). This is set in exactly one place: `api/deps.get_db_session`.

  2. **App-layer `WHERE tenant_id = :tenant`** — `TenantScopedSession` below adds the
     tenant predicate to every query it issues, so isolation HOLDS EVEN IF RLS IS
     DISABLED OR MISCONFIGURED (a bad migration, a superuser role that bypasses RLS,
     a replica without `FORCE ROW LEVEL SECURITY`). This is the belt to RLS's braces.

`tests/test_control_plane.py::test_cross_tenant_isolation` proves layer (2) blocks
cross-tenant reads with RLS turned OFF — i.e. the app-layer filter is load-bearing on
its own, not a comment that trusts the database.

This module is import-clean without SQLAlchemy installed (the scaffold venv has no
`sqlalchemy`): the real `select()` path is imported lazily inside `scoped_select`.
"""

from __future__ import annotations

import uuid
from typing import Any, Protocol


def tenant_id_of(principal: Any) -> uuid.UUID:
    """tenant_id == org_id at MVP (50_ §2.4)."""
    return principal.tenant_id


def _row_tenant_id(row: Any) -> Any:
    """The `tenant_id` carried by a fetched row (None if the row has none)."""
    return getattr(row, "tenant_id", None)


class RawBackend(Protocol):
    """The minimal DB surface `TenantScopedSession` sits in front of.

    In production this is backed by the SQLAlchemy session. In tests it is an
    in-memory store that INTENTIONALLY ignores tenant scoping (simulating RLS
    turned off) so the app-layer filter is exercised on its own.
    """

    def fetch_all(self, model: Any) -> list:  # pragma: no cover - protocol
        ...


class TenantScopedSession:
    """Wraps a DB session, pins one tenant, and filters every read by tenant_id.

    The pin comes from the authenticated principal (never from a request field), so
    a caller cannot ask for another tenant's rows. `all()`/`get()` apply the tenant
    predicate in Python over whatever the backend returned — which means that even
    if the backend (RLS) hands back cross-tenant rows, they are dropped here.
    """

    def __init__(self, principal: Any, backend: RawBackend):
        self.principal = principal
        self.tenant_id: uuid.UUID = tenant_id_of(principal)
        self._backend = backend

    def scoped_select(self, model: Any):
        """Return a SQLAlchemy `Select` already filtered to this tenant (real path).

        Imported lazily so this module stays import-clean when SQLAlchemy is absent.
        The `.where(model.tenant_id == ...)` here is the app-layer defense-in-depth;
        RLS is the second, independent layer in the database.
        """
        from sqlalchemy import select  # lazy: sqlalchemy is optional in scaffold venv

        return select(model).where(model.tenant_id == self.tenant_id)

    def all(self, model: Any) -> list:
        """All rows of `model` visible to this tenant (app-layer filtered)."""
        rows = self._backend.fetch_all(model)
        return [r for r in rows if _row_tenant_id(r) == self.tenant_id]

    def get(self, model: Any, obj_id: Any):
        """One row of `model` by id, or None if it is not in this tenant."""
        for r in self.all(model):
            if getattr(r, "id", None) == obj_id:
                return r
        return None
