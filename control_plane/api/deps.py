"""FastAPI dependencies: auth + tenant-scope + RBAC as ONE chain (50_ §2.4).

THE CRITICAL SECURITY INVARIANT (50_ §2.4): resolving the principal, opening a DB
session with `app.tenant_id` SET (which drives Postgres RLS) + an app-layer tenant
filter, and checking the RBAC role are a SINGLE dependency chain, so a route handler
is UNREACHABLE without all three. Fail-closed BY CONSTRUCTION:

    get_principal  ->  get_db_session  ->  require_auth / require_role
    (401 if no        (SET app.tenant_id;   (RBAC floor; returns the
     principal)        wraps TenantScoped-    tenant-scoped session)
                       Session for the
                       app-layer filter)

Every authenticated router depends on `require_auth` or `require_role(...)`, and BOTH
depend on `get_db_session`, which depends on `get_principal`. There is no path to a
handler that skips the tenant scope — this is verified structurally by
`tests/test_control_plane.py::test_no_handler_bypasses_tenant_scope`, which fails
if any handler injects `get_principal`/`get_db_session` directly instead.

SCAFFOLD STATUS: the JWT/SSO verification and the real async DB session are TODO
(Stage 1). Until then authenticated handlers fail closed — `get_principal` raises
before any query, and `get_db_session` raises rather than yielding an unscoped
session. The dependency SHAPE is final so routers are written against the real
contract, and the app-layer filter itself (control_plane/db.TenantScopedSession) is
real and tested today.
"""

from __future__ import annotations

# fastapi is an absent dep in the scaffold venv — see control_plane/README.md install.
from fastapi import Depends, Header, HTTPException, status

from control_plane.api.schemas import Principal
from control_plane.db import TenantScopedSession
from control_plane.enums import Role


# Role ranking for "at least this role" checks.
_ROLE_RANK = {Role.VIEWER: 0, Role.MEMBER: 1, Role.ADMIN: 2, Role.OWNER: 3}


async def get_principal(
    authorization: str | None = Header(default=None),
) -> Principal:
    """Resolve the authenticated caller from a bearer JWT.

    TODO(stage-1): verify the JWT signature against the IdP JWKS (human auth) OR
    validate a hashed API key (machine auth, 50_ §2.4); extract user_id + org_id
    + role; reject expired/invalid tokens with 401. For now this raises so no
    handler silently runs unauthenticated (fail-closed).
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    # TODO(stage-1): real token verification + principal resolution.
    raise NotImplementedError(
        "JWT/SSO + API-key verification not implemented (scaffold). "
        "See 50_ §2.4 and deps.py TODO."
    )


async def get_db_session(
    principal: Principal = Depends(get_principal),
) -> TenantScopedSession:
    """Yield a tenant-scoped DB session — the ONE place tenant scope is established.

    Two isolation layers are set up here (never one alone, 50_ §2.2):
      1. `SET LOCAL app.tenant_id = tenant_id_of(principal)` (transaction-scoped) so
         Postgres RLS filters every query to the principal's tenant; and
      2. wrapping the session in `TenantScopedSession`, which adds the app-layer
         `WHERE tenant_id` filter (defense-in-depth that holds even if RLS is off).
    A worker path must do the identical SET (50_ §4.2). Depending on `get_principal`
    guarantees the tenant is known before any query runs.

    TODO(stage-1): open the real async SQLAlchemy session and run the SET before
    wrapping it in TenantScopedSession(principal, session). Raising (not yielding an
    unscoped session) keeps authenticated handlers fail-closed until then.
    """
    raise NotImplementedError(
        "DB session + RLS `SET app.tenant_id` not implemented (scaffold). "
        "See 50_ §2.2 base.py RLS contract and control_plane/db.py."
    )


async def require_auth(
    session: TenantScopedSession = Depends(get_db_session),
) -> Principal:
    """Authenticated + tenant-scoped, no role floor (ingest + self endpoints).

    Depends on `get_db_session` so the tenant scope is ALWAYS set before the handler
    runs — a handler must never depend on `get_principal` directly (that would skip
    the tenant scope). Returns the principal for convenience; the scoped session is
    reachable via `session.principal` in handlers that need to query.
    """
    return session.principal


def require_role(minimum: Role):
    """Dependency factory: authenticated + tenant-scoped + at least `minimum` role.

    Depends on `get_db_session` (not `get_principal`) so the RBAC check and the
    tenant scope are the same chain — fail-closed by construction.
    """

    async def _checker(
        session: TenantScopedSession = Depends(get_db_session),
    ) -> Principal:
        principal = session.principal
        if _ROLE_RANK[principal.role] < _ROLE_RANK[minimum]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role >= {minimum.value}",
            )
        return principal

    return _checker
