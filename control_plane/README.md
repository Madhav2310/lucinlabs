# Lucin Platform (SaaS control plane) — SCAFFOLD

The hosted product **around** the OSS engine. This directory is the backend
described in [`../plan/50_technical_architecture.md`](../plan/50_technical_architecture.md):
a FastAPI app + Postgres(+RLS)/TimescaleDB data model + GUARD telemetry
ingestion, built **on top of** the single `lucin.aifg.AIFG` engine.

> **This is a first-pass scaffold**, not the finished platform. It is real,
> import-clean code that reflects the architecture doc — coherent structure,
> models, and route stubs with honest `TODO`s where business logic is deferred.
> Read the **"What's real vs stubbed"** section below before trusting anything.

## The one non-negotiable invariant (why this is not just another CRUD app)

There is **exactly one** `lucin.aifg.AIFG` implementation and one `IFCLabel`
lattice, imported by both the OSS CLI and this server (50_ §1, §5). This package
**never redefines** them. `api/reconstruction.py` rebuilds a *runtime* AIFG from
telemetry using the *same* dataclasses the static scanner uses, so
`query_trifecta` runs unchanged on both — a static finding and a runtime
enforcement are the *same object type*. That "one coherent SCAN→GUARD model"
claim is a **code property here**, demonstrated live (see the smoke test below).

## Backend stack (per 50_ §2.1)

| Layer | Choice | Status in scaffold venv |
|---|---|---|
| API framework | FastAPI + Pydantic v2 + Uvicorn | Pydantic + Uvicorn present; **FastAPI not installed** |
| ORM / DB | SQLAlchemy 2.0 → PostgreSQL 16 + RLS | **SQLAlchemy not installed** (code written against it) |
| Telemetry store | TimescaleDB hypertable (Postgres extension) | server-side extension, not a pip dep |
| Job queue | Postgres `SELECT … FOR UPDATE SKIP LOCKED` | not built (Stage 1) |
| Object store | S3-compatible (SARIF blobs, AIFG JSON) | referenced by key, not wired |

`pydantic` (2.12.x) and `uvicorn` are already importable in the shared venv;
`fastapi` and `sqlalchemy` are **not** — this scaffold does **not** force-install
them into the shared venv. To run the API for real:

```bash
pip install -r control_plane/requirements.txt   # fastapi + sqlalchemy (+ see file)
uvicorn control_plane.api.app:app --reload --port 8080
# then: GET http://localhost:8080/healthz   and   /docs (OpenAPI)
```

> **Naming note (why not `platform/`):** this package was originally scaffolded
> as `platform/`, but that name **shadows Python's stdlib `platform` module**
> whenever the repo root is on `sys.path` — which `python -m pytest tests/` from
> the repo root does (it puts cwd on `sys.path[0]`). That shadow broke the engine
> test suite's collection (a test imports `httpx → zstandard`, which calls
> `platform.python_implementation()` at import time). It was renamed to
> `control_plane/` (a non-stdlib name; the 50_ doc calls this the control plane)
> so the mandated `python -m pytest tests/` command stays green. Do not rename it
> back to `platform/` without solving that shadow (e.g. installing it as a proper
> distribution instead of importing by directory-adjacency).

## Directory tree

```
control_plane/
  __init__.py
  enums.py                 # RBAC roles, severities, states (pure; no heavy deps)
  db.py                    # TenantScopedSession — app-layer WHERE tenant_id filter
                           #   (defense-in-depth; tested with RLS off); tenant_id_of
  requirements.txt
  README.md                # this file
  models/                  # SQLAlchemy 2.0 ORM — the data model (50_ §2.2, §3)
    __init__.py            #   exports all tables on one declarative Base
    base.py                #   Base + TenantMixin (declared_attr tenant_id+FK) + RLS contract
    enums.py               #   re-export shim -> control_plane.enums
    tenant.py              #   Org, Team, User, Membership (multitenancy + RBAC)
    repo.py                #   Repo
    scan.py                #   Scan, Finding  (materialized from SARIF results)
    policy.py              #   Policy, Suppression (suppress by fingerprint)
    telemetry.py           #   TelemetryEvent (hypertable), Baseline
    audit.py               #   AuditLog (append-only)
  api/                     # FastAPI app + /v1 routers (50_ §2.3)
    __init__.py
    app.py                 #   create_app(); GET /healthz; mounts routers
    deps.py                #   ONE chain: get_principal -> get_db_session -> require_auth/require_role
    redaction.py           #   redaction backstop (fastapi-free; validates ALL fields; tested)
    schemas.py             #   Pydantic request/response DTOs (the OpenAPI contract)
    reconstruction.py      #   telemetry -> shared-engine AIFG -> query_trifecta
    routers/
      auth.py              #   POST /v1/auth/login  -> JWT
      scans.py             #   POST /v1/ingest/sarif; GET scans / aifg
      findings.py          #   GET findings; suppress / reopen (triage)
      telemetry.py         #   POST /v1/ingest/telemetry (GUARD events)
      orgs.py              #   org / members / users / policies
  sdk/                     # GUARD client SDK (stdlib-only, runs today)
    __init__.py
    guard_client.py        #   wrap tool -> ENFORCE (block fail-closed) -> redact -> emit
```

## Data model (text diagram — 50_ §2.2)

Every **tenant-scoped** table (marked `[T]`) carries `tenant_id` (NOT NULL, FK to
`orgs.id`, `tenant_id == org_id` at MVP) and is protected by a Postgres **RLS**
policy `USING (tenant_id = current_setting('app.tenant_id')::uuid)`. A missing
`app.tenant_id` denies all rows — **fail-closed** (see `models/base.py`).

```
orgs(id, name, plan, data_region)                         ← the tenant root (no tenant_id; it IS the tenant)
  ├─ teams[T](id, org_id, name)
  │    └─ memberships[T](user_id, team_id, role∈{owner,admin,member,viewer})   ← RBAC
  └─ repos[T](id, provider, external_id, default_branch, github_installation_id)
       └─ scans[T](id, repo_id, commit_sha, ref, trigger, engine_version,
       │           status, sarif_object_key, aifg_object_key, summary_counts)  ← blobs in object store
       │    └─ findings[T](id, scan_id, repo_id, rule_id, severity, file_path,
       │                   start_line, end_line, message, witness(jsonb=AIFG proof-path),
       │                   fingerprint, first/last_seen_scan_id, state∈{open,fixed,reappeared})
       └─ suppressions[T](finding_fingerprint, scope∈{finding,rule,path,repo},
                          reason, created_by, expires_at)   ← by FINGERPRINT, survives rescan

users(id, email, sso_subject)                             ← global identity (not tenant-scoped)
policies[T](id, name, spec(jsonb))                        ← governs SCAN gate AND GUARD IFC allow-list (one policy, both layers)

--- GUARD runtime (50_ §3) ---
telemetry_events[T](occurred_at, agent_id, session_id, role, tool_name,        ← TimescaleDB hypertable
                    tool_category, destination, decision, reason, witness,        (append-only, 90d TTL)
                    ifc_args, ifc_result, taint_sources(hashed), features)     ← REDACTED: labels/hashes/stats only
baselines[T](agent_role, tool_name, observation_count, stats(jsonb))           ← online sufficient statistics
audit_log[T](ts, actor, action, target, meta)                                  ← append-only / WORM
```

`findings.witness` is the AIFG proof-path (`TrifectaFinding.witness_summary`);
`scans.aifg_object_key` / a session's reconstructed graph are both
`AIFG.to_dict()` — the **same schema** for static and runtime graphs (50_ §5).

## What's REAL vs STUBBED (honesty section — anti-slop)

**REAL (runs today, verifiable):**
- **Enums, Pydantic schemas, the SDK, the redaction backstop, the tenant-scoped
  session, and AIFG reconstruction import and run** with only `pydantic` + the
  engine (no FastAPI/SQLAlchemy needed). Reproduce:
  ```bash
  venv/bin/python -c "import ast,glob; [ast.parse(open(f).read(),f) for f in glob.glob('control_plane/**/*.py',recursive=True)]; print('all parse')"
  venv/bin/python -m pytest tests/test_control_plane.py -q   # 21 pass, 10 skip (sqlalchemy-gated)
  ```
- **Tenant isolation is fail-closed BY CONSTRUCTION.** The auth/RBAC/tenant-scope
  is ONE dependency chain (`get_principal → get_db_session → require_auth/
  require_role` in `deps.py`); no handler injects `get_principal`/`get_db_session`
  directly, so none is reachable without `app.tenant_id` set (enforced by
  `test_no_handler_bypasses_tenant_scope` + `test_dependency_chain_wires_tenant_scope`).
- **App-layer defense-in-depth is real and tested.** `db.TenantScopedSession` adds
  a `WHERE tenant_id` filter on every read; `test_cross_tenant_isolation` proves it
  blocks cross-tenant reads **with RLS DISABLED** — isolation does not rely on
  Postgres RLS alone. Every tenant-scoped model inherits `TenantMixin` (the single
  `tenant_id`+FK definition); `test_every_tenant_scoped_model_inherits_tenant_mixin`
  FAILS if a tenant table omits it.
- **The coherence stitch is demonstrated live** — redacted telemetry events are
  reconstructed into the *engine's* `AIFG` and `query_trifecta` flags the
  trifecta unchanged. This uses the real `lucin.aifg`, not a copy (see
  `reconstruction.py`).
- **The GUARD SDK ENFORCES fail-closed** (not telemetry-only): on a BLOCK decision
  the wrapped tool never runs and `GuardBlocked` is raised, and the block is
  recorded as telemetry (`test_sdk_blocks_fail_closed_and_does_not_run_tool`).
  Enforcement is local and does not depend on the network. The default decision
  hook is ALLOW, so nothing is blocked until a real gate is wired — the enforcement
  PATH is real; the default decision SOURCE is a no-op stub.
- **Client-side redaction is real and verified**: `sdk.redact_to_event` hashes
  taint sources and emits only entropy/length/count stats — a raw secret passed in
  does **not** appear in the payload (`test_sdk_redaction_keeps_raw_args_off_the_wire`).
- **The data model** is real SQLAlchemy 2.0 (typed `Mapped[...]`), with `tenant_id`
  (+FK to orgs) on every tenant-scoped table via `TenantMixin` and the RLS contract
  in `base.py`. It becomes live the moment `sqlalchemy` is installed.
- **The API contract** (routers + typed DTOs + `GET /healthz`) is real FastAPI
  wiring; handlers that need the DB raise `NotImplementedError` or return empty
  fixtures with explicit `TODO(stage-N)` markers.
- **The redaction backstop** (`api/redaction.py`) validates **all** event fields —
  bounded identifiers, the IFC-label vocabulary, hashed taint ids, numeric-only
  feature stats — rejecting any field that could carry raw content. It is
  FastAPI-free and unit-tested (7 `test_redaction_*` cases).

**STUBBED (explicit TODOs, keyed to the 50_ stages):**
- **Auth + real DB session** (`deps.py`): JWT/SSO verification, API-key validation,
  the async SQLAlchemy session, and the `SET app.tenant_id` that drives RLS — all
  TODO (Stage 1). The dependency SHAPE and the app-layer filter are real and tested;
  what is stubbed is the token verification and the live session. Until then,
  authenticated handlers fail closed (401 / `NotImplementedError`).
- **Persistence**: no scan/finding/telemetry/baseline row is actually written;
  no fingerprint-diff worker, no object-store I/O, no pg job queue (Stage 1/3).
- **Migrations**: the RLS `ENABLE/FORCE ROW LEVEL SECURITY` + policy statements,
  the Timescale `create_hypertable`/retention/compression, and the audit-log
  append-only trigger are documented in the model docstrings but not shipped as
  Alembic migrations yet (Stage 1/3).
- **Baseline online-update + session scoring** (50_ §3.4) and **train-serve
  parity** against `benchmarks/behavioral_eval.py` (the Stage-3 gate) — not built.
- **SARIF 2.1.0 schema validation** on ingest — TODO (Stage 1).

## The launch-gated federated moat (50_ §3.5) — deliberately NOT here

The DP-SecAgg cross-tenant baseline "moat" (Stage 4) is **intentionally absent**.
Per 50_ §3.5 + §7 and the project anti-slop rules (no speculative features), it
must not be built until (a) ≥ N paying tenants populate ≥ k tenants per
(role,tool) bucket and (b) a written DP ε-budget exists. Building it before that
user-pull gate would be speculative-feature slop. It is a *compounding* advantage
(CONTESTED per the plan), not a day-one "first/only" claim.
```
