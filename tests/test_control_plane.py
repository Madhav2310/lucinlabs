"""Control-plane (SaaS scaffold) regression tests — S1/S2/S3 of plan/70.

These guard the three scaffold defects the 2026-07-29 audit flagged:

  S1  tenant isolation must be fail-closed BY CONSTRUCTION (one dependency chain,
      app-layer WHERE tenant_id defense-in-depth, TenantMixin on every tenant table).
  S2  the server redaction backstop must validate ALL event fields, and the GUARD
      SDK must actually enforce a BLOCK (fail-closed), not merely emit telemetry.
  S3  no drift (covered by docstring edits; the model/mixin coverage test here also
      pins that no tenant-scoped table silently omits tenant_id).

Design note: fastapi + sqlalchemy are NOT installed in the scaffold venv. The
load-bearing security logic (the app-layer tenant filter, the redaction backstop,
the SDK block path) lives in fastapi/sqlalchemy-FREE modules so it is exercised for
real here. Structural checks that need the router/deps source use AST (no import),
so they run today too. Tests that genuinely need fastapi/sqlalchemy skip cleanly.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CP = REPO_ROOT / "control_plane"


# ---------------------------------------------------------------------------
# S1 — app-layer tenant isolation (the CRITICAL scaffold flaw)
# ---------------------------------------------------------------------------

class _Row:
    def __init__(self, tenant_id, row_id):
        self.tenant_id = tenant_id
        self.id = row_id


class _Model:
    """Stand-in for an ORM model; the fake backend keys rows on it."""


class _RlsDisabledBackend:
    """Simulates a database with RLS OFF: `fetch_all` returns EVERY row for the
    model, ignoring tenant scoping entirely. If the app-layer filter is the only
    thing standing between tenants, this is exactly the adversarial condition."""

    def __init__(self, rows):
        self._rows = rows

    def fetch_all(self, model):
        return list(self._rows)


class _Principal:
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
        self.role = "viewer"


def test_cross_tenant_isolation():
    """S1 DoD: the app-layer WHERE tenant_id filter blocks cross-tenant reads
    EVEN WITH RLS DISABLED. This proves isolation does not rely on Postgres RLS."""
    from control_plane.db import TenantScopedSession

    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    a1 = _Row(tenant_a, uuid.uuid4())
    a2 = _Row(tenant_a, uuid.uuid4())
    b1 = _Row(tenant_b, uuid.uuid4())
    b2 = _Row(tenant_b, uuid.uuid4())

    # RLS is OFF: the backend hands back ALL four rows regardless of tenant.
    backend = _RlsDisabledBackend([a1, a2, b1, b2])
    session_a = TenantScopedSession(_Principal(tenant_a), backend)

    visible = session_a.all(_Model)
    visible_ids = {r.id for r in visible}

    # Tenant A sees only its own rows...
    assert visible_ids == {a1.id, a2.id}
    # ...and CANNOT read tenant B's rows even by direct id lookup.
    assert session_a.get(_Model, b1.id) is None
    assert session_a.get(_Model, a1.id) is a1

    # Sanity: a tenant-B session is the mirror image (no leakage either way).
    session_b = TenantScopedSession(_Principal(tenant_b), backend)
    assert {r.id for r in session_b.all(_Model)} == {b1.id, b2.id}
    assert session_b.get(_Model, a1.id) is None


def _iter_class_defs(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            yield node


def _tablename_of(classdef):
    for stmt in classdef.body:
        if isinstance(stmt, ast.Assign):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "__tablename__":
                    if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                        return stmt.value.value
    return None


def _base_names(classdef):
    names = set()
    for b in classdef.bases:
        if isinstance(b, ast.Name):
            names.add(b.id)
        elif isinstance(b, ast.Attribute):
            names.add(b.attr)
    return names


# Tables that are intentionally NOT tenant-scoped (50_ §2.4):
#   orgs  — the tenant root (it IS the tenant), users — global identity.
_NON_TENANT_TABLES = {"orgs", "users"}


def test_every_tenant_scoped_model_inherits_tenant_mixin():
    """S1 DoD: a tenant-scoped table that omits `tenant_id` must FAIL a test.

    Static (AST) check so it runs without sqlalchemy: every ORM class with a
    `__tablename__` NOT in the non-tenant allowlist must inherit `TenantMixin`
    (which is the single definition of the tenant_id column + FK)."""
    model_files = sorted((CP / "models").glob("*.py"))
    checked = []
    for f in model_files:
        tree = ast.parse(f.read_text(), str(f))
        for cls in _iter_class_defs(tree):
            table = _tablename_of(cls)
            if table is None or table in _NON_TENANT_TABLES:
                continue
            checked.append(table)
            assert "TenantMixin" in _base_names(cls), (
                f"tenant-scoped table '{table}' ({cls.name}) does not inherit "
                f"TenantMixin — it would silently lack tenant_id / RLS scoping"
            )
    # Guard against the check trivially passing (e.g. globs found nothing).
    for expected in ("teams", "memberships", "repos", "scans", "findings",
                     "policies", "suppressions", "telemetry_events", "baselines",
                     "audit_log"):
        assert expected in checked, f"expected tenant table '{expected}' not scanned"


def test_non_tenant_tables_do_not_carry_tenant_mixin():
    """orgs/users must NOT inherit TenantMixin (orgs IS the tenant; users are global)."""
    tree = ast.parse((CP / "models" / "tenant.py").read_text(), "tenant.py")
    for cls in _iter_class_defs(tree):
        if _tablename_of(cls) in _NON_TENANT_TABLES:
            assert "TenantMixin" not in _base_names(cls), (
                f"{cls.name} is a non-tenant table but inherits TenantMixin"
            )


def _depends_targets_in_function(func_node):
    """Collect every name X appearing as `Depends(X)` or `Depends(X(...))` in the
    argument defaults anywhere under this function (incl. nested closures)."""
    targets = set()
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Depends":
            if not node.args:
                continue
            arg0 = node.args[0]
            if isinstance(arg0, ast.Name):
                targets.add(arg0.id)
            elif isinstance(arg0, ast.Call) and isinstance(arg0.func, ast.Name):
                targets.add(arg0.func.id)
    return targets


def _funcs(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def test_dependency_chain_wires_tenant_scope():
    """S1: require_auth AND require_role must depend (transitively) on get_db_session,
    and get_db_session must depend on get_principal — so the tenant scope is set
    before any handler. Verified structurally from deps.py source (no fastapi needed)."""
    tree = ast.parse((CP / "api" / "deps.py").read_text(), "deps.py")
    by_name = {f.name: f for f in _funcs(tree)}

    assert "get_principal" in _depends_targets_in_function(by_name["get_db_session"]), (
        "get_db_session must depend on get_principal"
    )
    assert "get_db_session" in _depends_targets_in_function(by_name["require_auth"]), (
        "require_auth must depend on get_db_session (so tenant scope is always set)"
    )
    assert "get_db_session" in _depends_targets_in_function(by_name["require_role"]), (
        "require_role must depend on get_db_session (RBAC + tenant scope = one chain)"
    )


def test_no_handler_bypasses_tenant_scope():
    """S1: no route handler may inject get_principal/get_db_session DIRECTLY —
    every authenticated handler must go through require_auth/require_role so the
    tenant scope is guaranteed. (auth.py login/logout are unauthenticated by design.)"""
    router_dir = CP / "api" / "routers"
    offenders = []
    for f in sorted(router_dir.glob("*.py")):
        if f.name in ("__init__.py", "auth.py"):
            continue
        tree = ast.parse(f.read_text(), f.name)
        for func in _funcs(tree):
            targets = _depends_targets_in_function(func)
            bad = targets & {"get_principal", "get_db_session"}
            if bad:
                offenders.append((f.name, func.name, sorted(bad)))
    assert not offenders, (
        f"handlers bypass the tenant-scope chain (must use require_auth/require_role): {offenders}"
    )


@pytest.mark.parametrize("model_name", [
    "Team", "Membership", "Repo", "Scan", "Finding", "Policy",
    "Suppression", "TelemetryEvent", "Baseline", "AuditLog",
])
def test_orm_tenant_id_column_present_when_sqlalchemy_available(model_name):
    """Stronger S1 check when sqlalchemy IS installed: the live mapper actually has
    a `tenant_id` column. Skips in the scaffold venv (sqlalchemy absent)."""
    pytest.importorskip("sqlalchemy")
    import control_plane.models as m

    model = getattr(m, model_name)
    assert "tenant_id" in model.__table__.columns, (
        f"{model_name}.__table__ has no tenant_id column"
    )


# ---------------------------------------------------------------------------
# S2 — redaction backstop validates ALL fields
# ---------------------------------------------------------------------------

def _clean_event(**overrides):
    from control_plane.api.schemas import TelemetryEventIn

    base = dict(
        agent_id="agent-1",
        session_id="sess-1",
        tool_name="send_email",
        role="assistant",
        reason="egress blocked",
        witness=["read_db →_data send_email"],
        taint_sources=["h:0123456789abcdef"],
        features={"param_entropy": 3.2, "param_total_length": 42, "arg_count": 2},
    )
    base.update(overrides)
    return TelemetryEventIn(**base)


def test_redaction_accepts_a_properly_redacted_event():
    from control_plane.api.redaction import redaction_violation

    assert redaction_violation(_clean_event()) is None


@pytest.mark.parametrize("field,value,frag", [
    ("tool_name", "x" * 300, "tool_name"),
    ("role", "x" * 300, "role"),
    ("agent_id", "x" * 300, "agent_id"),
    ("session_id", "x" * 300, "session_id"),
    ("trace_id", "x" * 300, "trace_id"),
    ("span_id", "x" * 300, "span_id"),
    ("tool_category", "x" * 300, "tool_category"),
    ("destination", "s3://leaked/raw/arg", "destination"),
    ("reason", "x" * 600, "reason"),
])
def test_redaction_rejects_oversized_or_nonlabel_fields(field, value, frag):
    """S2: fields the OLD backstop did NOT check (tool_name/role/destination/...)
    are now validated. A raw value in any of them is rejected."""
    from control_plane.api.redaction import redaction_violation

    why = redaction_violation(_clean_event(**{field: value}))
    assert why is not None and frag in why, f"expected {field} rejection, got {why!r}"


def test_redaction_rejects_bad_ifc_labels():
    """S2: ifc_args/ifc_result must be lattice labels, not smuggled raw content."""
    from control_plane.api.redaction import redaction_violation
    from control_plane.api.schemas import IFCLabelWire

    bad_int = _clean_event(ifc_result=IFCLabelWire(integrity="sk-live-RAW-SECRET"))
    assert "ifc_result.integrity" in (redaction_violation(bad_int) or "")

    bad_conf = _clean_event(ifc_args=IFCLabelWire(confidentiality="the user's SSN is ..."))
    assert "ifc_args.confidentiality" in (redaction_violation(bad_conf) or "")


def test_redaction_rejects_nonnumeric_features():
    """S2: `features` must be numeric stats only — a string value is raw content."""
    from control_plane.api.redaction import redaction_violation

    leaked = _clean_event(features={"first_arg": "user@example.com password=hunter2"})
    why = redaction_violation(leaked)
    assert why is not None and "numeric" in why


def test_redaction_rejects_unhashed_taint_source():
    from control_plane.api.redaction import redaction_violation

    leaked = _clean_event(taint_sources=["sk-live-" + "A" * 200])
    assert "hash" in (redaction_violation(leaked) or "")


# ---------------------------------------------------------------------------
# S2 — GUARD SDK enforces BLOCK fail-closed (not telemetry-only)
# ---------------------------------------------------------------------------

def test_sdk_blocks_fail_closed_and_does_not_run_tool():
    """S2: on a BLOCK decision the wrapped tool NEVER runs and GuardBlocked raises.
    This is the difference between a GUARD SDK and a telemetry-only emitter."""
    from control_plane.sdk import GuardBlocked, GuardClient

    ran = {"count": 0}
    emitted = []

    def deny_decide(tool_name, args, kwargs):
        return {
            "decision": "block",
            "reason": "untrusted→egress",
            "witness": ["web_fetch →_control send_email"],
            "ifc_args": {"integrity": "untrusted", "confidentiality": "public"},
            "ifc_result": {"integrity": "untrusted", "confidentiality": "secret"},
            "taint_sources": [],
            "tool_category": "network",
            "destination": "external",
        }

    client = GuardClient("https://api.example", "key", decide=deny_decide)
    client._emit = lambda events: emitted.append(events)  # capture, no network

    @client.guard("send_email")
    def send_email(to):
        ran["count"] += 1
        return "sent"

    with pytest.raises(GuardBlocked) as exc:
        send_email("attacker@evil.com")

    assert ran["count"] == 0, "BLOCK must deny BEFORE the tool body runs (fail-closed)"
    assert exc.value.tool_name == "send_email"
    assert emitted, "the block should still be recorded as telemetry"
    assert emitted[0][0]["decision"] == "block"


def test_sdk_allows_when_decision_permits():
    """S2 counterpart: an ALLOW decision runs the tool and emits telemetry."""
    from control_plane.sdk import GuardClient

    emitted = []
    client = GuardClient("https://api.example", "key")  # default decide = ALLOW
    client._emit = lambda events: emitted.append(events)

    @client.guard("read_file")
    def read_file(path):
        return f"contents:{path}"

    assert read_file("/tmp/x") == "contents:/tmp/x"
    assert emitted and emitted[0][0]["decision"] == "allow"


def test_sdk_redaction_keeps_raw_args_off_the_wire():
    """The SDK's redaction must never place a raw secret in the emitted event."""
    from control_plane.sdk import GuardClient

    emitted = []
    client = GuardClient("https://api.example", "key")
    client._emit = lambda events: emitted.append(events)

    @client.guard("db_query")
    def db_query(secret):
        return "ok"

    db_query("sk-REAL-SECRET-VALUE")
    payload = str(emitted[0][0])
    assert "sk-REAL-SECRET-VALUE" not in payload, "raw arg leaked into telemetry event"


# ---------------------------------------------------------------------------
# S3 — server-side AIFG reconstruction: the witness-only-source trifecta miss
# ---------------------------------------------------------------------------

def _telemetry_event(**overrides):
    from control_plane.api.schemas import IFCLabelWire, TelemetryEventIn

    base = dict(agent_id="agent-1", session_id="sess-1", tool_name="",
                ifc_result=IFCLabelWire(), witness=[])
    base.update(overrides)
    if "ifc_result" in overrides and isinstance(overrides["ifc_result"], dict):
        base["ifc_result"] = IFCLabelWire(**overrides["ifc_result"])
    return TelemetryEventIn(**base)


def test_reconstruction_catches_witness_only_untrusted_source():
    """S3: a trifecta whose untrusted-control SOURCE appears ONLY inside another
    tool's witness (no event of its own) must still be flagged. Before the fix the
    witness-only node reconstructed as TRUSTED/PUBLIC and query_trifecta missed it.

    Runs for real (lucin engine + pydantic are present) — not a mock."""
    from control_plane.api.reconstruction import (
        query_runtime_trifecta,
        reconstruct_session_aifg,
    )

    events = [
        # egress sink emitted its own event; its witnesses NAME the sources.
        _telemetry_event(
            tool_name="send_email", destination="external",
            ifc_result={"integrity": "untrusted", "confidentiality": "public"},
            witness=["read_db →_data send_email", "web_fetch →_control send_email"],
        ),
        # a secret data source we DID see an event for...
        _telemetry_event(
            tool_name="read_db",
            ifc_result={"integrity": "trusted", "confidentiality": "secret"},
        ),
        # ...but 'web_fetch' (the untrusted-control origin) is WITNESS-ONLY.
    ]
    g = reconstruct_session_aifg("agent-1", events)
    findings = query_runtime_trifecta(g)

    assert len(findings) == 1, "witness-only untrusted source must not be missed"
    # The witness must name the REAL origin (web_fetch), never the LLM mediator (C2).
    assert findings[0].control_source == "web_fetch"
    assert g.nodes["web_fetch"].label.is_untrusted()
    assert g.nodes["web_fetch"].is_untrusted_input is True


def test_reconstruction_does_not_overfire_without_untrusted_source():
    """S3 counterpart: a read→egress flow with NO untrusted-control source (only a
    data witness) must NOT fabricate a trifecta — the fix stays sound, not greedy."""
    from control_plane.api.reconstruction import (
        query_runtime_trifecta,
        reconstruct_session_aifg,
    )

    events = [
        _telemetry_event(
            tool_name="send_email", destination="external",
            ifc_result={"integrity": "trusted", "confidentiality": "public"},
            witness=["read_db →_data send_email"],  # data only, no control source
        ),
        _telemetry_event(
            tool_name="read_db",
            ifc_result={"integrity": "trusted", "confidentiality": "secret"},
        ),
    ]
    g = reconstruct_session_aifg("agent-1", events)
    assert query_runtime_trifecta(g) == []
