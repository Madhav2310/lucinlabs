"""MATURITY: L2 (scaffolded + unit-tested on author input; NOT validated against a real framework/store).

Framework / store adapters for the multi-agent security layer.

These adapters bridge Lucin's multi-agent primitives (AgentGraph,
MemoryIntegrityMonitor, IdentityRegistry) to the concrete shapes produced by
popular agent frameworks and vector stores — WITHOUT taking a hard dependency
on those packages. crewai, chromadb, etc. are duck-typed: nothing here imports
them, so this module imports cleanly in any environment.

Provided adapters:
  - crew_to_graph(crew)      : CrewAI-style crew  -> AgentGraph
  - ChromaIntegrityAdapter   : Chroma-like collection -> MemoryIntegrityMonitor
  - A2AGuard                 : IdentityRegistry-backed authenticated message bus
"""

from __future__ import annotations

from typing import Any

from lucin.multiagent.cascade import AgentGraph
from lucin.multiagent.identity import (
    IdentityRegistry,
    SignedMessage,
    sign_message,
)
from lucin.multiagent.memory_integrity import (
    IntegrityReport,
    MemoryIntegrityMonitor,
)

# ---------------------------------------------------------------------------
# CrewAI adapter
# ---------------------------------------------------------------------------

def crew_to_graph(crew: Any) -> AgentGraph:
    """Build an :class:`AgentGraph` from a CrewAI-style crew.

    crewai is NOT a dependency — this function duck-types the crew. It accepts
    EITHER:

    1. A **dict** describing the crew, of the shape::

           {
               "agents": [
                   {
                       "role":            "triage",          # or "id"/"name"
                       "tools":           ["search", "email_sender"],
                       "allow_delegation": True,             # optional
                       "delegates_to":    ["sales", "refunds"],  # optional explicit
                   },
                   ...
               ],
               "tasks": [                                    # optional
                   {"agent": "triage", "context": ["sales"]},
                   ...
               ],
           }

    2. An **object** exposing ``.agents`` (and optionally ``.tasks``), where each
       agent object exposes ``.role`` (or ``.id``/``.name``), ``.tools``
       (each tool having a ``.name`` or being a str), and optionally
       ``.allow_delegation`` / ``.delegates_to``. Each task object exposes
       ``.agent`` and optionally ``.context`` (a list of upstream tasks/agents).

    Delegation edges are inferred from, in priority order:
      * an explicit ``delegates_to`` list on the agent, else
      * task ``context`` links (task's agent delegates to the agents that
        produce its context tasks), else
      * if ``allow_delegation`` is truthy, the agent is linked to every other
        agent (CrewAI's default hierarchical fan-out).

    Tool names drive Lucin's high-privilege detection, so we normalize
    each tool to its string name.

    Returns a populated :class:`AgentGraph`. Trust level defaults to
    ``"untrusted"`` (the graph's own default) since frameworks carry no trust
    metadata.
    """
    agents_raw, tasks_raw = _extract_agents_tasks(crew)

    # Normalize agents into {agent_id: {"role","tools","allow_delegation","delegates_to"}}
    parsed: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for a in agents_raw:
        agent_id = _agent_id(a)
        parsed[agent_id] = {
            "role": _get(a, "role", default=agent_id) or agent_id,
            "tools": _tool_names(_get(a, "tools", default=[]) or []),
            "allow_delegation": bool(_get(a, "allow_delegation", default=False)),
            "delegates_to": _id_list(_get(a, "delegates_to", default=[]) or []),
        }
        order.append(agent_id)

    # Infer delegation edges from tasks' context, when explicit edges absent.
    task_edges: dict[str, set[str]] = {aid: set() for aid in parsed}
    for t in tasks_raw:
        owner = _id_of(_get(t, "agent", default=None))
        if owner is None or owner not in parsed:
            continue
        for ctx in _id_list(_get(t, "context", default=[]) or []):
            # context may reference a task or an agent; resolve to an agent id
            ctx_agent = _resolve_ctx_to_agent(ctx, tasks_raw, parsed)
            if ctx_agent and ctx_agent != owner and ctx_agent in parsed:
                # the context PRODUCES input for `owner`; owner delegates upward
                task_edges[owner].add(ctx_agent)

    graph = AgentGraph()
    for agent_id in order:
        info = parsed[agent_id]
        delegates = list(info["delegates_to"])
        if not delegates:
            delegates = sorted(task_edges.get(agent_id, set()))
        if not delegates and info["allow_delegation"]:
            delegates = [other for other in order if other != agent_id]
        graph.add_agent(
            agent_id,
            role=str(info["role"]),
            tools=info["tools"],
            delegates_to=delegates,
        )
    return graph


def _extract_agents_tasks(crew: Any) -> tuple[list[Any], list[Any]]:
    if isinstance(crew, dict):
        return list(crew.get("agents", []) or []), list(crew.get("tasks", []) or [])
    agents = list(getattr(crew, "agents", []) or [])
    tasks = list(getattr(crew, "tasks", []) or [])
    return agents, tasks


def _get(obj: Any, *keys: str, default: Any = None) -> Any:
    """Get an attribute/key by any of `keys` from a dict or object."""
    for key in keys:
        if isinstance(obj, dict):
            if key in obj:
                return obj[key]
        elif hasattr(obj, key):
            return getattr(obj, key)
    return default


def _agent_id(agent: Any) -> str:
    val = _get(agent, "id", "name", "role", default=None)
    return str(val) if val is not None else f"agent_{id(agent)}"


def _id_of(agent: Any) -> str | None:
    """Resolve a referenced agent (dict/obj/str) to its id."""
    if agent is None:
        return None
    if isinstance(agent, str):
        return agent
    return _agent_id(agent)


def _id_list(values: Any) -> list[str]:
    if isinstance(values, (str, bytes)):
        return [values if isinstance(values, str) else values.decode()]
    # Real frameworks use a truthy "unspecified" sentinel for absent list
    # fields (e.g. crewai's Task.context defaults to a `_NotSpecified` object,
    # which is neither None nor a list, so `x or []` does NOT normalize it).
    # Anything that is not an actual collection carries no ids.
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    out: list[str] = []
    for v in values:
        rid = _id_of(v)
        if rid is not None:
            out.append(rid)
    return out


def _tool_names(tools: Any) -> list[str]:
    """Normalize tools (str, dict, or object with .name) to a list of names."""
    if isinstance(tools, (str, bytes)):
        tools = [tools]
    names: list[str] = []
    for t in tools:
        if isinstance(t, str):
            names.append(t)
        elif isinstance(t, dict):
            names.append(str(t.get("name", t.get("id", "tool"))))
        else:
            names.append(str(getattr(t, "name", getattr(t, "__name__", repr(t)))))
    return names


def _resolve_ctx_to_agent(ctx_ref: str, tasks_raw: list[Any],
                          parsed: dict[str, dict]) -> str | None:
    """A task's context references upstream tasks (or agents). Map the ref to
    the agent that owns it, so delegation edges point agent->agent."""
    if ctx_ref in parsed:
        return ctx_ref
    for t in tasks_raw:
        tid = _get(t, "id", "name", default=None)
        if tid is not None and str(tid) == ctx_ref:
            return _id_of(_get(t, "agent", default=None))
    return None


# ---------------------------------------------------------------------------
# Chroma vector-store integrity adapter
# ---------------------------------------------------------------------------

class ChromaIntegrityAdapter:
    """Wrap :class:`MemoryIntegrityMonitor` around a Chroma-like collection.

    chromadb is NOT a dependency — this duck-types the collection. Any object
    exposing a ``.get()`` method that returns a mapping like::

        {"ids": ["doc1", "doc2"], "documents": ["text one", "text two"], ...}

    is accepted (this is chromadb's ``Collection.get()`` return shape). The
    collection's ``.name`` attribute (if present) is used as the store id so a
    single adapter can track multiple collections; otherwise ``id(collection)``.

    Usage::

        adapter = ChromaIntegrityAdapter()
        adapter.baseline(collection)          # snapshot current contents
        report = adapter.check(collection)    # -> IntegrityReport
        if report.has_tampering:
            alert(report)
    """

    def __init__(self, monitor: MemoryIntegrityMonitor | None = None):
        self.monitor = monitor or MemoryIntegrityMonitor()

    @staticmethod
    def _store_id(collection: Any) -> str:
        name = getattr(collection, "name", None)
        return str(name) if name else f"chroma:{id(collection)}"

    @staticmethod
    def _read_docs(collection: Any) -> list[dict]:
        if not hasattr(collection, "get"):
            raise TypeError(
                "collection must expose a .get() method returning "
                "{'ids': [...], 'documents': [...]}"
            )
        raw = collection.get()
        ids = list(raw.get("ids", []) or [])
        docs = list(raw.get("documents", []) or [])
        out: list[dict] = []
        for i, doc_id in enumerate(ids):
            content = docs[i] if i < len(docs) else ""
            out.append({"id": str(doc_id), "content": "" if content is None else str(content)})
        return out

    def baseline(self, collection: Any) -> str:
        """Snapshot the collection's current contents as the integrity baseline.

        Returns the store_id used (so callers can correlate later checks).
        """
        store_id = self._store_id(collection)
        self.monitor.baseline(store_id, self._read_docs(collection))
        return store_id

    def check(self, collection: Any) -> IntegrityReport:
        """Compare the collection's current contents against its baseline.

        Flagged changes are HELD for review (detect-and-hold): a poisoned doc
        is re-reported on every ``check()`` until :meth:`accept` acknowledges
        it. It is never silently absorbed into the baseline.
        """
        store_id = self._store_id(collection)
        return self.monitor.check(store_id, self._read_docs(collection))

    def accept(self, collection: Any, doc_id: str) -> bool:
        """Acknowledge a pending-review change on this collection as legitimate.

        Delegates to :meth:`MemoryIntegrityMonitor.accept`. After acceptance the
        change is folded into the baseline and no longer re-reported.
        """
        return self.monitor.accept(self._store_id(collection), doc_id)

    def pending_changes(self, collection: Any) -> list:
        """Flagged changes on this collection currently awaiting review."""
        return self.monitor.pending_changes(self._store_id(collection))


# ---------------------------------------------------------------------------
# Agent-to-agent (A2A) authenticated message bus guard
# ---------------------------------------------------------------------------

class A2AGuard:
    """Authenticate agent-to-agent messages on a message bus.

    Wraps an :class:`IdentityRegistry`. Senders must be registered (so their
    secret key is known) before they can ``send``; recipients are verified on
    ``receive``. This is a behavioral authentication layer — NOT a transport
    security replacement.

    Usage::

        guard = A2AGuard()
        guard.register("alice", role="triage")
        guard.register("bob",   role="refunds")

        msg = guard.send("alice", "please refund order #123", recipient_id="bob")
        ok, content = guard.receive(msg)   # ok True on the untampered message
    """

    def __init__(self, registry: IdentityRegistry | None = None,
                 max_age_s: float = 60.0):
        self.registry = registry or IdentityRegistry()
        self.max_age_s = max_age_s

    def register(self, agent_id: str, *, secret_key: bytes | None = None,
                 role: str = "", capabilities: list[str] | None = None):
        """Register an agent on the bus. Returns its AgentIdentity."""
        return self.registry.register(
            agent_id, secret_key=secret_key, role=role, capabilities=capabilities
        )

    def send(self, sender_id: str, content: Any,
             recipient_id: str = "") -> SignedMessage:
        """Sign `content` as `sender_id` -> `recipient_id`. Returns a SignedMessage.

        Raises KeyError if the sender is not registered (its key is unknown).
        """
        sender = self.registry.get(sender_id)
        if sender is None:
            raise KeyError(f"sender not registered on bus: {sender_id!r}")
        return sign_message(sender, content, recipient=recipient_id)

    def receive(self, msg: SignedMessage) -> tuple[bool, Any]:
        """Verify `msg` against the registry.

        Returns ``(ok, content)``. ``ok`` is False for an unknown sender, a
        bad/tampered signature, a wrong recipient, or an expired message. On
        failure the content is still returned (unverified) so callers may log
        it — but MUST NOT act on it.
        """
        ok = self.registry.verify(msg, max_age_s=self.max_age_s)
        return ok, msg.content
