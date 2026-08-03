"""crew_to_graph auto-discovery evaluation — CrewAI crew -> AgentGraph -> R0.

Reproduce:
    python benchmarks/crew_graph_eval.py

What this does
--------------
Exercises ``lucin.multiagent.adapters.crew_to_graph`` end-to-end: it takes
a CrewAI crew (agents + tools + a delegation/task chain), auto-discovers an
:class:`AgentGraph`, and then runs the cascade module to compute R0 (the
effective reproduction number, Morris-II-style worm-spread indicator).

Two modes, chosen automatically:

  * LIVE   -- ``crewai`` is importable, so we build a REAL crewai ``Crew`` object
             (real ``Agent`` / ``Task`` / ``BaseTool`` instances) and feed the
             actual object to ``crew_to_graph``. This is the L3 win: validation
             against the real framework object shape, not our own dict.

  * MOCK   -- ``crewai`` could NOT be imported (unavailable in this environment,
             like PyCG / PROVE). We fall back to a FAITHFUL structural
             mock that reproduces the exact attribute names crew_to_graph reads
             on a real crewai object: ``crew.agents``, ``crew.tasks``, each
             agent's ``role`` / ``tools`` (tool objects with ``.name``) /
             ``allow_delegation``, each task's ``agent`` / ``context`` /
             ``description``. This is a STRUCTURAL-MOCK validation, NOT a
             live-framework validation.

The graph topology and R0 are deterministic, so the printed numbers reproduce
exactly on every run.
"""

from __future__ import annotations

import sys

from lucin.multiagent.adapters import crew_to_graph
from lucin.multiagent.cascade import CascadeDetector

# ---------------------------------------------------------------------------
# The crew we build (same logical shape in both LIVE and MOCK modes)
# ---------------------------------------------------------------------------
#
#   researcher  (tools: web_search)              -- benign, no dangerous tools
#   writer      (tools: write_file)              -- HIGH-PRIVILEGE
#   manager     (tools: send_email, allow_deleg) -- HIGH-PRIVILEGE
#
#   task chain (context = upstream producer):
#     t_research (researcher)
#     t_write    (writer,  context=[t_research])  ->  writer  delegates_to researcher
#     t_review   (manager, context=[t_write])     ->  manager delegates_to writer
#
#   Expected discovered graph: 3 nodes, 2 delegation edges
#     writer  -> researcher
#     manager -> writer
# ---------------------------------------------------------------------------


def build_live_crew():
    """Build a REAL crewai Crew. Raises if crewai is unavailable/unusable."""
    import os

    # crewai validates an LLM lazily (only at kickoff), but some versions probe
    # env at Agent construction. Provide a dummy key so *construction* succeeds;
    # we never call .kickoff(), so no network/LLM call is made.
    os.environ.setdefault("OPENAI_API_KEY", "sk-lucin-structural-only")

    from crewai import Agent, Crew, Task
    from crewai.tools import BaseTool

    def make_tool(tool_name: str):
        class _Tool(BaseTool):
            name: str = tool_name
            description: str = f"{tool_name} tool"

            def _run(self, *args, **kwargs):  # never actually invoked here
                return ""

        return _Tool()

    researcher = Agent(
        role="researcher",
        goal="find facts",
        backstory="a researcher",
        tools=[make_tool("web_search")],
        allow_delegation=False,
    )
    writer = Agent(
        role="writer",
        goal="write a report",
        backstory="a writer",
        tools=[make_tool("write_file")],
        allow_delegation=False,
    )
    manager = Agent(
        role="manager",
        goal="review and email the report",
        backstory="a manager",
        tools=[make_tool("send_email")],
        allow_delegation=True,
    )

    t_research = Task(description="research the topic",
                      expected_output="notes", agent=researcher)
    t_write = Task(description="write the report", expected_output="draft",
                   agent=writer, context=[t_research])
    t_review = Task(description="review and email", expected_output="sent",
                    agent=manager, context=[t_write])

    return Crew(agents=[researcher, writer, manager],
                tasks=[t_research, t_write, t_review])


# ---------------------------------------------------------------------------
# Faithful structural mock (matches crewai's real attribute names)
# ---------------------------------------------------------------------------

import uuid


class MockTool:
    """Mirrors crewai BaseTool: exposes ``.name``."""

    def __init__(self, name: str):
        self.name = name


class MockAgent:
    """Mirrors crewai Agent: ``.id`` (UUID), ``.role``, ``.tools``,
    ``.allow_delegation``. Real crewai Agents carry a UUID ``.id`` that
    ``_agent_id`` keys on (prioritized over ``role``) -- replicated here so the
    mock discovers the SAME graph as the live framework."""

    def __init__(self, role, tools, allow_delegation=False):
        self.id = uuid.uuid4()
        self.role = role
        self.tools = tools
        self.allow_delegation = allow_delegation


class MockTask:
    """Mirrors crewai Task: ``.id`` (UUID), ``.agent``, ``.context``,
    ``.description``. Real crewai Tasks carry a UUID ``.id``; context resolution
    (``_resolve_ctx_to_agent``) depends on it to map a context task back to its
    owning agent -- so the mock must have it to be faithful."""

    def __init__(self, description, agent, context=None):
        self.id = uuid.uuid4()
        self.description = description
        self.agent = agent
        self.context = context or []


class MockCrew:
    """Mirrors crewai Crew: ``.agents``, ``.tasks``."""

    def __init__(self, agents, tasks):
        self.agents = agents
        self.tasks = tasks


def build_mock_crew():
    researcher = MockAgent("researcher", [MockTool("web_search")],
                           allow_delegation=False)
    writer = MockAgent("writer", [MockTool("write_file")],
                       allow_delegation=False)
    manager = MockAgent("manager", [MockTool("send_email")],
                        allow_delegation=True)

    t_research = MockTask("research the topic", researcher)
    t_write = MockTask("write the report", writer, context=[t_research])
    t_review = MockTask("review and email", manager, context=[t_write])

    return MockCrew([researcher, writer, manager],
                    [t_research, t_write, t_review])


# ---------------------------------------------------------------------------

EXPECTED_EDGES = {
    "writer": {"researcher"},
    "manager": {"writer"},
    "researcher": set(),
}


def main() -> int:
    mode = "MOCK"
    import_err = None
    crew = None
    try:
        import crewai  # noqa: F401
        try:
            crew = build_live_crew()
            mode = "LIVE"
        except Exception as e:  # crewai importable but construction failed
            import_err = f"crewai imported but crew construction failed: {e!r}"
            crew = build_mock_crew()
    except Exception as e:  # import blocked
        import_err = f"crewai import blocked: {e!r}"
        crew = build_mock_crew()

    graph = crew_to_graph(crew)

    agents = graph.all_agents()
    # Node ids differ by mode: MOCK keys by role ("manager"); real crewai Agent
    # carries a UUID `.id` that _agent_id prioritizes, so LIVE keys by UUID.
    # Resolve everything through the node's stored `.role` so the checks are
    # mode-independent.
    id2role = {a: (graph.get(a).role if graph.get(a) else a) for a in agents}
    role2id = {r: a for a, r in id2role.items()}
    edges = {a: set(graph.successors(a)) for a in agents}
    # edges expressed in role terms
    role_edges = {
        id2role[a]: {id2role[b] for b in succ}
        for a, succ in edges.items()
    }
    n_edges = sum(len(v) for v in edges.values())

    detector = CascadeDetector(graph)
    global_r0 = detector.compute_global_r_zero()
    manager_report = detector.propagate_failure(role2id["manager"])
    manager_blast_roles = {id2role[a] for a in manager_report.blast_radius}

    print("=" * 60)
    print(f"  crew_to_graph evaluation  [mode: {mode}]")
    print("=" * 60)
    if import_err:
        print(f"  note: {import_err}")
        print("  -> STRUCTURAL-MOCK validation (live-crewai env-blocked, "
              "like PyCG/PROVE).")
    else:
        print("  -> LIVE-FRAMEWORK validation against real crewai objects.")
    print()
    print(f"  discovered nodes ({len(agents)}) by role: {sorted(id2role.values())}")
    if mode == "LIVE":
        print(f"  (node ids are crewai UUIDs; shown by role. raw ids: {sorted(agents)})")
    print(f"  discovered delegation edges ({n_edges}):")
    for a in sorted(role_edges):
        for b in sorted(role_edges[a]):
            node = graph.get(role2id[a])
            hp = " [high-priv]" if node and node.is_high_privilege else ""
            print(f"      {a} -> {b}{hp}")
    print()
    print(f"  global R0 (weighted out-degree): {global_r0:.4f}")
    print(f"  cascade from 'manager': blast_radius="
          f"{sorted(manager_blast_roles)}  "
          f"R0={manager_report.r_zero:.4f}  depth={manager_report.depth}")
    print()

    def hp(role):
        node = graph.get(role2id.get(role, ""))
        return bool(node and node.is_high_privilege)

    # ---- assertions: topology auto-discovered correctly -------------------
    ok = True

    def check(name, cond):
        nonlocal ok
        status = "PASS" if cond else "FAIL"
        if not cond:
            ok = False
        print(f"  [{status}] {name}")

    check("3 agents discovered", len(agents) == 3)
    check("2 delegation edges discovered", n_edges == 2)
    check("edges match expected topology (by role)", role_edges == EXPECTED_EDGES)
    check("writer flagged high-privilege (write_file)", hp("writer"))
    check("manager flagged high-privilege (send_email)", hp("manager"))
    check("researcher NOT high-privilege (web_search)", not hp("researcher"))
    check("global R0 == 0.8", abs(global_r0 - 0.8) < 1e-9)
    check("manager-cascade blast radius == {researcher, writer}",
          manager_blast_roles == {"researcher", "writer"})
    check("manager-cascade R0 == 1.0", abs(manager_report.r_zero - 1.0) < 1e-9)

    print()
    print(f"  RESULT: {'ALL CHECKS PASS' if ok else 'CHECKS FAILED'}  "
          f"(mode={mode})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
