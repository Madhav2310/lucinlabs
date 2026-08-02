# Threat model — the AIFG and the lethal trifecta

## The one object

Nearly every AI-agent vulnerability that has caused real-world damage is the same object:

> **untrusted input reaching a consequential action through the agent's tool graph.**

Lucin models that object once — the **Agent Information-Flow Graph (AIFG)** — and
reasons over it. This page describes the model and the flagship query built on it.

## The Agent Information-Flow Graph (AIFG)

The AIFG (`src/lucin/aifg.py`) is a labeled graph over an agent's tools and data:

- **Nodes** are tools, data sources, sinks, and an explicit `__llm__` mediator node that
  represents the model itself. Each node carries an **information-flow-control (IFC)
  label** on a two-axis lattice: **Integrity** (trusted ↔ untrusted) × **Confidentiality**
  (public ↔ secret), in the Bell-LaPadula / Biba tradition.
- **Edges** are typed **data** or **control** flows between nodes. When a tool body
  genuinely pipes a source into a sink, a real data edge is promoted; otherwise flows are
  routed through the `__llm__` mediator (`read_file → __llm__ → send_email`) rather than
  fabricating a direct tool-to-tool edge. This keeps the witness honest — it distinguishes
  "the model saw both" from "the code wired one into the other."

Because the model is a graph, the same structure powers static analysis (SCAN),
dynamic demonstration (PROVE), and runtime enforcement (GUARD).

## The lethal trifecta (AG-TRIFECTA)

The flagship query is the **lethal trifecta** — the condition that turns a set of
individually-reasonable tools into an exfiltration channel. A trifecta finding fires when
**all** of these hold on the AIFG:

1. **(T) Untrusted control** — an untrusted source has control influence over an egress sink.
2. **(S) Secret data** — an internal/secret source has a data path to that same egress sink.
3. **(E) Egress** — the sink crosses the trust boundary outward (network send, external write).
4. **(¬D) No declassifier** — no declassifier/endorser mediates either path.

In plain terms: the agent can be *told what to do* by untrusted input, it can *read
secrets*, and it can *send data out* — with nothing in between. That is the pattern behind
the incident-class agent breaches.

AG-TRIFECTA is the IFC-formal successor to the simpler `AG-002` (READ ∩ NETWORK capability
intersection). Beyond a yes/no, it:

- emits a **proof-witness path** — the actual data/control chain, so a reviewer can see
  *why* it fired;
- computes a **minimal tool cut** (`min_tool_cut`, Edmonds-Karp max-flow / min-cut) — the
  smallest set of tools to restrict that provably breaks *every* exfil path;
- distinguishes **control influence** from **data flow**.

It also runs across a **merged multi-agent graph** (`query_cross_agent_trifecta`), so a
trifecta that only exists once two agents are composed is still caught.

## Where the trifecta sits among the detectors

The trifecta is one query on the AIFG; the other detectors catch enabling
misconfigurations that make a trifecta (or a direct RCE/injection) possible — unrestricted
shell/exec (AG-001), tainted SQL/CQL (AG-SQL), SSRF (AG-SSRF), insecure deserialization
(AG-DESERIALIZE), tool-description injection (AG-011), wildcard-CORS / unauthenticated
agent servers (AG-CORS/AG-NOAUTH), and so on. The full list with severities is in
[the rules index](/rules/).

## What the static model can and cannot prove

**Can:** prove, pre-deploy, that a dangerous *capability configuration* exists in code —
the enabling conditions for the incident class — with a witness and a minimal fix.

**Cannot:** prove exploitability at runtime, catch behavior that only emerges from
model+tool interaction on live inputs, or fix the model's intent (alignment). Those are
the jobs of PROVE (dynamic) and [GUARD](/runtime/) (runtime enforcement + behavioral
monitoring), and of the honest boundaries in [what SCAN misses](/limits/).

A note on the "why now": the July 2026 Hugging Face incident (an autonomous agent
executing 17,000+ actions into production) is a real motivating event, but neither SCAN
nor GUARD would have stopped the underlying sandbox-escape zero-day itself. Lucin
addresses the far larger class of *misconfiguration-enabled* exfiltration and misuse — not
novel zero-days. We don't overclaim that.
