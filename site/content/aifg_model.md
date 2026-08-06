# An information-flow model for AI agents, and what it provably cannot decide

Most agent security tooling answers the question "does this look dangerous?" That question has no formal content, which is why the answers are classifiers, heuristics, and confidence floats that nobody can check.

This is a description of a different question, one that does have formal content: **can untrusted data reach an external sink through a node that holds secrets, and if so, what is the smallest set of tools whose removal makes that impossible?**

Both halves of that are decidable on a graph. This post is the model, the two algorithms, the proofs they rest on, and, at length, the part the model cannot decide and why that boundary is where a runtime layer has to begin.

Everything here is in `src/lucin/aifg.py`, 985 lines, MIT licensed.

## 1. The graph

An agent is a set of tools. Each tool is a function with a body. The Agent Information-Flow Graph (AIFG) has one node per tool, plus one distinguished node, `__llm__`, that I will come back to because it carries most of the interesting difficulty.

Edges are dataflow. An edge from `read_email` to `post_webhook` asserts that a value produced by the first can reach an argument of the second. Edges carry a kind, which separates *data* flow from *control* flow: whether the untrusted value became the payload, or merely steered the decision to make the call. Both matter, and conflating them is a common way to produce findings that cannot be defended.

Nodes are built by parsing tool bodies, not tool names. A tool called `get_weather` whose body calls `subprocess.run` is classified by the `subprocess.run`. This is the entire reason the model is worth building over a schema: names are documentation, and documentation is not a security boundary.

## 2. The lattice

Every node carries a label, and the label is a pair drawn from two classical lattices.

```python
class Integrity(IntEnum):      # Biba. Higher = more trusted.
    UNTRUSTED = 0
    TRUSTED   = 1

class Confidentiality(IntEnum): # Bell-LaPadula. Higher = more secret.
    PUBLIC   = 0
    INTERNAL = 1
    SECRET   = 2
```

Integrity is Biba: untrusted data may not rise to trusted without an explicit endorser. LLM output, tool returns, web and email content default to `UNTRUSTED`. Developer config and the system prompt default to `TRUSTED`.

Confidentiality is Bell-LaPadula: secret data may not flow to public without an explicit declassifier.

When values from several sources combine, the labels join:

```python
def join(self, other):
    return IFCLabel(
        integrity       = min(self.integrity, other.integrity),   # most-untrusted wins
        confidentiality = max(self.confidentiality, other.conf),  # most-secret wins,
    )
```

Minimum on integrity, maximum on confidentiality. One tainted input taints the result; one secret input makes the result secret.

That choice is not stylistic. The join is monotone in both components, so the labelling of a graph is a monotone function on a finite lattice, and by Knaster-Tarski a least fixed point exists and iteration reaches it. In practice: label propagation terminates, and it terminates at the same answer regardless of the order you visit nodes in. A model whose result depends on traversal order is not a model, it is a heuristic with extra steps.

```figure
aifg-lattice
```

## 3. The trifecta, as labelled reachability

Simon Willison's lethal trifecta names the condition informally: an agent is exposed to exfiltration by injection when it has access to private data, exposure to untrusted content, and the ability to communicate externally.

As a graph predicate it becomes precise. A trifecta exists when there is a path from a node whose integrity label is `UNTRUSTED` to a node classified as an egress sink, where some node along that path carries confidentiality `INTERNAL` or above.

Two things follow immediately, and both matter more than they look.

**First, it is a reachability query,** which means it is decidable in linear time and the answer does not depend on a threshold. There is no confidence score because there is nothing to be uncertain about at this layer. The path exists in the graph or it does not.

**Second, and this is the load-bearing part, a positive answer comes with a witness.** `query_trifecta` does not return a boolean. It returns the path:

```
control: read_email      → __llm__ → post_webhook
data:    query_customers → __llm__ → post_webhook
```

Separate control and data witnesses, because they answer different questions: what steered the call, and what ended up in it.

A finding that ships with the path that produced it is checkable by a reader who does not trust the tool. That property is what the rest of the system is built to preserve, and it is the difference between a scanner and an oracle.

It is also enforced downstream. A CRITICAL or HIGH finding with no witness and no source line is capped to MEDIUM before it is reported, because a reader cannot verify it. On the precision corpus, findings carrying a witness or a source line ran at **50% precision**; findings carrying neither ran at **11%**. The evidence gate is not a nicety, it is where half the precision comes from.

## 4. Minimal remediation, as a min vertex cut

Knowing a path exists is not advice. The useful question is which tools to change, and the smallest honest answer to that is a graph problem too.

You want the minimum-cardinality set of tool nodes whose removal disconnects every untrusted source from every egress sink. That is a minimum vertex cut, and by Menger's theorem its size equals the maximum number of vertex-disjoint source-to-sink paths.

The standard construction converts vertex capacities to edge capacities by splitting:

```python
for nid in g.nodes:
    if nid in removable:
        cap[f"{nid}::in"][f"{nid}::out"] = 1.0    # unit cost: cuttable
    else:
        cap[f"{nid}::in"][f"{nid}::out"] = INF    # cannot be cut

for e in g.edges:
    cap[f"{e.src}::out"][f"{e.dst}::in"] = INF    # real edges are free
```

Split every node into `v_in → v_out`. Give that internal edge capacity 1 if the tool may be restricted and infinity if it may not, since some tools are load-bearing and an operator cannot delete them. Give every real edge infinity, so only node-splits can ever saturate. Attach a super-source to the untrusted sources and a super-sink to the egress sinks, run Edmonds-Karp, and read the cut off the residual graph: the nodes whose `::in` is still reachable from the source but whose `::out` is not.

The output is a sentence a person can act on: *restrict these two tools and every exfiltration path in this agent is severed.* Not a ranked list of forty findings. A cut.

**A caveat I would rather state than have found.** The cut is computed only over trifecta paths. Measured on the current baseline, `AG-TRIFECTA` accounts for **21 of 701 findings across 21 of 658 targets**, roughly 3%. So this is the minimal provable fix for the exfiltration class, and it is not "the minimum set of changes that eliminates your findings." The three highest-volume rules are not covered by it at all. The graph layer appears to be uncontested (a grep for `min_cut|max_flow|lattice|IFC` across the two nearest open-source scanners I cloned and read, `agent-audit` and `SkillSpector`, returns zero hits in either), but its blast radius is narrow and a claim that does not say so is dishonest.

```figure
aifg-mincut
```

## 5. What the model provably cannot decide

Here is the part that matters, and the reason I do not think static analysis is the whole answer to this problem.

Look again at the witness:

```
read_email      → __llm__ → post_webhook
query_customers → __llm__ → post_webhook
```

`__llm__` is a node in the graph because the model is a real participant in the dataflow: values go in, values come out, and the transformation is opaque. Routing LLM-mediated data through an explicit join is the honest representation. Pretending `read_email` connects directly to `post_webhook` would assert a path the code does not contain.

But an opaque join has a consequence that no amount of static cleverness removes. **Two sources enter `__llm__` and one value leaves it. Static analysis cannot determine which source fed which sink.**

It knows both sources reached the model. It knows the model reached the sink. It cannot know whether the secret from `query_customers` is in the outgoing payload, or whether only the untrusted text from `read_email` is, or both. There is no dataflow fact to recover, because the transformation happened inside a system whose behaviour is not a function of its source code.

This is not an engineering gap. It is not PyCG being unavailable, or a call graph being incomplete, or a fixpoint being imprecise. It is a property of putting a model in the middle of a dataflow: the static graph can prove a path is *possible* and can never prove which values traversed it.

Which is exactly why the model's default posture is conservative. The join is monotone toward danger, so an `__llm__` node fed by anything untrusted taints everything downstream of it. That is sound and it over-approximates, and the over-approximation is visible in the numbers: overall precision on an uncurated 81-repo population is **20.5 to 31.5%** (n=73 clean-holdout adjudicated, 95% CI 12.9 to 42.9%), and on that clean holdout `AG-TRIFECTA` specifically scored **0 of 6**. A predicate that is easy to satisfy when a corpus is labelled is not the same as a predicate that is easy to satisfy usefully in the wild.

At runtime the ambiguity disappears, because you are no longer reasoning about what could happen. Runtime lineage is observed 1:1: this value, from this call, arrived at this argument. The disambiguation static analysis cannot perform is not hard at runtime, it is free.

So the argument for a runtime layer is not that static analysis is weak or incomplete. It is that one specific question, *which source fed this sink across the model*, is undecidable before execution and trivially decidable during it.

## 6. One model, two evaluations, and precisely how far that goes

If the static and runtime halves ran different models, the argument above would be worthless: you would have two policy languages that drift, and the first time they disagreed the security team would trust neither.

They do not. `lucin.aifg` is imported by the static trifecta detector, by five modules of the runtime layer, and by the control plane's reconstruction path. The runtime provenance graph reconstructs into the same `AIFG` dataclass and the same `to_dict()` schema, and `query_trifecta` runs unchanged over both.

The tripwire is `tests/test_aifg_coherence.py`, and I want to state exactly what it asserts, because this is the claim most likely to be overstated by someone summarising it, including me:

- The three native graph representations (static AIFG, runtime provenance, multi-agent delegation) are **structurally distinct types**. It really was three graphs.
- The runtime graph **projects into** the static `AIFG` type and schema, and `query_trifecta` yields a structurally identical `TrifectaFinding` from both on the same scenario.
- The multi-agent delegation graph also projects in, coarser and agent-granular, scoped as such.
- Runtime edges are observed lineage, not inferred.

The claim is honest at the level of schema coherence, query coherence, and real runtime edges. It is **not** a claim of tool-level static witness precision, and §5 is why. If the runtime side ever could not be reconstructed into `lucin.aifg.AIFG` without a parallel type, the "one coherent model" language would have to be retracted from everything public. It can, so it stands, at that scope and no wider.

## 7. What is not built

Sharing a type is not the same as sharing an artifact.

A static finding and a runtime decision are the same kind of object, and there is currently **no path by which a scan produces a runtime policy**. Every `IFCPolicy` in the repository is hand-constructed with a literal agent name. The policy type carries an allowlist and an agent id, with no slot for a finding or a source location, and the runtime `Decision` type carries `allow`, `reason`, `witness` and an allowlist entry, with no field that could hold a rule id or a `file:line`.

So a runtime block cannot presently cite the static finding that predicted it. That seam is the obvious next piece of work and it is not written yet. I would rather say that here than let a reader infer otherwise from the word "unified."

Two further limits, stated because they bound everything above. The runtime gate protects values that have been wrapped and labelled; unwrapped raw values pass through unchecked, which is the interceptor's problem and not the gate's. And the behavioural anomaly layer that sits alongside all of this is validated on synthetic corpora only, at a 3.75% benign-session false-positive rate, with zero production deployments.

## 8. Related work

The model is not novel in its parts, and I think that is a point in its favour rather than against it.

Microsoft Research's Costa and Köpf, [*Securing AI Agents with Information-Flow Control*](https://arxiv.org/pdf/2505.23643), independently describes labelling tools and arguments and comparing static labels against dynamic ones. That is this lattice, arrived at separately, which is the sort of convergence that suggests the shape is right rather than merely mine.

[*Deriving Static Security Testing from Runtime Security Protection*](https://arxiv.org/pdf/2107.07300) argues for a single policy library driving both static verification and runtime enforcement, precisely so that policy semantics cannot diverge between them. §6 is an attempt at that property, and §7 is how far short of it I currently am.

The sanitizer model is scoped per sink kind, modelled on Pysa's `Sanitize[TaintSink[SQL]]`: a value made safe for a shell sink is not credited as safe for a SQL sink. It is fail-closed, so it can only ever withdraw a finding it can prove is guarded. The Artemis ablation ([arXiv 2502.21026](https://arxiv.org/abs/2502.21026), OOPSLA 2025) measured weaker sanitizer modelling producing 9.2× more false positives, which is the reason it is scoped rather than global.

## 9. Reproduce

```
python benchmarks/build_benign_corpus.py     # 11 adjudicated FPs / 54 repos / 9,520 files
python benchmarks/recall_corpus.py           # 76% recall, 38/50, and the 12 misses by name
python benchmarks/agentzoo_precision.py --report-only   # 20.5-31.5% precision, n=73
```

The model is `src/lucin/aifg.py`. The coherence tripwire is `tests/test_aifg_coherence.py`. Both are short enough to read in an afternoon, which is the only real answer to why you should believe any of this.

If you find the model wrong, or the cut unsound, or a case where the labelling is not monotone, that is worth considerably more to me than agreement.

---

*Sources: [Costa & Köpf, Securing AI Agents with Information-Flow Control (arXiv 2505.23643)](https://arxiv.org/pdf/2505.23643) · [Deriving Static Security Testing from Runtime Security Protection (arXiv 2107.07300)](https://arxiv.org/pdf/2107.07300) · [Artemis (arXiv 2502.21026), OOPSLA 2025](https://arxiv.org/abs/2502.21026) · [Simon Willison, The lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/). Lucin figures reproducible from the commands above.*
