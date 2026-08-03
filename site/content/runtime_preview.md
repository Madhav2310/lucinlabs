# Runtime enforcement — design-partner preview

**Status: not generally available.** There is no signup, no trial, and no billing.
This page exists so the claim is unambiguous rather than implied.

## What is actually built and validated

The runtime layer (GUARD) enforces the same information-flow model the scanner uses
statically: the path flagged before deploy is the path blocked at runtime. Validated
today, each with a command that regenerates it:

- **Deterministic trifecta block on a real framework.** Wrapping real
  `langchain_core` tools, GUARD blocks a secret → external-email flow and allows
  benign egress (`benchmarks/validate_phases.py`).
- **Live-LLM end-to-end block.** A real model performed a plausible-looking action
  that emailed a customer's PII to an external address; GUARD blocked it
  deterministically, and a benign task passed with no false block
  (`benchmarks/guard_live_llm.py`).
- **Content-based taint across the model boundary.** Label-only tracking is lost when
  a model re-emits a secret as plain text, so sensitive tool returns are fingerprinted
  and re-tainted on any later egress argument.

## What is NOT true yet

- **No production deployment.** Zero design partners are running this in a real
  environment. Any vendor telling you their agent runtime is battle-tested in 2026 is
  ahead of the evidence, and so would we be.
- **Transformed secrets can still escape.** Content fingerprinting catches verbatim
  and simple-encoding exfiltration (base64/hex/url). A model that *paraphrases* a
  secret defeats it. The fix (sealing values behind opaque references at the tool
  boundary, so the model never sees the secret) is designed and not yet shipped.
- **Behavioural anomaly detection is validated on synthetic traces only** — a 3.75%
  benign session false-positive rate on a generated adversarial corpus, not on real
  production traffic. We label it synthetic everywhere and keep it out of headlines.
- **No latency SLA.** Measured about 5 ms per event on the behavioural path. An
  earlier "sub-millisecond" claim was wrong and was corrected.

## Who this is for

One or two teams running real agents that touch real credentials, who want
deterministic enforcement rather than a probabilistic filter, and who are willing to
be a design partner — meaning you get engineering attention and we get the thing we
cannot manufacture: real traces and real false-block data.

If that is not you, the scanner is free, complete, and needs nothing from us:

```
pip install lucin
lucin scan .
```

## Why deterministic, not model-based

Most runtime AI-security products classify prompts and responses with a model. That
approach cannot give you a guarantee — it gives you a probability, and it fails on the
inputs it was not trained for. GUARD's gate is deterministic: it enforces a label
lattice over observed data flow, so a blocked flow is blocked because of a rule you
can read, with a witness path you can audit. The trade-off is honest: determinism
covers less ground, and what it covers, it covers reliably.
