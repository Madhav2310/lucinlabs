# Adjudication rubric — agentzoo holdout (written 2026-07-30, BEFORE reading any finding)

Fixing the criteria before looking at findings is the point. Deciding the rule one finding
at a time is how you choose the rule that produces the number you want.

## The question

**Would a competent maintainer of this repository, shown this finding, agree it identifies a
real security weakness in this code that is worth acting on?**

Not "is the pattern present." Not "could this ever be dangerous." The question is whether
*this* code, in *this* context, has the weakness the rule claims.

## Verdicts

### TP — true positive
The claimed weakness genuinely exists in this code AND the code is reachable in an
agent/LLM context (or is a library surface an agent would plausibly invoke).

- An exec sink whose argument can carry LLM- or user-derived data.
- A SQL string genuinely interpolated from a non-constant.
- A trifecta whose three legs are all real and reachable from one model.
- A secret that is a real credential value committed to the repo.
- Permissive CORS on a server that exposes agent capability.

### FP — false positive
The pattern matched but the weakness does not exist here. Non-exhaustive:

- **Not agent-exposed.** A human-invoked CLI, a build script, a `setup.py`, a dev utility,
  a `__main__` demo. Nothing an LLM can steer.
- **Test / example / fixture code.** Deliberately vulnerable or throwaway; not a shipped
  surface. (Note: intentionally-vulnerable *benchmark* repos are FP for "should act on" —
  record the reason.)
- **Argument provably constant.** The dangerous parameter is a literal or built only from
  literals.
- **Already mitigated adjacent to the call.** Real allowlist, real sandbox with escape flags
  absent, parameterised query, `shlex.quote` on the command path.
- **Placeholder, not a secret.** `sk-...`, `YOUR_API_KEY`, `os.getenv(...)` default of `""`,
  an obvious dummy in a docstring.
- **Misidentified sink.** e.g. the "egress" is a `fetch`/`read`, or the "exec" is a
  subprocess of a fixed binary with no injectable argument.
- **Framework-internal plumbing** that only ever receives developer-authored config.

### UNKNOWN — genuinely undecidable
Reserved for cases where deciding needs knowledge of the codebase you do not have after a
reasonable read (dynamic dispatch you cannot resolve, config you cannot find, a sink defined
in a dependency not present). **Use it.** Guessing in order to avoid UNKNOWN is the bias this
category exists to prevent. UNKNOWN is excluded from precision and reported separately.

## Evidence requirement

Every verdict cites what was read: the file and the line(s), and the specific fact that
decided it. A verdict without evidence is not a verdict.

## Contamination rule

This holdout consists only of findings whose keys had **no prior verdict**, so no label here
influenced the design of any detector or filter. The earlier 100-verdict table is retained
separately and explicitly labelled as the **tuning set**; it must never be used to compute a
published precision number, because the filters were built from it.
