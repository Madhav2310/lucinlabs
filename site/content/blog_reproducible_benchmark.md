# We published our false-positive rate and the command that regenerates it. Here's why nobody else does.

Pick any AI-agent security tool and read its landing page. You will find a detection number. Detects 200+ attack techniques. Blocks 95% of prompt injections. Covers the OWASP LLM Top 10. What you will not find is a command you can run to check it.

That asymmetry is why this post exists. The number that decides whether a security tool survives in your pipeline is not recall. It is precision. And precision is the number nobody publishes.

## A false positive is worse than a miss

This is counterintuitive enough to state plainly: for adoption, a false positive costs more than a miss.

A miss is invisible. You never see the vulnerability the tool failed to find, so it costs you nothing in trust. A false positive is loud, and it costs you the tool. The first time a scanner flags a line that is obviously fine, confidence drops. The third time, someone adds `# noqa`. The fifth time it gets piped to `/dev/null` in CI and forgotten. A muted security tool is worse than no tool, because now there is a green dashboard and nobody looking at it.

Anyone who has run a noisy linter knows this already. The industry's response has been to compete on breadth: more techniques, more rules, more alarming findings in the demo. Scary findings sell. False positives never appear on a slide. So the incentive is to maximise recall where people can see it and never mention precision at all.

I think that is backwards, and the only way to prove it is to publish the precision number with the command that regenerates it.

## The number, and the command

Here is mine.

**11 adjudicated false positives across 54 real repositories and 9,520 files**, counted per distinct (file, detector-id) pair, outside a documented per-repo known-capability allowlist.

```
python benchmarks/build_benign_corpus.py
```

And the number that corpus cannot tell you. On a deliberately broader 81-repo population, precision is **20.5 to 31.5%** (n=73 clean-holdout adjudicated, 95% CI 12.9 to 42.9%). An earlier figure of 58% was computed over the same adjudication labels used to build the precision filters, which is training on the test set. It is withdrawn. Both numbers are here because only one of them flatters me.

The corpus is 54 real open-source repositories: agent frameworks and the applications built on them, including smolagents, CAMEL, LlamaIndex, mem0, txtai, autogen, agno and promptflow. Not fixtures I wrote. The script clones them, runs every detector, and counts what survives adjudication. 380 confirmed true positives are excluded under the documented methodology so they cannot flatter the result.

Getting to 11 was not free, and I did not get there by making the detectors timid. I got there by reading every false positive and fixing what caused it. An `execute` keyword that over-matched. A bare substring that fired on any FastAPI or Flask server. A database verb matching inside a docstring. Each of those was a detector that was technically correct and practically noise. Cutting them is what makes a clean scan mean anything.

## The number you are not supposed to print next to it

A low false-positive count on its own is a red flag, and you should treat it as one. `cat /dev/null` never fires either. A precision claim means nothing unless recall sits beside it, so:

**76% recall. 38 of 50 distinct vulnerabilities across 10 classes. A 24% false-negative rate. 86%, or 19 of 22, on the real third-party cases.**

```
python benchmarks/recall_corpus.py
```

The recall corpus is 50 distinct vulnerable agents: 22 real cases with provenance and CVEs recorded in a manifest, plus 28 labelled constructed ones. Here is the per-class breakdown, including the classes where I am weak or blind.

| Vuln class | Recall | Note |
|---|---|---|
| SQL / CQL injection | 100% | |
| Command injection | 100% | |
| eval / exec RCE | 100% | |
| CORS / no-auth | 100% | |
| Lethal trifecta (exfil edge) | 100% | the flagship shape |
| Insecure deserialization | 100% | via cross-function/intra-class taint |
| Container escape | ~80% | resolves docker commands built through a variable |
| SSRF | 17% | deliberately conservative: fires only when tainted data forms the URL host |
| Path traversal | 0% | detector built, sound, unit-tested, left unregistered on purpose |

The path-traversal row is the one that makes the point. I have a working, unit-tested path-traversal detector. It is not registered. Turning it on would raise recall and break the precision result, because the benign corpus contains legitimate file-handling tools that are byte-identical to the vulnerable ones without runtime context. So it stays off. That is precision over recall as a policy rather than a slogan: I would rather miss a class and name it than ship a detector I already know fires on correct code.

SSRF at 17% is the same trade at a smaller scale. That detector fires only when tainted data actually forms the URL host, so it stays quiet instead of flagging every outbound request.

## Why nobody else does this

Not because they are dishonest. Because it is expensive and it is dangerous.

It is expensive because a reproducible benchmark is real infrastructure. A corpus of real repositories, a labelling methodology, a script that regenerates the number on every commit, and all of it has to stay green while the detectors keep changing. That is ongoing work with no demo payoff.

It is dangerous because the moment you publish the command, the number stops being yours. A hostile reader can run it. If your real false-positive rate is 12% and your marketing says "low false positives," a reproducible command turns that into something anyone can disprove in thirty seconds. Most tools cannot survive it, so they do not offer it. The absence of a rerun command is itself information.

There is a third reason, and it is the one that actually bites. Publishing the command forces you to publish the methodology: what counts as a false positive, what is excluded, which corpus. Once that is in the open you can no longer improve the number quietly by moving the goalposts. The discipline is the product.

## What this buys, and what it does not

It does not make me correct. 54 repositories are a proxy for the population of real agent codebases, not the population itself. Precision at real user scale is something I can only earn with real users, and I have not earned it yet. The recall number will move as the detectors change, and when it moves, the command will show it moving in whichever direction it went.

What a reproducible benchmark buys is the one thing security tooling runs on and cannot fake: a claim you can check without trusting me. You do not have to believe the false-positive count. You can run `build_benign_corpus.py` and get 11, or you can run it and find the twelfth one I missed.

The second outcome is the more useful one, and it is the ask.

```
pip install lucin && lucin scan ./your-agent/
```

MIT licensed. Both benchmark commands are committed. The 24% I miss is written down by name.

---

*Sources: [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/). Benchmark methodology and both commands are in the repository. All figures verified against DEFINITION_OF_DONE.md, 2026-07-29.*
