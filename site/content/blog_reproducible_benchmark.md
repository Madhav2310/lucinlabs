# We published our false-positive rate and the command that regenerates it. Here's why nobody else does.

*~1,250 words. All numbers reproducible against `DEFINITION_OF_DONE.md`, verified 2026-07-29. Product name placeholder `lucin` pending rename.*

---

Pick any AI-agent security tool and read its landing page. You will find a detection number — "detects 200+ attack techniques," "blocks 95% of prompt injections," "catches OWASP LLM Top 10." What you will not find is a command you can run to check it.

That asymmetry is the whole reason this post exists. In security tooling, the number that decides whether a tool gets adopted or uninstalled is not recall. It's precision. And precision is exactly the number nobody publishes.

## A false positive is worse than a miss

This is the thesis, and it's counterintuitive enough that it's worth stating plainly: **for adoption, a false positive is worse than a miss.**

A miss is invisible. You never see the vuln the tool didn't find, so it costs you nothing in trust. A false positive is loud, and it costs you the tool. The first time a scanner flags a line that's obviously fine, a developer's confidence drops. The third time, they add `# noqa`. The fifth time, they pipe it to `/dev/null` in CI and forget it exists. A security tool that gets muted is worse than no tool, because now there's a dashboard that's green for the wrong reason and nobody's actually looking.

Every developer who's run a noisy linter or a CVE scanner that screams about unreachable dependencies knows this in their gut. The industry's response has been to compete on breadth of detection — more techniques, more rules, more scary findings in the demo — because scary findings sell and false positives don't show up in a slide. So the incentive is to maximize recall in the demo and never mention precision.

We think that's backwards, and we think the way to prove it is to publish the precision number *with the command that regenerates it.*

## The number, and the command

Here is our false-positive rate:

**0 adjudicated false positives across 52 real repositories / 2,732 files** — counted per distinct (file, detector-id) pair, outside a documented per-repo known-capability allowlist. And the number that corpus *cannot* tell you: on a deliberately broader 81-repo population, precision is **20.5–31.5% (n=73 clean-holdout adjudicated, 95% CI 12.9–42.9%)**. Our earlier 58% was computed over the same adjudication labels used to build the precision filters — train-on-test — and is withdrawn. Both are published because only one of them flatters us.

Here is the command:

```
python benchmarks/build_benign_corpus.py
```

The corpus is 52 real open-source repos — real agent frameworks and real applications built on them (smolagents, CAMEL, LlamaIndex, mem0, txtai, autogen, agno, promptflow, and more), not fixtures we wrote. The script clones them, runs every detector, and counts confirmed false positives. Confirmed true-positives (380 of them) are excluded per the documented methodology so they don't flatter the number. The result is 0 adjudicated false positives. You can run it and get the same number, or you can find one we missed — which is genuinely the most useful thing you could send us.

Getting to 0.0% was not free, and we didn't get there by being timid. We got there by triaging real false positives and fixing the detectors: an `"execute"`-keyword over-match, a bare-substring match on FastAPI/Flask servers, a DB-verb substring firing inside docstrings. Each one was a detector that was technically "right" and practically noise. Cutting them is what earns the green checkmark meaning something.

## The number you're not supposed to show next to it

Zero confirmed false positives, on its own, is a red flag, and you should treat it as one. `cat /dev/null` never fires either. The only way a near-zero false-positive count means anything is if you publish recall next to it — so we do:

**76% recall: 38 of 50 distinct vulnerabilities across 10 classes. A 24% false-negative rate. 86% (19/22) on the real third-party cases.**

```
python benchmarks/recall_corpus.py
```

The recall corpus is 50 distinct vulnerable agents — 22 real cases with provenance/CVEs recorded in a manifest, plus 28 labeled constructed ones — spanning 10 vulnerability classes. Here's the honest per-class breakdown, including the classes we're weak or blind on:

| Vuln class | Recall | Note |
|---|---|---|
| SQL / CQL injection | 100% | |
| Command injection | 100% | |
| eval / exec RCE | 100% | |
| CORS / no-auth | 100% | |
| Lethal trifecta (exfil edge) | 100% | the flagship shape |
| Insecure deserialization | 100% | via cross-function/intra-class taint |
| Container escape | ~80% | resolves docker cmds built via a variable |
| SSRF | 17% | **deliberately conservative** — only fires when tainted data forms the URL host |
| Path traversal | 0% | detector **built, sound, unit-tested — left unregistered on purpose** (see below) |

The path-traversal row is the one that makes the point. We have a working, unit-tested path-traversal detector. It's not registered. If we turned it on, recall would go up — and the precision result (0 confirmed FP outside a documented per-repo known-capability allowlist) would break, because the benign corpus contains byte-identical *legitimate* file-handling tools that the detector cannot distinguish from the vulnerable ones without runtime context. So we left it off. That is precision-over-recall as a policy, not a slogan: we would rather miss a class and say so than ship a detector we know fires on benign code.

SSRF at 17% is the same choice at a smaller scale — the detector only fires when tainted data actually forms the URL host, so it stays quiet (and precise) rather than flagging every outbound request.

## Why nobody else publishes this

Not because they're dishonest. Because it's expensive and it's dangerous.

**It's expensive** because a reproducible benchmark is real infrastructure — a corpus of real repos, a labeling methodology, a script that regenerates the number on every commit — and it has to stay green as the detectors change. That's ongoing work with no demo payoff.

**It's dangerous** because the moment you publish the command, the number stops being yours. A hostile reader can run it. If your real false-positive rate is 12% and your marketing says "low false positives," a reproducible command turns your marketing into a lie anyone can prove in thirty seconds. Most tools can't survive that, so they don't offer it. The absence of a rerun command is itself information.

There's a deeper reason too. Publishing the command forces you to publish the *methodology* — what counts as a false positive, what's excluded, what corpus. Once that's in the open, you can't quietly tune the number by moving the goalposts. The discipline the command imposes on us is the actual product: it's what keeps the 0.0% honest across releases.

## What this buys, and what it doesn't

We're not claiming the benchmark makes us correct. 52 repos is a proxy for the true population of agent codebases, not the population itself; precision at real user scale is something we can only earn with real users, and we say so. The recall number will move as we add detectors, and when it moves, the command will show it moving — up or down.

What the reproducible benchmark buys is the one thing security tooling runs on and can't fake: **trust you can check.** You don't have to believe our false-positive rate. You can run `build_benign_corpus.py` and watch it come back 0, or you can run it and find the false positive we missed. Either outcome is better than a number on a slide.

If you run an agent in production, that's the ask. Point the scanner at it, try to make it cry wolf, and file the issue when it does.

```
pip install lucin && lucin scan ./your-agent/
```

The scanner is MIT-licensed. Both benchmark commands are committed. The 24% we miss is written down. Run the numbers yourself — we'd rather you reproduce them than trust our marketing.

---

*Sources: [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) · benchmark methodology and both commands are in the repo. All figures verified against DEFINITION_OF_DONE.md, 2026-07-29.*
