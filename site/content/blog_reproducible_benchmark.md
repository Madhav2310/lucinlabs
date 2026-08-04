# I published my false-positive rate and the command that regenerates it. Here is why almost nobody does.

Every security tool tells you what it catches. Detects 200+ attack techniques. Blocks 95% of prompt injections. Full OWASP LLM Top 10 coverage.

Go looking for the command that proves any of it and you will not find one. Not on the landing page, not in the docs, not in the repository. The number is there. The way to check the number is not.

That gap is not an oversight. It is the business model, and this post is about what happens when you close it.

## The wrong number sells

Ask a vendor how good their scanner is and they will answer with recall: what fraction of the bad things it finds. It is the number that fills a slide. It is also very nearly irrelevant to whether the tool is still installed a year from now.

The number that decides that is precision, and it decides it through a sequence every engineer has lived through.

A scanner flags a line that is obviously fine. You look, you shrug, you move on, and something small happens to your relationship with the tool. Third time, someone adds a `# noqa`. Fifth time, it goes to `/dev/null` in CI with a comment nobody will read. Now you have a green dashboard, a security control in the build, and no one looking at either.

A muted scanner is worse than no scanner, because no scanner is at least honest about the coverage you have.

So here is the thing worth saying plainly, and it is counterintuitive enough that the industry has organised itself around denying it: **for adoption, a false positive costs more than a miss.**

A miss is invisible. You never meet the vulnerability the tool failed to find, so it takes nothing from you. A false positive is loud, it is in your face, and it takes the tool. Recall failures are silent. Precision failures are the ones that get you uninstalled.

Which means the incentive is to maximise the number people can see and never publish the one that matters. That is what everybody does, and it is rational, and I think it is worth breaking.

## The number, and the command

Mine is 11.

**11 adjudicated false positives across 54 real repositories and 9,520 files**, counted per distinct (file, detector-id) pair, outside a documented per-repo known-capability allowlist.

```
python benchmarks/build_benign_corpus.py
```

The corpus is 54 real open-source repositories, not fixtures I wrote to be found: smolagents, CAMEL, LlamaIndex, mem0, txtai, autogen, agno, promptflow and others. The script clones them, runs every detector, and counts what survives adjudication. 380 confirmed true positives are excluded under the documented methodology, so they cannot quietly flatter the result.

Eleven was not free, and I did not get there by making the detectors timid. I got there by opening every false positive and fixing what produced it. An `execute` keyword that over-matched. A bare substring that fired on any FastAPI or Flask server. A database verb matching inside a docstring. Each of those was a rule that was technically correct and practically noise, and cutting them is the only reason a clean scan means anything.

## Now the number that cuts the other way

Eleven false positives across 54 repositories sounds excellent. Print it alone and it is misleading, so here is what that corpus cannot tell you.

On a deliberately broader 81-repo population, precision is **20.5 to 31.5%** (n=73 clean-holdout adjudicated, 95% CI 12.9 to 42.9%).

Those two numbers are both true and they describe different questions. The first asks whether I fire on code that is known to be fine. The second asks what fraction of everything I say is worth your time on a population I did not curate. The second is the harder question and the answer is not flattering.

There was an earlier figure of 58%. It was computed over the same adjudication labels used to build the precision filters, which is training on the test set. It is withdrawn. I am telling you about a number I deleted because the deletion is the point: if the only numbers that ever survive contact with your methodology are the good ones, you do not have a methodology.

## A low false-positive count is a red flag

You should treat mine as one. `cat /dev/null` has never produced a false positive either.

The only thing that makes a precision claim mean anything is recall printed beside it, so:

**76% recall. 38 of 50 distinct vulnerabilities across 10 classes. A 24% false-negative rate. 86%, or 19 of 22, on the real third-party cases.**

```
python benchmarks/recall_corpus.py
```

The recall corpus is 50 distinct vulnerable agents: 22 real cases with provenance and CVEs in a manifest, plus 28 labelled constructed ones. Per class, including where I am weak and where I am blind:

| Vuln class | Recall | Note |
|---|---|---|
| SQL / CQL injection | 100% | |
| Command injection | 100% | |
| eval / exec RCE | 100% | |
| CORS / no-auth | 100% | |
| Lethal trifecta (exfil edge) | 100% | on labelled cases |
| Insecure deserialization | 100% | via cross-function/intra-class taint |
| Container escape | ~80% | resolves docker commands built through a variable |
| SSRF | 17% | deliberately conservative: fires only when tainted data forms the URL host |
| Path traversal | 0% | detector built, sound, unit-tested, switched off on purpose |

## The zero I am proudest of

Look at the last row again. Zero percent. Not because I could not build it.

I did build it. It works. It has unit tests. It catches real bugs.

It is not registered, and it will not be, because the benign corpus is full of legitimate file-handling tools that are byte-identical to the vulnerable ones without runtime context. Turning it on raises recall on the slide and breaks the precision result in your repository. So it sits in the tree, switched off, and the class it covers reads 0%.

That is the whole argument for precision over recall, made once, with something that cost me. It is easy to say you value precision. It is different to publish a zero you could have made a number.

SSRF at 17% is the same trade, smaller. That detector fires only when tainted data actually forms the URL host, so it stays quiet instead of flagging every outbound request in your codebase.

## Why almost nobody does this

Not dishonesty. Two much more ordinary reasons.

It is expensive. A reproducible benchmark is infrastructure: a corpus of real repositories, a labelling methodology, a script that regenerates on every commit, and all of it staying green while the detectors keep moving underneath. That is permanent work with no demo payoff.

And it is dangerous. The moment you publish the command, the number stops being yours. A hostile reader runs it. If your real false-positive rate is 12% and your marketing says "low false positives", you have handed every skeptic a thirty-second disproof. Most tools cannot survive that, so they do not offer it, and the absence of a rerun command is itself information about the number.

There is a third reason and it is the one that actually bites. Publishing the command forces you to publish the methodology: what counts as a false positive, what is excluded, which corpus, how adjudication works. Once that is public you can no longer improve the number quietly by moving a definition. The discipline is the product. The number is just its receipt.

## What this does not buy

It does not make me right.

54 repositories are a proxy for the population of real agent codebases. They are not that population. Precision at real user scale is something I can only earn from real users, and I have not earned it. The recall figure will move as detectors change, and when it moves the command will show which direction it went, including the wrong one.

What it buys is narrower and it is the only thing security tooling genuinely runs on: a claim you can check without trusting the person making it. You do not have to believe eleven. You can run `build_benign_corpus.py` and get eleven, or you can run it and find the twelfth one I missed.

The second outcome is worth more to me than the first, and it is the ask.

```
pip install lucin && lucin scan ./your-agent/
```

MIT licensed. Both commands are committed. The 24% I miss is written down by name.

---

*Sources: [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/). Benchmark methodology and both commands are in the repository. All figures verified against DEFINITION_OF_DONE.md, 2026-07-29.*
