# We publish our misses. Here are all twelve.

*76% recall, the twelve cases that get past us, and the detector we switched off on purpose*

Every security scanner publishes a detection number. None of them publish the list of things they failed to detect, and the reason is not modesty. It is that a recall number is a claim about a set nobody can enumerate — the things you did not find — which makes it the one number in security marketing that can never be checked.

So here is ours, with the part that can be checked.

Lucin's recall is **76%**. On a held-out corpus of 50 distinct vulnerable agents across 10 vulnerability classes, it finds 38 and misses 12. Below is every miss, by name, with the reason.

```
$ python benchmarks/recall_corpus.py
```

That command regenerates this entire post. It prints the table, and it prints the false negatives, because a benchmark that only reports its wins is a slide, not a measurement.

## The number, by class

| Vulnerability class | Detected | Recall |
|---|---|---|
| path traversal | 0 / 6 | **0%** |
| SSRF | 1 / 6 | **17%** |
| container escape | 4 / 5 | 80% |
| CQL injection | 2 / 2 | 100% |
| command injection | 5 / 5 | 100% |
| CORS / unauthenticated server | 5 / 5 | 100% |
| insecure deserialization | 6 / 6 | 100% |
| RCE via eval/exec | 5 / 5 | 100% |
| secret exfiltration (lethal trifecta) | 4 / 4 | 100% |
| SQL injection | 6 / 6 | 100% |
| **Overall** | **38 / 50** | **76%** |

The corpus is 22 real third-party cases and 28 constructed ones, labelled as such in `benchmarks/recall_corpus/manifest.json`. On the real cases alone, recall is **19 / 22 = 86%**. I report the combined number as the headline because the constructed cases are the ones I control, and quoting the more flattering figure would be exactly the behaviour this post exists to argue against.

Notice the shape. It is not a uniform 76%. It is six classes at 100%, one at 80%, and two that are essentially broken. An aggregate recall number hides that completely, which is a good argument for never trusting one — including mine.

```figure
recall-bars
```

## All twelve misses

```
container_escape/real__camel_docker_interpreter   [real]         fired AG-001, expected AG-DOCKER-EXEC
path_traversal/real__agno_python_tools            [real]         no registered detector
path_traversal/constructed__read_document         [constructed]  no registered detector
path_traversal/constructed__write_report          [constructed]  no registered detector
path_traversal/constructed__load_template         [constructed]  no registered detector
path_traversal/constructed__delete_file           [constructed]  no registered detector
path_traversal/constructed__serve_static_file     [constructed]  no registered detector
ssrf/real__llamaindex_openapi_tool                [real]         detector too conservative
ssrf/constructed__url_fetcher                     [constructed]  detector too conservative
ssrf/constructed__webhook_poster                  [constructed]  detector too conservative
ssrf/constructed__image_downloader                [constructed]  detector too conservative
ssrf/constructed__urllib_proxy                    [constructed]  detector too conservative
```

Three distinct failures, and they fail for three different reasons. The interesting one is the first.

## Failure 1 — path traversal: the detector works and I switched it off

Six of the twelve misses are path traversal, and the recall is not 0% because the analysis is hard. It is 0% because there is a working, unit-tested path-traversal detector in the codebase that is **deliberately not registered.**

Here is why.

A path-traversal detector for agent tools has to flag this:

```python
@tool
def read_document(name: str) -> str:
    """Read a document from the library."""
    return open(name).read()          # tool-controlled path, no containment
```

And it has to not flag this:

```python
@tool
def read_template(name: str) -> str:
    """Load a prompt template."""
    return open(os.path.join(TEMPLATE_DIR, name)).read()
```

The second one is what a large amount of entirely reasonable code looks like. It is also exploitable if `name` is `../../../etc/passwd`, and it is not exploitable if the caller happens to validate upstream, or if `TEMPLATE_DIR` is inside a container with nothing else in it, or if the tool is only reachable by an authenticated operator.

When I ran the detector against the benign corpus — 54 real repositories, 9,520 files — it fired on patterns that were **byte-identical** to legitimate file tools. Not similar. Identical: `open(param)` and `os.path.join(base, name)`, in code where the surrounding system made them fine.

Static analysis cannot distinguish those two cases, because the distinguishing information is not in the file. It is in the deployment.

So I had a choice. Register the detector, gain roughly 12 percentage points of headline recall, and start producing findings that developers would correctly identify as noise. Or leave it out, publish 0% on a class that clearly matters, and explain why.

I chose the second, and I want to be direct about the reasoning, because "precision over recall" is the kind of phrase that sounds like a principle and is usually a rationalisation.

The reason is not that false positives are aesthetically worse. It is that a scanner's real failure mode is being switched off. The first time a tool flags a line that is obviously fine, a developer's confidence drops. By the fifth time it is piped to `/dev/null` in CI, and now there is a green check that means nothing and nobody is looking. A muted scanner is worse than no scanner, because it produces the belief that something is being checked.

A miss costs you one vulnerability. A false positive costs you the tool, and therefore every vulnerability after it.

That trade is defensible and I might still be wrong about it. The detector is in the repository if you want to read it and disagree — and if you think the right answer is to ship it behind a flag for people who would rather triage noise than miss a class entirely, say so, because that is a genuinely reasonable position and it is the change I am most likely to make.

```figure
path-traversal-ambiguity
```

## Failure 2 — SSRF: 17%, and conservative by construction

Five more misses are SSRF. The detector exists and is registered, and it fires on one case out of six, because it only fires when tainted input forms the **host** portion of a URL.

Caught:
```python
requests.get(f"https://{user_supplied}/api/data")     # taint controls the host
```

Not caught:
```python
requests.get(user_supplied)                          # taint is the whole URL
requests.get(f"https://api.internal/{user_supplied}") # taint controls the path
urllib.request.urlopen(url_from_tool_arg)            # taint via a local
```

The second group contains real vulnerabilities. `requests.get(user_supplied)` in an agent tool is an SSRF, full stop, and Lucin misses it.

The reason is the same as before, one step further along. Widening the rule to "tainted value reaches a request sink" fires on an enormous amount of legitimate code, because *fetching a URL the caller provided* is the entire purpose of a large class of tools. An agent tool named `fetch_page(url)` is supposed to fetch the URL it is given. Flagging it says nothing.

What makes SSRF exploitable in an agent is not that the URL is parameterised. It is that the URL is parameterised **and** the agent can be talked into supplying an internal one **and** the response comes back into the model's context. That is three facts, and only the first is visible in the function body.

Host-position taint is a proxy for the dangerous subset. It is a bad proxy — 17% recall says so — and it is the best one I have found that does not produce noise. The honest summary is that Lucin's SSRF coverage is close to a placeholder, and if you are relying on it, do not.

## Failure 3 — the interesting one: right answer, wrong rule

One miss is not a miss in the way the other eleven are.

```
container_escape/real__camel_docker_interpreter   fired AG-001, expected AG-DOCKER-EXEC
```

This is a real third-party case — a Docker-based code interpreter with a container-escape configuration. Lucin flagged it. It reported `AG-001, Unrestricted Shell/Exec Access`, critical severity, with the correct file and line.

The benchmark counts it as a false negative, because the expected finding was `AG-DOCKER-EXEC`, which describes the specific container-escape mechanism rather than the general shell-access problem. A user running Lucin on this code would have been warned. The benchmark still scores it as a failure.

I could have written the grader to accept any finding on the right line. That would have raised recall to 78% and made the number less meaningful, because "we flagged something here" and "we correctly identified the vulnerability class" are different claims, and only the second one tells you whether the remediation advice will be right. `AG-001` suggests sandboxing the shell. `AG-DOCKER-EXEC` suggests fixing the container configuration. Same line, different fix.

So it counts as a miss. Grading yourself strictly is cheap when the alternative is a number that means less.

## What each of these would take to fix

Not a roadmap with dates. An honest statement of what is actually required, since "we're working on it" is what everyone says.

**Path traversal** needs containment analysis: proving that a joined path cannot escape a base directory, which means modelling `os.path.realpath`, symlink resolution, and normalisation. That is tractable and it is real work. The shortcut — a flag that enables the detector for people who want the class covered and accept the noise — is a day, and is probably the right first move.

**SSRF** needs the thing Lucin does not have: whether the response flows back into model context. That is an information-flow question across function boundaries, and it runs into the same wall described below.

**The container-escape case** needs detector precedence — when both `AG-001` and `AG-DOCKER-EXEC` match, prefer the specific one. That is a small change and it is worth doing for the remediation advice, not for the number.

## The structural limit underneath all of this

The three failures share a cause, and it is worth naming because it bounds everything above.

Lucin's taint analysis is **intraprocedural** — it reasons within a single function body — plus a limited same-file, cross-function pass that resolves method-to-method flows within a class. It is not a whole-program call graph. It cannot follow a value from a function in one file into a sink in another.

That is not a design preference. The standard tool for building a Python call graph, PyCG, was not available in the environment where this was built, so the cross-function approximation is capability-based instead: classify each tool by the capabilities its code exhibits, then flag dangerous *combinations*. That catches the incident-class patterns — the lethal trifecta, the read-to-egress chains — without proving a literal path.

It works better than it sounds for the classes at 100%, because those vulnerabilities tend to be local: the injection and the sink are in the same function. It works badly for SSRF, where the dangerous fact is somewhere else entirely.

If you write agent code with heavy `getattr`, reflection, or generated tools, recall will be worse than 76% and I cannot tell you how much worse, because I have not measured it on code like that. If you have a codebase like that and are willing to let me measure, that is the single most useful thing anyone could send me right now.

## Why publish this

Two reasons, and one of them is self-interested.

The honest one: you cannot evaluate a scanner from its detection claims, because every scanner claims detection. You can evaluate one from its failures, because failures are specific and checkable. Publishing them is the only way to give you something to actually assess.

The self-interested one: the twelve cases above are the strongest argument I have. A tool that tells you it covers everything is telling you nothing. A tool that tells you SSRF coverage is 17% and close to a placeholder has told you something you can plan around — you know to add a rule to your own review, or run something else alongside it, or ignore Lucin's SSRF findings entirely.

That is worth more to you than 76% is, and it is the reason the number is on the page next to the misses instead of on its own.

If you find a thirteenth, open an issue. It goes in the corpus, and it goes in the next version of this table.

---

**Reproduce anything in this post**

```
The whole table and the miss list:  python benchmarks/recall_corpus.py
Case provenance:                    benchmarks/recall_corpus/manifest.json
The unregistered detector:          src/lucin/detectors/path_traversal.py
The registry gate:                  src/lucin/detectors/__init__.py
Scan your own agent:                pip install lucin && lucin scan .
```

---
