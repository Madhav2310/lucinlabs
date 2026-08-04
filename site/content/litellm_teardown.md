# The attack chain started by compromising a security scanner

*What the LiteLLM supply-chain compromise means for tools like this one*

On 24 March 2026 at 10:39 UTC, two versions of `litellm` appeared on PyPI that no maintainer had tagged, no CI job had built, and no release workflow had produced.

Versions 1.82.7 and 1.82.8 went up directly, past the pipeline. There is no matching tag in the GitHub repository, because nothing in the repository was involved. For roughly forty minutes they were the newest release of a library PyPI serves about 95 million times a month, sitting underneath most of the agent frameworks, MCP servers and orchestration tools currently in production.

Inside the wheel was a file called `litellm_init.pth`.

A `.pth` file is not a module. It is a line of code the interpreter runs at startup, before your program begins, every time any Python process starts in that environment. You do not have to import `litellm`. You do not have to call it. If it is installed, the payload runs.

The payload had three stages: a credential harvester, a Kubernetes lateral-movement toolkit, and a persistent backdoor. It took cloud credentials, SSH keys and Kubernetes secrets.

PyPI quarantined the package. The last known-clean release is 1.82.6.

That is the incident, and it is the least interesting part. What is worth several thousand words is how the attacker got the keys.

## They came in through the security scanner

The threat actor, tracked as TeamPCP, did not phish a maintainer. They did not brute-force a PyPI password.

They took the publishing credentials by first compromising **Trivy**, the open-source vulnerability scanner running inside LiteLLM's own CI/CD pipeline.

Laid out as a timeline, the campaign is patient and deliberate:

- **19 March.** Trivy, Aqua Security's scanner, is compromised.
- **21 March.** Checkmarx's AST GitHub Actions are compromised.
- **24 March.** LiteLLM 1.82.7 and 1.82.8 go to PyPI with the backdoor.
- **27 March.** `telnyx` 4.87.1 and 4.87.2 are backdoored.

CanisterWorm was moving through npm alongside it. Datadog's researchers tied the threads together.

Read the first two entries again. The route into the AI supply chain ran through the security tooling. Not around it. Through it.

That works for a structural reason rather than an accidental one, and it is worth spelling out. Think about what a scanner needs in order to do its job in your pipeline. It runs on every commit, so it runs with your CI's privileges. It reads your entire source tree, including files your application never touches. It frequently needs registry credentials to resolve dependencies. It often needs a token to write results back to your pull requests.

And nobody audits it, because auditing the security tool feels like the thing the security tool was supposed to do for you.

A scanner is a privileged process that reads everything and that no one questions. If you sat down to design a target, you would design that.

## Which brings me to the uncomfortable part

I build a security scanner.

It is called Lucin. It reads the code inside AI agents' tools and traces paths from untrusted input to dangerous actions. Install it in your CI and it will run on every commit, with your CI's privileges, across your whole source tree.

Every property I just described as making a perfect target is a property of my product.

So I am not going to write this as a story about someone else's failure. The useful thing I can do is state which structural choices make a scanner a smaller target, and then be held to them.

**It should run locally, with no service.** `lucin scan .` finishes in under a second on a typical agent and needs no API key, no account, and no network call to function. Your code does not leave your machine. There is no server holding your source, so there is no server whose compromise reaches your source. I cannot take much credit for this, since it falls out of doing static analysis instead of selling a platform, but it is the property that matters here.

**It should be readable.** The whole thing is MIT-licensed on GitHub, and the detectors are pure functions: `Agent → list[Finding]`. If you want to know what a rule does, you can read it in a couple of minutes. That is the honest answer to "why should I trust this binary." Do not trust it. Read it. The offer only means anything because the code is small enough to accept.

**It should be pinnable, and you should pin it.** Every version is tagged and published. The GitHub Action takes an explicit `version` input. Pin it to a digest if you want. If a release of Lucin is ever compromised, an unpinned dependency is exactly how it reaches you.

**It should ask for as little as it can.** Lucin needs read access to your source. It does not need registry credentials, cloud credentials, or a token to write to your repository. In CI, findings come out as workflow annotations, which require no extra permission grant.

I know how that reads. A vendor uses an industry incident to explain why its own architecture is sound.

So here is what the argument does not cover. None of those four properties would have saved you from the LiteLLM compromise, because that attack did not come through the scanner's *design*. It came through the scanner's *release pipeline*.

My release pipeline is a GitHub Actions workflow holding a PyPI token. Which is a smaller version of precisely the thing that failed.

Being local does not fix that. Being open source does not fix that. What fixes it is pinning, provenance attestation, and you declining to extend trust you have not checked, including to me.

## What your dependency graph looks like from here

If you build agents, LiteLLM is probably in your tree, and probably not because you chose it.

It is the routing layer underneath a large number of higher-level tools. You install a framework, the framework wants a provider-agnostic gateway, and `litellm` arrives transitively. Ninety-five million downloads a month is not ninety-five million decisions. It is a small number of decisions multiplied by everything downstream of them.

That is what makes the forty-minute window less reassuring than it sounds. Forty minutes is short for a human deciding to upgrade a library. It is not short for CI. An unpinned dependency, in a build that runs on every push, on a repository with any traffic at all, resolves to whatever is newest the moment it runs. A forty-minute window catches whoever happened to be building, and "whoever happened to be building" is not a small set when the ecosystem is this large and pipelines fire this often.

Then PyPI quarantined the whole package, which broke installs for people who had done nothing wrong. That was the correct call, and it shows the second-order cost: the remediation for a compromised popular package is an outage for everybody who depends on it.

## The rule that fires on this

Lucin has a detector called `AG-FRAMEWORK-PIN`. It is small and unglamorous. It looks at how your agent's framework dependencies are specified and flags the ones that are not pinned. Severity medium. The kind of finding people close without reading.

In March 2026 that exact configuration was the delivery mechanism for a credential harvester in a library with 95 million monthly downloads.

I want to be precise about what the rule does, because overclaiming here would be worse than staying quiet.

It does not detect malicious packages. It has no threat intelligence, no reputation feed, and no knowledge of which versions are compromised. It would not have told you that 1.82.7 was backdoored.

What it does is narrower and, on the evidence of this incident, more useful than it sounds. It tells you which of your dependencies are resolved at build time rather than fixed by you, which is the same as telling you where an attacker who compromises a registry account reaches your build without ever touching your repository.

That is not a detection. It is an inventory of one specific kind of exposure, and it is the difference between "we were in the blast radius" and "we were not."

The companion rule is `AG-015`, which does the same for unpinned MCP servers. Those are a newer version of the same problem with a worse trust model: pulled by identifier at runtime, from registries with less scrutiny than PyPI, executing with whatever permissions the agent has.

```
$ lucin scan .

  MEDIUM  AG-FRAMEWORK-PIN   Unpinned agent framework version
  Location: requirements.txt:4
  Proof:    litellm (no version constraint)
  Fix:      litellm==1.82.6
```

## If you were running anything in that window

1. **Check whether 1.82.7 or 1.82.8 ever resolved in any environment,** including ephemeral CI runners. Lockfiles, CI logs, container image layers. The last clean release is 1.82.6.
2. **If either version ran anywhere, rotate.** Cloud credentials, SSH keys, Kubernetes secrets, anything readable from the environment. The payload ran at interpreter startup, so "we never called litellm" is not an exclusion.
3. **Look for the `.pth`.** `litellm_init.pth` in `site-packages` is the marker.
4. **Then pin.** Not just `litellm`, but the whole tree, with a lockfile and a hash.

## What I actually think the lesson is

The comfortable reading is that supply-chain attacks are getting more sophisticated and we all need better tooling. I do not think that is right, and I think the comfortable reading is why this keeps happening.

The attacker needed no sophistication. They needed to notice that security tools are privileged, ubiquitous and unexamined, and that a scanner's credentials are worth more than whatever the scanner is scanning. Then they walked from one to the next, four times in nine days.

The lesson is about where trust accumulates. Every tool you add to a pipeline to reduce risk is also a component whose compromise transfers to you, and security tools concentrate privilege more than most, because we grant them access precisely so they can look at everything.

That trade can still be worth making. It is not worth making unexamined.

Which means the question to ask of my scanner, and of every other one in your pipeline, is not "does it find bugs." It is: what does it need, who can publish it, what happens if that publisher is compromised, and can you read it?

I would rather you asked me those than took my word for anything.

---

**Reproduce anything in this post**

```
Scan your own agent:      pip install lucin && lucin scan .
Read every detector:      github.com/Madhav2310/lucinlabs/tree/main/src/lucin/detectors
My false-negative list:   python benchmarks/recall_corpus.py
```

*Sources:* LiteLLM's advisory ([docs.litellm.ai](https://docs.litellm.ai/blog/security-update-march-2026)) · Datadog Security Labs on the TeamPCP campaign ([securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/)) · Snyk on the Trivy pivot ([snyk.io](https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/)) · ARMO's payload analysis ([armosec.io](https://www.armosec.io/blog/litellm-supply-chain-attack-backdoor-analysis/)) · Endor Labs ([endorlabs.com](https://www.endorlabs.com/learn/teampcp-isnt-done)) · Bitsight ([bitsight.com](https://www.bitsight.com/blog/litellm-versions-1-82-7-1-82-8-supply-chain-compromise)) · Trend Micro ([trendmicro.com](https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html))
