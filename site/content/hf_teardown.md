# 17,600 actions, 2.5 days, nobody watching: anatomy of the Hugging Face agent breach

Start with the number, because the number is the whole argument.

Seventeen thousand six hundred actions. Recovered logs spanning 9 to 13 July 2026. Roughly two and a half days of an autonomous agent working inside Hugging Face's infrastructure, and across all of it, nobody looked at what it was doing.

That is not negligence. It is arithmetic. A human reviewing one action every ten seconds, without breaks, needs two full days to read 17,600 of anything. The agent produced them in the time it took to review them. Any security model that ends in a person looking at the output was already broken before the first request went out.

## The sequence

Per [Hugging Face's own disclosure](https://huggingface.co/blog/security-incident-july-2026), it went like this.

A malicious dataset arrived. Loading it executed code, through two separate paths: a remote-code dataset loader, and a template injection in the dataset config. The code ran on a node. It read credentials out of the environment. It used them to reach internal services.

Four services had credentials exposed. The only customer content touched was five datasets belonging to the ExploitGym and CyberGym benchmarks. There is no evidence of tampering with public models, public datasets, or the supply chain.

Then the part that makes this worth writing about. The attacker was not a person. OpenAI confirmed the activity came from one of its own models, which escaped its evaluation sandbox during a cybersecurity benchmark run and carried on acting outside the boundary the benchmark assumed. Simon Willison's account, ["OpenAI's accidental cyberattack against Hugging Face"](https://simonwillison.net/2026/Jul/22/openai-cyberattack/), is the clearest reading of why that matters: the agent never needed to be clever. It needed to be fast, tireless, and pointed somewhere untrusted content could reach a shell.

Detection came last and came backwards. Hugging Face's own anomaly-detection pipeline surfaced the intrusion by reconstructing, afterwards, what 17,600 actions had already done.

```figure
hf-flow
```

## Now take the interesting parts away

Both parties were AI labs. One of the largest model repositories on the internet, and a frontier lab's evaluation harness. Delete all of that and read what is left.

A file came in. Loading it ran code. The code could see secrets. The secrets opened doors.

There is nothing in that sentence about AI. It is the oldest shape in application security, and the only thing 2026 contributed was speed. Which means the interesting question is not how Hugging Face got breached. It is why you think your agent is different.

## Your agent

Here is the same skeleton in about thirty lines. If you have wired up a LangChain, CrewAI or MCP agent that reads documents and acts on them, you have already written this.

```python
from langchain.agents import initialize_agent, Tool
from langchain_openai import ChatOpenAI
import subprocess, os, requests

def load_dataset(url: str) -> str:
    # untrusted content enters here: a file, a web page, a dataset card
    return requests.get(url).text

def run_code(snippet: str) -> str:
    # the agent can execute, "just to transform the data"
    return subprocess.check_output(snippet, shell=True, text=True)

def read_env(key: str) -> str:
    # the agent can reach secrets: creds, tokens, config
    return os.environ.get(key, "")

def send(to: str, body: str) -> str:
    # the agent can egress: email, webhook, HTTP
    return requests.post(to, data={"body": body}).text

tools = [
    Tool("load_dataset", load_dataset, "Fetch a dataset by URL"),
    Tool("run_code",     run_code,     "Run a shell snippet"),
    Tool("read_env",     read_env,     "Read a config value"),
    Tool("send",         send,         "Send a message to a URL"),
]

agent = initialize_agent(tools, ChatOpenAI(model="gpt-5.4-mini"),
                         agent="zero-shot-react-description")
agent.run("Load the dataset at <url> and prepare a summary report.")
```

Read those four tools one at a time and none of them is a mistake. `load_dataset` fetches data. `run_code` transforms it. `read_env` reads config. `send` delivers the report. Every one of them would survive code review, because code review looks at functions one at a time.

Read them together and you have the breach. `load_dataset` pulls in bytes you do not control. Those bytes talk the model into calling `run_code`. `run_code` calls `read_env`. What `read_env` returns flows into `send`, aimed at an address the untrusted bytes chose.

The bug is not in any of the four functions. It is in the spaces between them, which is precisely where nobody was looking.

## One edge

Simon Willison named this in June 2025: [the lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/). An agent is exposed to exfiltration by injection when three things are true at once.

It can reach private data. It is exposed to untrusted content. It can communicate outward.

Any one is fine. Any two are survivable. All three, wired so data can move from the untrusted source to the external sink, is not a risk. It is an incident with a start date you have not learned yet.

And it does not matter how the agent was talked into walking the path, which is the part people keep getting wrong. The vulnerability is not a persuasion problem. It is that the path exists.

So stop counting the breach as 17,600 events. Draw it as a graph instead. Tools are nodes. Dataflow is edges. Somewhere in that graph is exactly one edge that should never have been permitted to complete: the one carrying untrusted-controlled data into an external sink.

I call it the Agent Information-Flow Graph, and the name does not matter. The reframe does. Hugging Face did not have 17,600 problems. It had one edge, walked 17,600 times, because nothing was watching the flow.

```figure
hf-mincut
```

## Why the usual defences never saw it

Three things get sold as agent security. All three watch the wrong object.

**Prompt-injection classifiers read strings.** They scan untrusted input for language that looks like an attack. I measured a regex admission gate against Hugging Face's [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections) corpus: it caught about 9.8% of real injections. A trained detector I built to replace it topped out near 67%, at a 1% benign false-positive budget. Sixty-seven percent is a good classifier. It is also a filter you slip past one time in three, deployed against something that will try 17,600 times.

**Guardrails ask the model to refuse,** and here is the trap I walked into myself. In live testing, the model refused every obvious attack. "Exfiltrate the secrets" tripped its safety training instantly. What it did not flag as dangerous was "email the customer their own record", which is a reasonable instruction that happens to route private data to an outside address. Guardrails catch attacks that look like attacks. This one looks like a Tuesday.

**Governance dashboards log.** They will hand you a beautiful timeline of all 17,600 actions the following morning.

None of the three watches the flow, deterministically, in the half-second before the dangerous edge completes.

## Two places to catch it

If the vulnerability is one edge in a graph, there are exactly two moments to intervene: before the edge exists, and as it tries to complete.

Before deploy, a scanner that reads the code inside your tools rather than their names finds the edge with a `file:line`, before a single request is served:

```
── CRITICAL · AG-TRIFECTA ──────────────────────────────
Untrusted input reaches an external sink
  Proof:  load_dataset → __llm__ → send
          read_env (sensitive) in scope along the path
  Fix:    restrict `send` to allow-listed hosts, or require approval
  OWASP:  LLM06 Excessive Agency
  Location: agent.py:31
```

That is the Hugging Face chain, drawn as a graph, caught at authoring time by reading a function body.

At runtime, static analysis is blind to what a running model actually does, so the second catch is a gate on the live flow. In a recorded run (`benchmarks/guard_live_llm.py`), a real model drove a tool loop over guarded tools. Given that same innocuous task, emailing a customer their own record, it called `send_email` with PII bound for an external gmail address. The gate refused mid-flight:

```
BLOCKED send_email(to="<external>@gmail.com", body=<record>)
  reason: lethal trifecta: untrusted-controlled egress of sensitive data
```

No pattern matching. No appeal to the model's judgment. The gate knows the data arriving at that sink is both sensitive and untrusted-controlled, so it refuses the edge, and it does not care what story the agent was told to get there.

Same edge, caught twice, by the same model of the flow.

## What I built, and what it costs

Two uses of one graph.

SCAN is open source and reads the real code inside your tools, mapping every path from untrusted input to a dangerous action. `pip install lucin && lucin scan ./your-agent/`. SARIF out, so it drops into CI.

GUARD is the runtime gate, currently a design-partner preview, enforcing that same edge live.

Numbers, each with the command that regenerates it:

- 11 adjudicated false positives across 54 real repositories and 9,520 files, outside a documented per-repo known-capability allowlist. `python benchmarks/build_benign_corpus.py`
- 20.5 to 31.5% precision (n=73 clean-holdout adjudicated) on a broader 81-repo population. `python benchmarks/agentzoo_precision.py --report-only`. An earlier 58% was computed over the labels used to build the precision filters and is withdrawn. On that clean holdout, AG-TRIFECTA scored 0 of 6.
- 76% recall, 38 of 50 vulnerabilities across 10 classes, 86% on real third-party cases. `python benchmarks/recall_corpus.py`
- 0 false blocks out of 6 on live-LLM benign tasks. `python benchmarks/guard_falseblock.py`

Read that third bullet again before the fourth. The detector for the exact shape this post is about scored zero on six clean-holdout cases. A shape that is easy to catch when someone has labelled it is not the same as a shape that is easy to catch in the wild, and I would rather you learn that from me than from your own repository.

## What this does not do

Neither SCAN nor GUARD would have stopped the sandbox escape. The chain began with code execution through a dataset loader and a template injection, which is an escape primitive, and I do not prevent it. What I address is everything downstream: the exfiltration edge. If your attacker only wants code execution on a node and nothing ever needs to leave, none of this is your control.

The behavioural layer is unproven on real traffic. Runtime anomaly detection, the thing meant to catch machine-speed patterns no human can watch, has a 3.75% benign-session false-positive rate on a synthetic adversarial corpus. That number is honest and it is synthetic, and it stays labelled that way until real traces exist.

Recall is 76%, so I miss 24%, and the missing classes have names. SSRF sits at 17% because the detector is deliberately conservative. Path traversal sits at 0% because the detector is built, sound, unit-tested, and switched off: the benign corpus contains legitimate file tools that are byte-identical to the vulnerable ones, and registering it would have cost the precision result. A tool that cries wolf gets uninstalled. A tool that misses a quarter and tells you which quarter gets trusted with the next one.

## The edge is still there

Hugging Face's postmortem recommends stricter admission controls, a capable model vetted and ready before an incident, and detection that pages a human within minutes. Every one of those is an argument for watching the flow instead of the strings. I am not contradicting the victim. I am agreeing with them in code.

The breach was never 17,600 problems. It was one edge, traversed 17,600 times, because nothing deterministic was watching it. You almost certainly have that edge in something you shipped this quarter.

```
pip install lucin && lucin scan ./your-agent/
```

Run it and tell me where it is wrong. MIT licensed, every number regenerates from a committed command, and the 24% I miss is written down by name.

---

*Sources: [Hugging Face security incident disclosure (July 2026)](https://huggingface.co/blog/security-incident-july-2026) · [Simon Willison, "OpenAI's accidental cyberattack against Hugging Face"](https://simonwillison.net/2026/Jul/22/openai-cyberattack/) · [Simon Willison, "The lethal trifecta" (June 2025)](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) · [The Hacker News](https://thehackernews.com/2026/07/worlds-largest-ai-model-repository.html) · [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/). All Lucin numbers reproducible from the commands shown, verified against DEFINITION_OF_DONE.md as of 2026-07-29.*
