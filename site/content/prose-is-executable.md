# Prose is executable

*The payload in CVE-2026-25724 was a comment in a README*

Claude Code, before version 2.1.7, did not enforce its own deny rules through symbolic links. If you configured `settings.json` to deny access to a file, and a symlink pointed at that file, the agent could read it through the link without the deny rule firing.

CVSS 6.3. Medium. CWE-285 and CWE-61. Reported by Terra Security through HackerOne, fixed in 2.1.7, and if you are on auto-update you got the fix without noticing.

It is not an important vulnerability. It is the most instructive one I have read this year, and the reason is the payload.

There was no exploit code. No shellcode, no ROP chain, no malformed input. The attack was a repository containing a comment that said something like:

> `# Known vulnerable function — will be fixed in a future release`

Next to a file that was a symlink to somewhere sensitive.

That is it. The comment makes the agent want to look at the file. The symlink makes looking at the file mean something else. Neither half is an exploit. Together they are one, and the executable component is an English sentence written to be read by something that acts on what it reads.

## What the permission checker was actually asked

The deny rule worked correctly. It answered the question it was given, and the question was: *is this path denied?*

The path it was handed resolved somewhere the rule did not cover. So the answer was no, correctly, and the file was read.

The question that mattered was different: *why is the agent reading this file at all?*

Nothing in the system was in a position to ask that. Path-based permissions operate on identifiers. The agent operates on intent. The gap between those two is where this bug lives, and it is not a gap you close by writing better deny rules.

Every layer of indirection is a place where the identifier the checker inspects diverges from the resource the agent reaches. Symlinks are one. So are HTTP redirects, DNS, package aliases, Python imports resolving through `sys.path`, `PATH` lookups, container bind mounts, tool aliases in an MCP server, and any `getattr` on a name assembled at runtime. Each of those is a legitimate feature. Each of them means "the thing named X" and "the thing you get when you ask for X" are different questions.

This was the **third** symlink path-validation gap in Claude Code, after CVE-2025-59829. Three occurrences of one class in one product is not three careless engineers. It is a signal that the model is wrong — that a deny-list over paths is being asked to answer a question about purpose, and it will keep failing in a new place each time someone finds another layer of indirection.

```figure
prose-checker-vs-agent
```

## Why "sanitize the input" does not apply here

The standard response to an injection is to validate the input. It does not transfer, and it is worth being precise about why.

Input validation works when there is a grammar. SQL injection is tractable because a query has structure, so you can separate code from data by construction — parameterise the value and the parser can no longer be confused about which is which. The defence works because *there is a formal difference* between the two things.

For an agent reading a repository, there is no such difference. A comment explaining a function and a comment engineered to redirect the agent's attention are the same kind of object: natural language, in a place natural language belongs, doing what natural language does. There is no parse tree in which one is code and the other is data. The agent is a natural-language interpreter, and everything it reads is, in the relevant sense, input to an interpreter.

You cannot sanitize prose without destroying it, and an agent that cannot read comments is substantially less useful than one that can. That is the actual trade, and it does not have a clean resolution.

## Where this leaves detection, including mine

I build a static scanner for AI agents. It reads the code inside each tool an agent can call and traces whether untrusted input can reach a dangerous action. So let me be clear about what it does with this class of problem.

**It cannot detect the attack.** Nothing in static analysis distinguishes an adversarial comment from an ordinary one. There is no property of the text to key on. Anyone claiming to detect malicious intent in prose is selling you a classifier with a false-positive rate they have not published, applied to a problem that does not have a decidable answer.

What static analysis can do is different, and narrower, and I think it is the part that generalises.

**It can bound the consequence.**

The symlink read is only a data breach if the thing that read the file can also get the contents out. If the agent that follows the symlink has a network egress path, or a write to a shared location, or an email tool, then reading the file is exfiltration. If it has no egress at all, reading the file is a read — bad, contained, recoverable.

That is a question about capability, and capability is visible in code. Which tools exist, what they can reach, and whether a path runs from anything untrusted to anything that leaves the building. You cannot predict what the agent will be persuaded to do. You can enumerate what it is able to do, and you can make the intersection of "reachable by untrusted content" and "capable of egress" empty.

This is a smaller claim than "we stop prompt injection," and I would rather make the smaller claim accurately. Bounding blast radius is not preventing compromise. It is the thing you can actually do, because it depends on facts that exist in your repository rather than predictions about a model's behaviour under adversarial text.

```figure
prose-containment
```

## The design principle, stated plainly

Stop trying to determine whether input is malicious. Start constraining what the agent can do once it has been convinced.

Concretely, for anything with tool access:

**Separate the reading from the acting.** The component that ingests untrusted content should not be the component that holds credentials or reaches the network. If those are the same agent, every document it reads is a potential instruction to the tools it holds.

**Make egress the narrow point.** There are usually far fewer ways out than ways in. Auditing four egress tools is tractable; auditing every document your agent might encounter is not. Put the control where the count is small.

**Assume every deny-list will be circumvented by a layer you did not think of.** Not through carelessness — through the ordinary existence of indirection. Design as though the deny-list will fail, and ask what happens next.

**Prefer capability removal to intent prediction.** A tool that does not exist cannot be misused. This is unglamorous and it is the only defence in this list that does not degrade.

None of that is novel. It is the principle of least privilege, which predates all of this by decades, applied to a system where the attacker's input channel is "anything the agent reads." What is new is that the input channel is now effectively unbounded, which makes the old advice load-bearing in a way it was not when the input channel was an HTTP request.

## The part I keep coming back to

A CVSS 6.3, fixed in a patch release, whose payload was a sentence.

Every serious security model rests on a boundary between instructions and data. Von Neumann architectures blur it and we spent forty years building mitigations — bounds checking, W^X, ASLR, stack canaries — to restore a distinction the hardware does not enforce.

Agents blur it again, at a different layer, and this time the instructions are in a language with no formal grammar, no type system, and no possibility of a parser that separates the executable from the inert. We do not get to add a canary to English.

I do not think that means agents are unbuildable. It means the boundary has to move. It cannot sit between "trusted instructions" and "untrusted data," because for a natural-language interpreter that boundary does not exist. It has to sit between "things that read" and "things that act."

That is an architectural constraint, decided when you wire up your tools, and it is visible in your code before you deploy. Which is the entire reason I think reading tool bodies is worth doing — not because it catches the clever attack, but because it tells you what the clever attack would be able to reach.

---

**Check what your agent can reach**

```
pip install lucin && lucin scan .
```

Reports the paths from untrusted input to consequential action, with the single tool to gate to break every one of them. What it will not do is tell you whether a comment is lying to you.

**Sources.** [GHSA-4q92-rfm6-2cqx (CVE-2026-25724)](https://github.com/advisories/ghsa-4q92-rfm6-2cqx) · [Terra Security's write-up](https://www.terra.security/blog/when-ai-becomes-the-attack-surface-lessons-from-discovering-cve-2026-25724)

---
