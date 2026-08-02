"""AG-013: Memory and RAG Poisoning Risk Assessment.

OWASP Agentic AI #3: Memory Poisoning — corrupting an agent's long-term
memory store to persistently alter its behavior across sessions.

Unlike prompt injection (which resets when the context clears), memory
poisoning is PERSISTENT. Once an attacker corrupts the memory/RAG:
- Every future session is affected
- The corruption is invisible to users
- It survives restarts, redeployments, and context resets
- It can propagate to other agents that share the memory

This detector analyzes agent code for memory poisoning RISK FACTORS:
1. Does the agent persist state between sessions?
2. Can untrusted user input flow into persistent storage?
3. Is there validation/sanitization on memory writes?
4. Is the memory shared across users or agents?
5. Is there a mechanism to detect or rollback corruption?

Real-world basis:
- Agents of Chaos (arXiv:2602.20021): agents maintained corrupted state
- ChatGPT memory manipulation via indirect prompt injection (2024)
- RAG poisoning via malicious document injection (academic, 2024-2025)
- OWASP Agentic AI Top 10 lists this as #3 risk
"""

import ast
import re
from pathlib import Path

from lucin.models import Agent, Finding, Severity, Tool


# Patterns indicating persistent memory/state
MEMORY_INDICATORS = {
    "code_patterns": [
        # LangChain/LangGraph memory
        r"ConversationBufferMemory",
        r"ConversationSummaryMemory",
        r"VectorStoreRetrieverMemory",
        r"ChatMessageHistory",
        r"RedisChatMessageHistory",
        r"PostgresChatMessageHistory",
        r"FileChatMessageHistory",
        r"MongoDBChatMessageHistory",
        r"MemorySaver",
        r"SqliteSaver",
        r"PostgresSaver",
        # Vector stores (RAG)
        r"Chroma",
        r"Pinecone",
        r"Weaviate",
        r"Qdrant",
        r"Milvus",
        r"FAISS",
        r"PGVector",
        r"chromadb",
        r"pinecone",
        # Generic persistence
        r"add_documents",
        r"add_texts",
        r"upsert",
        r"persist",
        r"save_context",
        r"add_memory",
        r"store_memory",
        r"update_memory",
        # CrewAI memory
        r"memory\s*=\s*True",
        r"long_term_memory",
        r"short_term_memory",
        r"entity_memory",
    ],
    "config_patterns": [
        r"\"memory\"",
        r"\"vector_store\"",
        r"\"rag\"",
        r"\"retrieval\"",
        r"\"persistent\"",
        r"\"knowledge_base\"",
    ],
}

# Patterns indicating input flows into memory without validation
UNSAFE_MEMORY_WRITE_PATTERNS = [
    # Direct user input → memory store
    r"add_documents\([^)]*user",
    r"add_texts\([^)]*input",
    r"upsert\([^)]*message",
    r"save_context\(",  # Usually saves raw user input + AI output
    # Loading external data into RAG without sanitization
    r"DirectoryLoader\(",
    r"WebBaseLoader\(",
    r"UnstructuredURLLoader\(",
    r"ArxivLoader\(",
    r"WikipediaLoader\(",
    r"GitLoader\(",
    r"S3FileLoader\(",
    r"RecursiveUrlLoader\(",
    # File-based memory (writable by other processes)
    r"FileChatMessageHistory\(",
    r"\.json\"|\.jsonl\"",
]

# Patterns indicating retrieval-stage filtering (defense against poisoning)
RETRIEVAL_FILTER_PATTERNS = [
    r"filter",
    r"rerank",
    r"score_threshold",
    r"relevance_score",
    r"ContentFilter",
    r"post_retrieval",
    r"chunk_filter",
    r"TrustFilter",
    r"RAGDefender",
    r"adversarial_filter",
]

# Patterns indicating RAG content is injected into system prompt (highest risk)
SYSTEM_PROMPT_INJECTION_PATTERNS = [
    r"system.*{.*context",
    r"system.*{.*retrieved",
    r"SystemMessage.*context",
    r"system_prompt.*=.*f['\"].*{",
    r"role.*system.*content.*{",
]

# Patterns indicating memory protection mechanisms
MEMORY_PROTECTION_PATTERNS = [
    r"sanitize",
    r"validate",
    r"filter",
    r"clean",
    r"strip",
    r"escape",
    r"ContentFilter",
    r"InputValidator",
    r"memory_guard",
    r"read_only",
    r"immutable",
    r"checksum",
    r"integrity",
    r"rollback",
    r"snapshot",
    r"versioning",
]


def detect_memory_poisoning(agent: Agent) -> list[Finding]:
    """Detect memory/RAG poisoning risk factors.

    DISABLED in Phase 0. The detection logic has a coin-flip FP problem:
    - `save_context` is both a "memory match" AND an "unsafe write" for any
      LangChain ConversationBufferMemory — a completely benign, common pattern.
    - `_is_shared_memory` fires when memory exists but there is no `user_id`,
      flagging all local single-user scripts as "shared memory."
    Verified: a clean single-user ConversationBufferMemory script triggers HIGH.
    This detector needs a real benign corpus to tune against before it ships.
    Re-enable in Phase 5 (multi-agent & memory integrity — THE_BLUEPRINT §6.4).
    """
    return []  # disabled until rebuilt with real FP measurement

    findings = []  # noqa: unreachable — kept as scaffold for Phase 5

    # Collect all source files
    source_files = _get_source_files(agent)

    for filepath in source_files:
        path = Path(filepath)
        if not path.exists():
            continue

        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        # Step 1: Does this agent have persistent memory?
        memory_matches = _find_memory_usage(content)
        if not memory_matches:
            continue  # No memory = no poisoning risk from this file

        # Step 2: Can untrusted data flow into memory?
        unsafe_writes = _find_unsafe_memory_writes(content)

        # Step 3: Are there protection mechanisms?
        has_protection = _has_memory_protection(content)

        # Step 4: Is memory shared across users?
        shared_memory = _is_shared_memory(content)

        # Generate findings based on risk assessment
        if memory_matches and unsafe_writes and not has_protection:
            # Critical: memory exists + untrusted writes + no protection
            findings.append(Finding(
                id="AG-013",
                title="Memory Poisoning: Unprotected Persistent State",
                severity=Severity.HIGH,
                description=(
                    f"Agent '{agent.name}' uses persistent memory ({', '.join(memory_matches[:3])}) "
                    f"with data ingestion paths ({', '.join(unsafe_writes[:2])}) "
                    f"but no validation or sanitization on memory writes.\n\n"
                    f"An attacker can inject malicious content into the agent's memory "
                    f"that persists across sessions, permanently altering its behavior."
                ),
                agent_name=agent.name,
                attack_scenario=(
                    "1. Attacker crafts input containing instructions disguised as facts\n"
                    "2. Agent stores this in its persistent memory/RAG\n"
                    "3. Every future session retrieves the poisoned memory\n"
                    "4. Agent follows the injected instructions indefinitely\n\n"
                    "Unlike prompt injection, this PERSISTS across sessions and "
                    "survives context resets. The agent's long-term knowledge is corrupted."
                ),
                blast_radius=(
                    f"All future sessions for this agent are affected. "
                    f"If memory is shared across users, ALL users are affected. "
                    f"Corruption persists until manually detected and removed."
                ),
                owasp_ref="A03 - Memory Poisoning (Agentic AI Top 10)",
                fix_suggestion=(
                    "ARCHITECTURAL DEFENSES (research-verified):\n\n"
                    "1. CORDON Principle (arXiv:2605.26754, 92.4% attack reduction):\n"
                    "   → No agent capable of final synthesis may access untrusted\n"
                    "     natural-language evidence directly. Separate evidence extraction\n"
                    "     from answer synthesis into different agents with asymmetric memory.\n\n"
                    "2. Hybrid retrieval (reduces gradient-based poison from 38% to 0%):\n"
                    "   → Use BM25 + vector retrieval together, not vector alone.\n"
                    "     Gradient-optimized poisons target the vector space but fail\n"
                    "     against keyword-based retrieval.\n\n"
                    "3. Retrieval-stage filtering:\n"
                    "   → Add a classifier BETWEEN retrieval and context injection\n"
                    "   → Score each retrieved chunk for adversarial content before\n"
                    "     passing to the LLM. Block chunks with injection indicators.\n\n"
                    "4. Input sanitization + integrity monitoring:\n"
                    "   → Strip instruction-like patterns before storage\n"
                    "   → Periodic integrity checksums on vector store\n"
                    "   → Snapshot and rollback capability\n\n"
                    "5. Memory isolation:\n"
                    "   → User-contributed memory MUST NOT enter system-prompt context\n"
                    "   → Per-user namespaces in vector store\n"
                    "   → Read-only knowledge bases for critical system context"
                ),
                source_file=filepath,
            ))

        elif memory_matches and not has_protection:
            # Medium: memory exists without protection (even if writes aren't obviously unsafe)
            findings.append(Finding(
                id="AG-013",
                title="Memory Poisoning: No Protection on Persistent State",
                severity=Severity.MEDIUM,
                description=(
                    f"Agent '{agent.name}' uses persistent memory ({', '.join(memory_matches[:3])}) "
                    f"without detectable validation, sanitization, or integrity checks on stored data.\n\n"
                    f"While no obvious untrusted write path was detected, the absence of "
                    f"protection means any future code change that writes user data to memory "
                    f"would create a poisoning vector."
                ),
                agent_name=agent.name,
                attack_scenario=(
                    "Memory stores without protection are vulnerable to:\n"
                    "- Direct poisoning via user inputs saved as context\n"
                    "- Indirect poisoning via retrieved documents containing instructions\n"
                    "- Cross-user contamination if memory is shared"
                ),
                blast_radius="All sessions using this memory store.",
                owasp_ref="A03 - Memory Poisoning (Agentic AI Top 10)",
                fix_suggestion=(
                    "Add input validation before memory writes.\n"
                    "Add periodic integrity checks on stored content.\n"
                    "Consider read-only knowledge bases for critical system context."
                ),
                source_file=filepath,
            ))

        # Shared memory is an additional risk amplifier
        if memory_matches and shared_memory:
            findings.append(Finding(
                id="AG-013",
                title="Memory Poisoning: Shared Memory Across Users/Agents",
                severity=Severity.HIGH,
                description=(
                    f"Agent '{agent.name}' appears to share persistent memory across "
                    f"multiple users or agent instances. A single compromised session "
                    f"can poison the shared memory, affecting ALL users and agents "
                    f"that access the same store."
                ),
                agent_name=agent.name,
                attack_scenario=(
                    "1. Attacker interacts with the agent in one session\n"
                    "2. Injects content that gets stored in shared memory\n"
                    "3. Every other user's sessions now retrieve the poisoned content\n"
                    "4. One attacker compromises ALL users simultaneously"
                ),
                blast_radius="ALL users and agents sharing this memory store.",
                owasp_ref="A03 - Memory Poisoning (Agentic AI Top 10)",
                fix_suggestion=(
                    "1. Isolate memory per user (separate namespaces/collections)\n"
                    "2. Use per-user access controls on the memory store\n"
                    "3. Never allow user-contributed content to enter shared system memory\n"
                    "4. If sharing is required, use append-only + review workflow"
                ),
                source_file=filepath,
            ))

        # Step 5: Check for absence of retrieval-stage filtering
        has_retrieval_filter = any(
            re.search(p, content, re.IGNORECASE) for p in RETRIEVAL_FILTER_PATTERNS
        )
        if memory_matches and not has_retrieval_filter:
            findings.append(Finding(
                id="AG-013",
                title="Memory Poisoning: No Retrieval-Stage Filtering",
                severity=Severity.MEDIUM,
                description=(
                    f"Agent '{agent.name}' uses RAG/memory retrieval but has no "
                    f"post-retrieval filtering or scoring. Retrieved chunks are passed "
                    f"directly to the LLM without checking for adversarial content.\n\n"
                    f"A retrieval-stage filter (classifier between retrieval and LLM) "
                    f"is a key defense against poisoned embeddings."
                ),
                agent_name=agent.name,
                attack_scenario=(
                    "Poisoned documents pass through retrieval unfiltered. "
                    "The LLM receives adversarial content as trusted context."
                ),
                blast_radius="All queries that retrieve poisoned chunks.",
                owasp_ref="A03 - Memory Poisoning (Agentic AI Top 10)",
                fix_suggestion=(
                    "Add post-retrieval filtering:\n"
                    "  → Score retrieved chunks for adversarial content before passing to LLM\n"
                    "  → Use a lightweight classifier (PromptGuard 2) on retrieved text\n"
                    "  → Set relevance_score_threshold to reject low-quality matches\n"
                    "  → Reference: RAGDefender pattern"
                ),
                source_file=filepath,
            ))

        # Step 6: Check if RAG content enters system-prompt position (highest risk)
        system_prompt_injection = any(
            re.search(p, content) for p in SYSTEM_PROMPT_INJECTION_PATTERNS
        )
        if memory_matches and system_prompt_injection:
            findings.append(Finding(
                id="AG-013",
                title="Memory Poisoning: RAG Content in System Prompt Position",
                severity=Severity.HIGH,
                description=(
                    f"Agent '{agent.name}' injects retrieved/memory content into the "
                    f"SYSTEM PROMPT position. Content in system prompt has the highest "
                    f"influence on agent behavior — poisoned content here is maximally effective.\n\n"
                    f"Content should enter as USER messages or ASSISTANT context, not as system instructions."
                ),
                agent_name=agent.name,
                attack_scenario=(
                    "1. Attacker poisons a document in the vector store\n"
                    "2. Poisoned text is retrieved and inserted into SYSTEM prompt\n"
                    "3. LLM treats poisoned content as HIGH-AUTHORITY instructions\n"
                    "4. Attack has maximum effectiveness because system > user in priority"
                ),
                blast_radius="Maximum — system-prompt-level control over agent behavior.",
                owasp_ref="A03 - Memory Poisoning (Agentic AI Top 10)",
                fix_suggestion=(
                    "NEVER inject retrieved content into the system prompt.\n"
                    "  → Use HumanMessage or dedicated 'context' role instead\n"
                    "  → Keep system prompt STATIC and under developer control\n"
                    "  → Retrieved content should be clearly delineated from instructions\n"
                    "  → Reference: CORDON Principle (arXiv:2605.26754)"
                ),
                source_file=filepath,
            ))

    return findings


def _get_source_files(agent: Agent) -> set[str]:
    """Get all source files associated with an agent."""
    files = set()
    if agent.source_file:
        files.add(agent.source_file)
        # Also check other Python files in the same directory
        source_dir = Path(agent.source_file).parent
        if source_dir.exists():
            for py_file in source_dir.rglob("*.py"):
                files.add(str(py_file))
    for tool in agent.tools:
        if tool.source_file:
            files.add(tool.source_file)
    return files


def _find_memory_usage(content: str) -> list[str]:
    """Find patterns indicating persistent memory usage."""
    matches = []
    for pattern in MEMORY_INDICATORS["code_patterns"]:
        if re.search(pattern, content):
            # Clean the pattern for display
            clean = pattern.replace(r"\s*=\s*", "=").replace(r"\(", "(")
            matches.append(clean)
    for pattern in MEMORY_INDICATORS["config_patterns"]:
        if re.search(pattern, content):
            matches.append(pattern.strip('"').strip("\\"))
    return matches


def _find_unsafe_memory_writes(content: str) -> list[str]:
    """Find patterns indicating data flows into memory without validation."""
    matches = []
    for pattern in UNSAFE_MEMORY_WRITE_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            # Extract a readable version
            clean = pattern.replace(r"\(", "(").replace(r"[^)]*", "...")
            matches.append(clean)
    return matches


def _has_memory_protection(content: str) -> bool:
    """Check if there are any memory protection mechanisms in actual CODE.

    Important: We strip comments and docstrings before checking,
    because a comment saying "no validation" shouldn't count as
    having validation.
    """
    # Strip comments and docstrings to only analyze actual code
    code_only = _strip_comments_and_docstrings(content).lower()

    # Need at least 2 protection indicators in CODE to consider it "protected"
    protection_count = sum(
        1 for pattern in MEMORY_PROTECTION_PATTERNS
        if re.search(pattern, code_only)
    )
    return protection_count >= 2


def _strip_comments_and_docstrings(source: str) -> str:
    """Remove comments and docstrings from Python source, leaving only code."""
    lines = []
    in_docstring = False
    docstring_char = None

    for line in source.splitlines():
        stripped = line.strip()

        # Handle triple-quote docstrings
        if not in_docstring:
            if stripped.startswith('"""') or stripped.startswith("'''"):
                docstring_char = stripped[:3]
                # Check if it closes on the same line
                if stripped.count(docstring_char) >= 2 and len(stripped) > 3:
                    continue  # Single-line docstring, skip entirely
                in_docstring = True
                continue
        else:
            if docstring_char and docstring_char in stripped:
                in_docstring = False
            continue

        # Skip comment-only lines
        if stripped.startswith('#'):
            continue

        # Remove inline comments (rough but good enough)
        code_part = line.split('#')[0] if '#' in line else line
        lines.append(code_part)

    return '\n'.join(lines)


def _is_shared_memory(content: str) -> bool:
    """Detect if memory is shared across users/agents."""
    shared_indicators = [
        # Shared database connections without user scoping
        r"collection_name\s*=\s*['\"][^'\"]*['\"]",  # Single collection for all
        r"namespace\s*=\s*['\"](?:default|shared|global)",
        # No user_id in memory key
        r"session_id\s*=\s*['\"](?:default|global|shared)",
        # Explicit sharing
        r"shared_memory",
        r"global_memory",
        r"team_memory",
    ]

    # Also check for ABSENCE of user-scoping
    has_user_scoping = bool(re.search(
        r"user_id|user\.id|session_id|thread_id|configurable.*thread",
        content
    ))

    has_shared_indicator = any(
        re.search(p, content, re.IGNORECASE)
        for p in shared_indicators
    )

    # Shared if: explicit sharing indicator OR (has memory but no user scoping)
    has_memory = bool(_find_memory_usage(content))
    return has_shared_indicator or (has_memory and not has_user_scoping)
