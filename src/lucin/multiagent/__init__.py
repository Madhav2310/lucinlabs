"""Multi-agent security — identity, cascade, and memory integrity.

Blueprint §6.4, Phase 5:
  - Inter-agent comms authentication (spoofed-agent detection)
  - Cascading-failure / worm-R₀ monitoring across the cluster graph
  - Runtime memory/RAG-store poisoning integrity monitoring

These are the zero-competitor gaps per the competitive analysis.
"""
from lucin.multiagent.cascade import (
    AgentGraph,
    CascadeDetector,
    CascadeReport,
    CrossAgentTrifecta,
    query_cross_agent_trifecta,
)
from lucin.multiagent.identity import (
    AgentIdentity,
    IdentityRegistry,
    SignedMessage,
    sign_message,
    verify_message,
)
from lucin.multiagent.memory_integrity import (
    DocumentRecord,
    IntegrityReport,
    MemoryIntegrityMonitor,
    PendingChange,
)

__all__ = [
    "AgentIdentity", "SignedMessage", "IdentityRegistry",
    "sign_message", "verify_message",
    "AgentGraph", "CascadeDetector", "CascadeReport",
    "CrossAgentTrifecta", "query_cross_agent_trifecta",
    "MemoryIntegrityMonitor", "IntegrityReport", "DocumentRecord", "PendingChange",
]
