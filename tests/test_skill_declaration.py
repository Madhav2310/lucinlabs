"""Tests for skill_declaration.py — the fixed declaration-reconciliation module.

Regression tests pinned to the three bugs found in PHASE_6_PLAN.md §2.3/§5.2.3:
wildcard laundering, dependency-implies-declared, and the dead `compatibility`
channel.
"""
from lucin.detectors.skill_declaration import WILDCARD_TOKENS, reconcile
from lucin.models import SkillCapability


def test_bare_bash_is_flagged_as_wildcard_not_a_free_pass():
    report = reconcile(
        observed_capabilities=[SkillCapability.EXEC, SkillCapability.REMOTE_FETCH, SkillCapability.DESERIALIZE],
        declared_capabilities=["bash"],
        compatibility_text="",
    )
    assert report.has_wildcard is True
    # Bare "bash" must NOT count as declaring REMOTE_FETCH or DESERIALIZE —
    # this is the exact bug: an unscoped grant used to launder everything.
    assert SkillCapability.REMOTE_FETCH in report.undeclared
    assert SkillCapability.DESERIALIZE in report.undeclared


def test_scoped_bash_declares_exec_without_being_a_wildcard():
    report = reconcile(
        observed_capabilities=[SkillCapability.EXEC],
        declared_capabilities=["bash(git:*)"],
        compatibility_text="",
    )
    assert report.has_wildcard is False
    assert SkillCapability.EXEC in report.declared_via_allowed_tools


def test_dependency_alone_does_not_count_as_declared():
    """Regression: listing `requests` in requirements.txt used to silently
    count as declaring REMOTE_FETCH. It no longer does — `reconcile` only
    looks at the two real declaration channels, not at `skill.dependencies`."""
    report = reconcile(
        observed_capabilities=[SkillCapability.REMOTE_FETCH],
        declared_capabilities=[],
        compatibility_text="",
    )
    assert SkillCapability.REMOTE_FETCH in report.undeclared
    assert SkillCapability.REMOTE_FETCH not in report.declared_via_allowed_tools


def test_compatibility_channel_now_actually_works():
    """Regression: `compatibility` used to be dead code — mentioned in the
    fix_suggestion text but never checked."""
    report = reconcile(
        observed_capabilities=[SkillCapability.REMOTE_FETCH],
        declared_capabilities=[],
        compatibility_text="Requires internet access to fetch remote data.",
    )
    assert SkillCapability.REMOTE_FETCH in report.declared_via_compatibility
    assert SkillCapability.REMOTE_FETCH not in report.undeclared


def test_wildcard_tokens_are_exact_not_substring():
    """"database" must not match the wildcard "all" as a substring accident."""
    report = reconcile(
        observed_capabilities=[SkillCapability.EXEC],
        declared_capabilities=["database"],
        compatibility_text="",
    )
    assert report.has_wildcard is False
