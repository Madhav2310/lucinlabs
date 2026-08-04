from lucin.detectors import _bound_severity_by_evidence, _require_evidence_on_unproven_agents
from lucin.models import Agent, EvidenceClass, Finding, Severity


def test_posture_findings_capped():
    f1 = Finding(
        id="AG-TEST",
        title="test",
        severity=Severity.HIGH,
        description="x",
        evidence_class=EvidenceClass.POSTURE
    )

    # Cap should drop severity to MEDIUM when there is no witness
    res = _bound_severity_by_evidence([f1])
    assert res[0].severity == Severity.MEDIUM

def test_witnessed_findings_not_capped():
    f1 = Finding(
        id="AG-TEST",
        title="test",
        severity=Severity.HIGH,
        description="x",
        evidence_class=EvidenceClass.WITNESSED,
        witness=["some proof"]
    )
    # Even if witness logic failed for some reason, WITNESSED explicitly keeps severity
    res = _bound_severity_by_evidence([f1])
    assert res[0].severity == Severity.HIGH

def test_suppression_logic():
    # Skill agents should not get posture findings
    skill_agent = Agent(name="skill_agent", framework="skill", agent_evidence=[], posture_findings_apply=False)
    f_posture = Finding(
        id="AG-TEST",
        title="test",
        severity=Severity.HIGH,
        description="x",
        evidence_class=EvidenceClass.POSTURE,
        agent_name="skill_agent"
    )

    # It should be dropped
    res = _require_evidence_on_unproven_agents([f_posture], [skill_agent])
    assert len(res) == 0

    # Unproven generic agents should not get posture findings
    unproven_agent = Agent(name="unproven", framework="generic", agent_evidence=[])
    f_posture2 = Finding(
        id="AG-TEST",
        title="test",
        severity=Severity.HIGH,
        description="x",
        evidence_class=EvidenceClass.POSTURE,
        agent_name="unproven"
    )
    res2 = _require_evidence_on_unproven_agents([f_posture2], [unproven_agent])
    assert len(res2) == 0

    # Proven generic agents SHOULD get posture findings
    proven_agent = Agent(name="proven", framework="generic", agent_evidence=["has evidence"])
    f_posture3 = Finding(
        id="AG-TEST",
        title="test",
        severity=Severity.HIGH,
        description="x",
        evidence_class=EvidenceClass.POSTURE,
        agent_name="proven"
    )
    res3 = _require_evidence_on_unproven_agents([f_posture3], [proven_agent])
    assert len(res3) == 1

    # Unproven generic agents SHOULD get witnessed findings
    f_witnessed = Finding(
        id="AG-TEST",
        title="test",
        severity=Severity.HIGH,
        description="x",
        evidence_class=EvidenceClass.WITNESSED,
        witness=["proof"],
        agent_name="unproven"
    )
    res4 = _require_evidence_on_unproven_agents([f_witnessed], [unproven_agent])
    assert len(res4) == 1
