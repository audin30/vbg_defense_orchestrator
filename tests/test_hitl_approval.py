"""HITL containment approval: nothing remediates without a recorded human decision.

Covers the full path -- Commander queues a ContainmentApproval instead of
executing anything, approval_service.approve_containment is the only thing
that can trigger SOAR playbook execution, and rejection leaves the incident
untouched.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.agents.incident_commander_agent import incident_commander_agent
from app.agents.incident_response_agent import incident_response_agent
from app.models import (
    Alert,
    AlertSeverity,
    ApprovalStatus,
    Asset,
    CommanderContainmentReview,
    CommanderDecision,
    ContainmentApproval,
    ContainmentOutcome,
    Exposure,
    Incident,
    IncidentStatus,
    Playbook,
    PlaybookExecution,
    ResponseDecision,
    ThreatActorProfile,
    ThreatIndicator,
    Vulnerability,
)
from app.services import approval_service
from app.services.approval_service import ApprovalNotPending

NOW = datetime.now(timezone.utc)


def _asset(db, hostname, criticality=5, exposure=Exposure.INTERNET_FACING):
    a = Asset(hostname=hostname, ip_address="10.0.0.1", criticality=criticality, exposure=exposure)
    db.add(a)
    db.flush()
    return a


def _alert(db, asset, title, severity, technique_id, description="", minutes_ago=10):
    a = Alert(
        source="test", title=title, description=description, severity=severity,
        asset_id=asset.id, attack_technique_id=technique_id,
        occurred_at=NOW - timedelta(minutes=minutes_ago),
    )
    db.add(a)
    return a


def _incident(db, asset, alerts, severity=AlertSeverity.CRITICAL, confidence=1.0):
    inc = Incident(title="test incident", severity=severity, asset_id=asset.id, confidence=confidence)
    db.add(inc)
    db.flush()
    for a in alerts:
        a.incident_id = inc.id
    db.commit()
    db.refresh(inc)
    return inc


def _critical_incident_with_matching_playbook(db):
    """T1003 (credential dumping) on a critical, internet-facing, KEV-listed,
    IOC-matched asset -- lands criticality CRITICAL and matches the seeded
    'Credential dumping response' playbook shape."""
    web = _asset(db, "web-01")
    db.add(Vulnerability(cve_id="CVE-TEST-1", title="t", cvss_score=9.8, kev_listed=True, asset_id=web.id))
    actor = ThreatActorProfile(name="TEST-ACTOR", description="", associated_technique_ids="T1003,T1041")
    db.add(actor)
    db.flush()
    db.add(ThreatIndicator(indicator_type="ip", value="203.0.113.99", threat_actor_id=actor.id))
    db.add(Playbook(
        name="Credential dumping response", trigger_attack_technique_id="T1003",
        trigger_min_severity=AlertSeverity.HIGH, actions="isolate_host,notify_oncall",
    ))
    db.commit()
    alert = _alert(db, web, "lsass access", AlertSeverity.CRITICAL, "T1003", description="hit from 203.0.113.99")
    return _incident(db, web, [alert])


def test_critical_decision_never_executes_playbooks_directly(db_session):
    incident = _critical_incident_with_matching_playbook(db_session)

    triage = incident_response_agent.triage(db_session, incident)
    decision = incident_commander_agent.decide(db_session, incident, triage)

    assert decision.decision == ResponseDecision.CONTAIN_PENDING_APPROVAL
    assert db_session.query(PlaybookExecution).count() == 0
    assert incident.status == IncidentStatus.OPEN


def test_containment_approval_previews_matching_playbooks(db_session):
    incident = _critical_incident_with_matching_playbook(db_session)
    triage = incident_response_agent.triage(db_session, incident)
    incident_commander_agent.decide(db_session, incident, triage)

    approval = db_session.query(ContainmentApproval).filter_by(incident_id=incident.id).one()
    assert approval.status == ApprovalStatus.PENDING
    assert "Credential dumping response" in approval.requested_actions
    assert "isolate_host" in approval.requested_actions


def test_approve_containment_executes_playbooks_and_marks_contained(db_session):
    incident = _critical_incident_with_matching_playbook(db_session)
    triage = incident_response_agent.triage(db_session, incident)
    incident_commander_agent.decide(db_session, incident, triage)
    approval = db_session.query(ContainmentApproval).filter_by(incident_id=incident.id).one()

    approved, executions = approval_service.approve_containment(
        db_session, approval.id, approver="analyst@example.com", note="confirmed malicious"
    )

    assert approved.status == ApprovalStatus.APPROVED
    assert approved.decided_by == "analyst@example.com"
    assert approved.decision_note == "confirmed malicious"
    assert approved.decided_at is not None
    assert len(executions) == 1
    assert db_session.query(PlaybookExecution).count() == 1
    db_session.refresh(incident)
    assert incident.status == IncidentStatus.CONTAINED


def test_reject_containment_executes_nothing(db_session):
    incident = _critical_incident_with_matching_playbook(db_session)
    triage = incident_response_agent.triage(db_session, incident)
    incident_commander_agent.decide(db_session, incident, triage)
    approval = db_session.query(ContainmentApproval).filter_by(incident_id=incident.id).one()

    rejected = approval_service.reject_containment(db_session, approval.id, approver="analyst@example.com", note="false positive")

    assert rejected.status == ApprovalStatus.REJECTED
    assert db_session.query(PlaybookExecution).count() == 0
    db_session.refresh(incident)
    assert incident.status == IncidentStatus.OPEN


def test_cannot_decide_an_already_decided_approval(db_session):
    incident = _critical_incident_with_matching_playbook(db_session)
    triage = incident_response_agent.triage(db_session, incident)
    incident_commander_agent.decide(db_session, incident, triage)
    approval = db_session.query(ContainmentApproval).filter_by(incident_id=incident.id).one()

    approval_service.approve_containment(db_session, approval.id, approver="first-analyst")

    with pytest.raises(ApprovalNotPending):
        approval_service.approve_containment(db_session, approval.id, approver="second-analyst")
    with pytest.raises(ApprovalNotPending):
        approval_service.reject_containment(db_session, approval.id, approver="second-analyst")


def test_deciding_unknown_approval_raises(db_session):
    with pytest.raises(ApprovalNotPending):
        approval_service.approve_containment(db_session, "does-not-exist", approver="analyst")


def test_reject_containment_falls_back_to_escalate(db_session):
    incident = _critical_incident_with_matching_playbook(db_session)
    triage = incident_response_agent.triage(db_session, incident)
    incident_commander_agent.decide(db_session, incident, triage)
    approval = db_session.query(ContainmentApproval).filter_by(incident_id=incident.id).one()

    approval_service.reject_containment(db_session, approval.id, approver="analyst@example.com", note="false positive")

    decision = db_session.query(CommanderDecision).filter_by(incident_id=incident.id).one()
    assert decision.decision == ResponseDecision.ESCALATE

    review = db_session.query(CommanderContainmentReview).filter_by(incident_id=incident.id).one()
    assert review.outcome == ContainmentOutcome.REJECTED
    assert review.prior_decision == ResponseDecision.CONTAIN_PENDING_APPROVAL
    assert review.new_decision == ResponseDecision.ESCALATE


def test_approve_containment_with_no_matching_playbook_falls_back_to_escalate(db_session):
    # CRITICAL via KEV + confidence, but no seeded Playbook triggers on its
    # technique -- approval succeeds but executes nothing.
    web = _asset(db_session, "web-01")
    db_session.add(Vulnerability(cve_id="CVE-TEST-1", title="t", cvss_score=9.8, kev_listed=True, asset_id=web.id))
    actor = ThreatActorProfile(name="TEST-ACTOR", description="", associated_technique_ids="T1003,T1041")
    db_session.add(actor)
    db_session.flush()
    db_session.add(ThreatIndicator(indicator_type="ip", value="203.0.113.99", threat_actor_id=actor.id))
    db_session.commit()
    alert = _alert(db_session, web, "lsass access", AlertSeverity.CRITICAL, "T1003", description="hit from 203.0.113.99")
    incident = _incident(db_session, web, [alert])

    triage = incident_response_agent.triage(db_session, incident)
    decision = incident_commander_agent.decide(db_session, incident, triage)
    assert decision.decision == ResponseDecision.CONTAIN_PENDING_APPROVAL
    approval = db_session.query(ContainmentApproval).filter_by(incident_id=incident.id).one()

    approved, executions = approval_service.approve_containment(db_session, approval.id, approver="analyst@example.com")

    assert approved.status == ApprovalStatus.APPROVED
    assert executions == []
    db_session.refresh(incident)
    assert incident.status == IncidentStatus.OPEN  # never marked contained -- nothing executed

    new_decision = db_session.query(CommanderDecision).filter_by(incident_id=incident.id).one()
    assert new_decision.decision == ResponseDecision.ESCALATE

    review = db_session.query(CommanderContainmentReview).filter_by(incident_id=incident.id).one()
    assert review.outcome == ContainmentOutcome.NO_PLAYBOOK_MATCH
    assert review.new_decision == ResponseDecision.ESCALATE


def test_escalate_and_monitor_never_create_containment_approval(db_session):
    ws = _asset(db_session, "ws-01", criticality=1, exposure=Exposure.INTERNAL)
    alert = _alert(db_session, ws, "minor alert", AlertSeverity.LOW, "T1110")
    incident = _incident(db_session, ws, [alert], severity=AlertSeverity.LOW, confidence=0.1)

    triage = incident_response_agent.triage(db_session, incident)
    decision = incident_commander_agent.decide(db_session, incident, triage)

    assert decision.decision == ResponseDecision.MONITOR
    assert db_session.query(ContainmentApproval).count() == 0
