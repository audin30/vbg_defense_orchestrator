from datetime import datetime, timedelta, timezone

import pytest

from app.agents import incident_commander_agent, incident_response_agent
from app.agents.incident_commander_agent import ReanalysisAlreadyRequested
from app.agents.threat_analyzer_agent import threat_analyzer_agent
from app.agents.threat_intel_agent import threat_intel_agent
from app.models import (
    Alert,
    AlertSeverity,
    ApprovalStatus,
    Asset,
    CommanderDecision,
    CommanderReanalysisRequest,
    ContainmentApproval,
    Exposure,
    Incident,
    IncidentTriage,
    PlaybookExecution,
    ResponseDecision,
    ThreatActorProfile,
    ThreatIndicator,
    Vulnerability,
)

NOW = datetime.now(timezone.utc)


def _asset(db, hostname, criticality=3, exposure=Exposure.INTERNAL):
    a = Asset(hostname=hostname, ip_address="10.0.0.1", criticality=criticality, exposure=exposure)
    db.add(a)
    db.flush()
    return a


def _alert(db, asset, title, severity, technique_id, description="", minutes_ago=10):
    a = Alert(
        source="test",
        title=title,
        description=description,
        severity=severity,
        asset_id=asset.id,
        attack_technique_id=technique_id,
        occurred_at=NOW - timedelta(minutes=minutes_ago),
    )
    db.add(a)
    return a


def _incident(db, asset, alerts, severity=AlertSeverity.CRITICAL, confidence=0.9):
    inc = Incident(title="test incident", severity=severity, asset_id=asset.id, confidence=confidence)
    db.add(inc)
    db.flush()
    for a in alerts:
        a.incident_id = inc.id
    db.commit()
    db.refresh(inc)
    return inc


def test_threat_intel_agent_matches_ioc_in_alert_text(db_session):
    actor = ThreatActorProfile(name="TEST-ACTOR", description="", associated_technique_ids="T1041")
    db_session.add(actor)
    db_session.flush()
    db_session.add(
        ThreatIndicator(
            indicator_type="ip", value="198.51.100.77", confidence=0.9,
            description="test IOC", threat_actor_id=actor.id,
        )
    )
    db_session.commit()

    asset = _asset(db_session, "host-1")
    alert = _alert(db_session, asset, "exfil", AlertSeverity.CRITICAL, "T1041",
                    description="sent data to 198.51.100.77")
    db_session.commit()

    report = threat_intel_agent.get_context(db_session, [alert])

    assert report.has_ioc_hit
    assert report.ioc_matches[0].threat_actor_name == "TEST-ACTOR"


def test_threat_intel_agent_no_match_returns_empty_report(db_session):
    asset = _asset(db_session, "host-1")
    alert = _alert(db_session, asset, "benign", AlertSeverity.LOW, "T1053", description="nothing interesting")
    db_session.commit()

    report = threat_intel_agent.get_context(db_session, [alert])

    assert not report.has_ioc_hit
    assert report.actor_matches == []


def test_critical_incident_with_kev_and_ioc_queues_containment_for_approval(db_session):
    web = _asset(db_session, "web-01", criticality=5, exposure=Exposure.INTERNET_FACING)
    db_session.add(Vulnerability(cve_id="CVE-TEST-1", title="t", cvss_score=9.8, kev_listed=True, asset_id=web.id))
    actor = ThreatActorProfile(name="TEST-ACTOR", description="", associated_technique_ids="T1190,T1041")
    db_session.add(actor)
    db_session.flush()
    db_session.add(ThreatIndicator(indicator_type="ip", value="203.0.113.99", threat_actor_id=actor.id))
    db_session.commit()

    alert = _alert(db_session, web, "exploit", AlertSeverity.CRITICAL, "T1190", description="hit from 203.0.113.99")
    incident = _incident(db_session, web, [alert], severity=AlertSeverity.CRITICAL, confidence=1.0)

    triage = incident_response_agent.triage(db_session, incident)
    decision = incident_commander_agent.decide(db_session, incident, triage)

    assert triage.criticality == "critical"
    assert decision.decision == ResponseDecision.CONTAIN_PENDING_APPROVAL
    # No containment is executed until a human approves -- no playbook runs yet.
    assert db_session.query(PlaybookExecution).count() == 0
    approval = db_session.query(ContainmentApproval).filter_by(incident_id=incident.id).one()
    assert approval.status == ApprovalStatus.PENDING
    assert approval.requested_actions  # preview of what approval would run


def test_low_confidence_incident_gets_monitor_and_no_playbooks(db_session):
    ws = _asset(db_session, "ws-01", criticality=1, exposure=Exposure.INTERNAL)
    alert = _alert(db_session, ws, "minor alert", AlertSeverity.LOW, "T1110")
    incident = _incident(db_session, ws, [alert], severity=AlertSeverity.LOW, confidence=0.1)

    triage = incident_response_agent.triage(db_session, incident)
    decision = incident_commander_agent.decide(db_session, incident, triage)

    assert triage.criticality == "low"
    assert decision.decision == ResponseDecision.MONITOR


def test_reasoning_mode_falls_back_to_deterministic_without_api_key(db_session, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    ws = _asset(db_session, "ws-01")
    alert = _alert(db_session, ws, "alert", AlertSeverity.MEDIUM, "T1053")
    incident = _incident(db_session, ws, [alert], severity=AlertSeverity.MEDIUM, confidence=0.4)

    triage = incident_response_agent.triage(db_session, incident)

    assert triage.reasoning_mode == "deterministic"


def test_commander_reanalysis_floor_raises_rating_but_never_lowers_it(db_session):
    ws = _asset(db_session, "ws-01", criticality=2, exposure=Exposure.INTERNAL)
    alert = _alert(db_session, ws, "minor alert", AlertSeverity.LOW, "T1110")
    incident = _incident(db_session, ws, [alert], severity=AlertSeverity.LOW, confidence=0.1)

    baseline = threat_analyzer_agent.analyze(db_session, incident)
    assert baseline.risk_rating == "low"
    assert not baseline.recommended

    # A floor below the computed rating is a no-op -- it can only raise.
    same = threat_analyzer_agent.analyze(db_session, incident, override_floor=AlertSeverity.LOW)
    assert same.risk_rating == "low"

    raised = incident_commander_agent.request_reanalysis(
        db_session, incident, reason="analyst believes this is understated", override_floor=AlertSeverity.HIGH
    )
    assert raised.risk_rating == "high"
    assert raised.recommended

    record = db_session.query(CommanderReanalysisRequest).filter_by(incident_id=incident.id).one()
    assert record.prior_risk_rating == AlertSeverity.LOW
    assert not record.prior_recommended
    assert record.new_risk_rating == AlertSeverity.HIGH
    assert record.new_recommended


def test_commander_reanalysis_is_capped_at_one_retry(db_session):
    ws = _asset(db_session, "ws-01")
    alert = _alert(db_session, ws, "minor alert", AlertSeverity.LOW, "T1110")
    incident = _incident(db_session, ws, [alert], severity=AlertSeverity.LOW, confidence=0.1)
    threat_analyzer_agent.analyze(db_session, incident)

    incident_commander_agent.request_reanalysis(
        db_session, incident, reason="first disagreement", override_floor=AlertSeverity.HIGH
    )

    with pytest.raises(ReanalysisAlreadyRequested):
        incident_commander_agent.request_reanalysis(
            db_session, incident, reason="second disagreement", override_floor=AlertSeverity.CRITICAL
        )


def test_commander_reanalysis_reroutes_a_previously_skipped_incident_into_triage(db_session):
    """Mirrors what routes.reanalyze_incident does at the agent layer: a
    skip()-ped incident whose reanalysis now recommends it gets its stale
    MONITOR decision replaced by a full triage() + decide() pass."""
    ws = _asset(db_session, "ws-01", criticality=2, exposure=Exposure.INTERNAL)
    alert = _alert(db_session, ws, "minor alert", AlertSeverity.LOW, "T1110")
    incident = _incident(db_session, ws, [alert], severity=AlertSeverity.LOW, confidence=0.1)

    risk_assessment = incident_commander_agent.gate(db_session, incident)
    assert not risk_assessment.recommended
    incident_commander_agent.skip(db_session, incident, risk_assessment)
    assert db_session.query(CommanderDecision).filter_by(incident_id=incident.id).one().decision == ResponseDecision.MONITOR

    raised = incident_commander_agent.request_reanalysis(
        db_session, incident, reason="analyst override", override_floor=AlertSeverity.HIGH
    )
    assert raised.recommended
    assert db_session.query(IncidentTriage).filter_by(incident_id=incident.id).one_or_none() is None

    stale = db_session.query(CommanderDecision).filter_by(incident_id=incident.id).one()
    db_session.delete(stale)
    db_session.commit()
    triage = incident_response_agent.triage(db_session, incident, raised)
    decision = incident_commander_agent.decide(db_session, incident, triage)

    assert triage.criticality == "high"
    assert decision.decision == ResponseDecision.ESCALATE
