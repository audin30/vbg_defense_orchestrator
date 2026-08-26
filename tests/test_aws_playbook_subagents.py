from datetime import datetime, timedelta, timezone

from app.agents.incident_commander_agent import incident_commander_agent
from app.agents.incident_response_agent import incident_response_agent
from app.agents.response.aws import dispatch_aws_playbooks
from app.agents.response.aws.catalog import AWS_PLAYBOOK_SUBAGENTS
from app.models import (
    Alert,
    AlertSeverity,
    Asset,
    Exposure,
    Incident,
    ResponseDecision,
    ResponseTask,
)

NOW = datetime.now(timezone.utc)


def _asset(db, hostname, criticality=5, exposure=Exposure.INTERNET_FACING):
    a = Asset(hostname=hostname, ip_address="0.0.0.0", criticality=criticality, exposure=exposure)
    db.add(a)
    db.flush()
    return a


def _alert(db, asset, title, severity, technique_id=None, finding_type=None, minutes_ago=10):
    a = Alert(
        source="test",
        title=title,
        severity=severity,
        asset_id=asset.id,
        attack_technique_id=technique_id,
        finding_type=finding_type,
        occurred_at=NOW - timedelta(minutes=minutes_ago),
    )
    db.add(a)
    return a


def _incident(db, asset, alerts, severity=AlertSeverity.CRITICAL, confidence=0.9):
    inc = Incident(title="aws test incident", severity=severity, asset_id=asset.id, confidence=confidence)
    db.add(inc)
    db.flush()
    for a in alerts:
        a.incident_id = inc.id
    db.commit()
    db.refresh(inc)
    return inc


def _aws_ransomware_incident(db, confidence=0.9):
    """Mirrors the mock scenario's cloud chain: stolen instance creds,
    S3 destruction, attacker KMS key."""
    acct = _asset(db, "aws-prod-account")
    alerts = [
        _alert(db, acct, "cred exfil", AlertSeverity.HIGH, "T1078",
               "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", 90),
        _alert(db, acct, "s3 destruction", AlertSeverity.CRITICAL, "T1490",
               "Impact:S3/AnomalousBehavior.Delete", 45),
        _alert(db, acct, "kms key + ransom note", AlertSeverity.CRITICAL, "T1486",
               "eventName:CreateKey", 40),
    ]
    return _incident(db, acct, alerts, confidence=confidence)


def test_finding_prefixes_route_to_matching_playbooks(db_session):
    incident = _aws_ransomware_incident(db_session)

    plans = dispatch_aws_playbooks(incident, ResponseDecision.ESCALATE)
    categories = {p.category for p in plans}

    # InstanceCredentialExfiltration -> STS token abuse (IMDS theft vector);
    # Impact:S3 + eventName:CreateKey -> ransomware.
    assert categories == {"aws_ransomware", "aws_sts_token_abuse"}


def test_plans_record_matched_finding_types_not_techniques(db_session):
    incident = _aws_ransomware_incident(db_session)

    plans = dispatch_aws_playbooks(incident, ResponseDecision.CONTAIN_PENDING_APPROVAL)
    ransomware = next(p for p in plans if p.category == "aws_ransomware")

    assert ransomware.triggered_by_technique_ids == [
        "Impact:S3/AnomalousBehavior.Delete",
        "eventName:CreateKey",
    ]


def test_monitor_decision_never_activates_aws_playbooks(db_session):
    incident = _aws_ransomware_incident(db_session)

    assert dispatch_aws_playbooks(incident, ResponseDecision.MONITOR) == []


def test_onprem_incident_without_finding_types_matches_no_aws_playbooks(db_session):
    host = _asset(db_session, "web-01")
    alert = _alert(db_session, host, "exploit", AlertSeverity.CRITICAL, technique_id="T1190")
    incident = _incident(db_session, host, [alert])

    assert dispatch_aws_playbooks(incident, ResponseDecision.CONTAIN_PENDING_APPROVAL) == []


def test_commander_call_persists_aws_tasks_with_commander_dispatch(db_session):
    incident = _aws_ransomware_incident(db_session)

    triage = incident_response_agent.triage(db_session, incident)
    decision = incident_commander_agent.decide(db_session, incident, triage)

    assert decision.decision in (ResponseDecision.ESCALATE, ResponseDecision.CONTAIN_PENDING_APPROVAL)
    aws_tasks = (
        db_session.query(ResponseTask)
        .filter_by(incident_id=incident.id, dispatched_by="commander")
        .all()
    )
    assert aws_tasks, "Commander decision should have activated AWS playbooks"
    assert all(t.category.startswith("aws_") for t in aws_tasks)
    # Triage-stage tasks stay attributed to the IR agent (T1078/T1486/T1490
    # also spawn the generic credential-compromise + ransomware runbooks).
    triage_tasks = (
        db_session.query(ResponseTask)
        .filter_by(incident_id=incident.id, dispatched_by="ir_agent")
        .all()
    )
    assert triage_tasks and not any(t.category.startswith("aws_") for t in triage_tasks)


def test_low_criticality_commander_call_dispatches_nothing(db_session):
    acct = _asset(db_session, "aws-dev-account", criticality=1, exposure=Exposure.INTERNAL)
    alert = _alert(db_session, acct, "single finding", AlertSeverity.LOW,
                   finding_type="Discovery:IAMUser/AnomalousBehavior")
    incident = _incident(db_session, acct, [alert], severity=AlertSeverity.LOW, confidence=0.1)

    triage = incident_response_agent.triage(db_session, incident)
    decision = incident_commander_agent.decide(db_session, incident, triage)

    assert decision.decision == ResponseDecision.MONITOR
    assert (
        db_session.query(ResponseTask)
        .filter_by(incident_id=incident.id, dispatched_by="commander")
        .count()
        == 0
    )


def test_aws_catalog_categories_unique_and_prefixed():
    categories = [a.category for a in AWS_PLAYBOOK_SUBAGENTS]
    assert len(categories) == len(set(categories))
    assert all(c.startswith("aws_") for c in categories)
    assert all(a.source_playbook.endswith(".md") for a in AWS_PLAYBOOK_SUBAGENTS)
