from datetime import datetime, timedelta, timezone

from app.agents.incident_response_agent import incident_response_agent
from app.agents.response import RESPONSE_SUBAGENTS, dispatch_response_subagents
from app.agents.response.base import PHASES
from app.models import Alert, AlertSeverity, Asset, Exposure, Incident, ResponseTask, ResponseTaskStatus

NOW = datetime.now(timezone.utc)


def _asset(db, hostname, criticality=3, exposure=Exposure.INTERNAL, tags=""):
    a = Asset(hostname=hostname, ip_address="10.0.0.1", criticality=criticality, exposure=exposure, tags=tags)
    db.add(a)
    db.flush()
    return a


def _alert(db, asset, title, severity, technique_id, minutes_ago=10):
    a = Alert(
        source="test",
        title=title,
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


def _attack_chain_incident(db):
    """Mirrors the mock scenario: exploit -> execution -> cred dump on web,
    lateral move -> exfil on the DC."""
    web = _asset(db, "web-01", criticality=4, exposure=Exposure.INTERNET_FACING)
    dc = _asset(db, "dc-01", criticality=5)
    alerts = [
        _alert(db, web, "exploit", AlertSeverity.CRITICAL, "T1190", minutes_ago=120),
        _alert(db, web, "shell", AlertSeverity.HIGH, "T1059", minutes_ago=115),
        _alert(db, web, "lsass", AlertSeverity.CRITICAL, "T1003", minutes_ago=100),
        _alert(db, dc, "smb pivot", AlertSeverity.HIGH, "T1021", minutes_ago=80),
        _alert(db, dc, "exfil", AlertSeverity.CRITICAL, "T1041", minutes_ago=60),
    ]
    return _incident(db, web, alerts)


def test_attack_chain_spawns_matching_subagents_only(db_session):
    incident = _attack_chain_incident(db_session)

    plans = dispatch_response_subagents(incident)
    categories = {p.category for p in plans}

    assert categories == {"malware", "credential_compromise", "lateral_movement", "data_exfiltration"}


def test_per_host_steps_scoped_to_hosts_where_trigger_technique_was_seen(db_session):
    incident = _attack_chain_incident(db_session)

    plans = dispatch_response_subagents(incident)
    exfil = next(p for p in plans if p.category == "data_exfiltration")

    # T1041 was only observed on dc-01, so per-host steps must not touch web-01.
    scoped_hosts = {s.scope_hostname for s in exfil.steps if s.scope_hostname is not None}
    assert scoped_hosts == {"dc-01"}
    # Incident-wide steps (egress block, legal assessment) carry no hostname.
    assert any(s.scope_hostname is None for s in exfil.steps)


def test_plans_record_which_techniques_triggered_them(db_session):
    incident = _attack_chain_incident(db_session)

    plans = dispatch_response_subagents(incident)
    malware = next(p for p in plans if p.category == "malware")

    assert malware.triggered_by_technique_ids == ["T1059", "T1190"]


def test_brute_force_noise_triggers_only_credential_compromise(db_session):
    ws = _asset(db_session, "ws-01", criticality=2)
    alert = _alert(db_session, ws, "failed logins", AlertSeverity.MEDIUM, "T1110")
    incident = _incident(db_session, ws, [alert], severity=AlertSeverity.MEDIUM, confidence=0.4)

    plans = dispatch_response_subagents(incident)

    assert [p.category for p in plans] == ["credential_compromise"]


def test_unmapped_technique_spawns_no_subagents(db_session):
    ws = _asset(db_session, "ws-01")
    alert = _alert(db_session, ws, "odd but unmapped", AlertSeverity.LOW, "T9999")
    incident = _incident(db_session, ws, [alert], severity=AlertSeverity.LOW, confidence=0.2)

    assert dispatch_response_subagents(incident) == []


def test_encryption_for_impact_triggers_ransomware_runbook(db_session):
    fs = _asset(db_session, "fileserver-01", criticality=5)
    alert = _alert(db_session, fs, "mass file rename to .locked", AlertSeverity.CRITICAL, "T1486")
    incident = _incident(db_session, fs, [alert])

    plans = dispatch_response_subagents(incident)

    assert "ransomware" in {p.category for p in plans}


def test_all_runbooks_use_known_phases_and_are_ordered(db_session):
    incident = _attack_chain_incident(db_session)

    for plan in dispatch_response_subagents(incident):
        assert plan.steps, f"{plan.category} produced an empty plan"
        assert [s.order for s in plan.steps] == list(range(1, len(plan.steps) + 1))
        for step in plan.steps:
            assert step.phase in PHASES


def test_subagent_registry_has_unique_categories():
    categories = [a.category for a in RESPONSE_SUBAGENTS]
    assert len(categories) == len(set(categories))


def test_triage_persists_response_tasks_as_recommended(db_session):
    incident = _attack_chain_incident(db_session)

    report = incident_response_agent.triage(db_session, incident)

    tasks = db_session.query(ResponseTask).filter_by(incident_id=incident.id).all()
    assert len(tasks) == sum(len(p.steps) for p in report.response_plans)
    assert all(t.status == ResponseTaskStatus.RECOMMENDED for t in tasks)
    assert "Runbook" in db_session.query(ResponseTask).first().runbook_name
