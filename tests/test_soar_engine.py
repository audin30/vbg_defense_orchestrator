from app.models import AlertSeverity, Asset, Exposure, Incident, Playbook
from app.services.soar_engine import evaluate_and_execute


def _asset(db):
    a = Asset(hostname="host-1", ip_address="10.0.0.1", criticality=5, exposure=Exposure.INTERNET_FACING)
    db.add(a)
    db.flush()
    return a


def test_matching_playbook_executes_its_actions(db_session):
    asset = _asset(db_session)
    incident = Incident(title="test incident", severity=AlertSeverity.CRITICAL, asset_id=asset.id, confidence=0.9)
    db_session.add(incident)
    db_session.flush()

    playbook = Playbook(
        name="critical escalation",
        trigger_attack_technique_id=None,
        trigger_min_severity=AlertSeverity.HIGH,
        actions="notify_oncall,create_ticket",
    )
    db_session.add(playbook)
    db_session.commit()

    executions = evaluate_and_execute(db_session, incident)

    assert len(executions) == 1
    actions = executions[0].actions_taken
    assert "notify_oncall" not in actions  # action name itself isn't logged, its result is
    assert "Paged security on-call" in actions
    assert "Filed incident ticket" in actions


def test_playbook_below_severity_threshold_does_not_execute(db_session):
    asset = _asset(db_session)
    incident = Incident(title="low severity", severity=AlertSeverity.LOW, asset_id=asset.id, confidence=0.2)
    db_session.add(incident)
    db_session.flush()

    playbook = Playbook(
        name="critical only",
        trigger_attack_technique_id=None,
        trigger_min_severity=AlertSeverity.CRITICAL,
        actions="notify_oncall",
    )
    db_session.add(playbook)
    db_session.commit()

    executions = evaluate_and_execute(db_session, incident)

    assert executions == []
