from datetime import datetime, timedelta, timezone

from app.models import Alert, AlertSeverity, Asset, Exposure
from app.services.correlation_service import correlate_alerts_into_incidents

NOW = datetime.now(timezone.utc)


def _asset(db, hostname, criticality=3, exposure=Exposure.INTERNAL):
    a = Asset(hostname=hostname, ip_address="10.0.0.1", criticality=criticality, exposure=exposure)
    db.add(a)
    db.flush()
    return a


def _alert(db, asset, title, severity, technique_id, minutes_ago):
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


def test_alerts_on_same_asset_cluster_into_one_incident(db_session):
    asset = _asset(db_session, "host-1")
    _alert(db_session, asset, "alert 1", AlertSeverity.HIGH, "T1059", 30)
    _alert(db_session, asset, "alert 2", AlertSeverity.HIGH, "T1003", 20)
    db_session.commit()

    incidents = correlate_alerts_into_incidents(db_session)

    assert len(incidents) == 1
    assert len(incidents[0].alerts) == 2


def test_distant_alerts_on_same_asset_stay_separate(db_session):
    asset = _asset(db_session, "host-1")
    _alert(db_session, asset, "old alert", AlertSeverity.LOW, "T1110", 600)
    _alert(db_session, asset, "new alert", AlertSeverity.LOW, "T1053", 10)
    db_session.commit()

    incidents = correlate_alerts_into_incidents(db_session)

    assert len(incidents) == 2


def test_lateral_movement_chains_two_assets_into_one_incident(db_session):
    web = _asset(db_session, "web-01", criticality=4, exposure=Exposure.INTERNET_FACING)
    dc = _asset(db_session, "dc-01", criticality=5)

    _alert(db_session, web, "exploit attempt", AlertSeverity.CRITICAL, "T1190", 120)
    _alert(db_session, web, "cred dump", AlertSeverity.CRITICAL, "T1003", 100)
    _alert(db_session, dc, "lateral movement", AlertSeverity.HIGH, "T1021", 80)

    db_session.commit()

    incidents = correlate_alerts_into_incidents(db_session)

    assert len(incidents) == 1
    incident = incidents[0]
    assert len(incident.alerts) == 3
    assert {a.asset_id for a in incident.alerts} == {web.id, dc.id}
    # multi-asset chains should score higher confidence than a single-host cluster
    assert incident.confidence > 0.5


def test_unrelated_asset_far_in_time_not_chained_in(db_session):
    web = _asset(db_session, "web-01")
    dc = _asset(db_session, "dc-01")
    unrelated = _asset(db_session, "ws-99")

    _alert(db_session, web, "exploit attempt", AlertSeverity.CRITICAL, "T1190", 120)
    _alert(db_session, dc, "lateral movement", AlertSeverity.HIGH, "T1021", 80)
    _alert(db_session, unrelated, "unrelated noise", AlertSeverity.LOW, "T1110", 900)

    db_session.commit()

    incidents = correlate_alerts_into_incidents(db_session)

    assert len(incidents) == 2
    sizes = sorted(len(i.alerts) for i in incidents)
    assert sizes == [1, 2]
