from datetime import datetime, timedelta, timezone

from app.agents.evidence_planner import build_evidence_plan
from app.agents.threat_intel_agent import threat_intel_agent
from app.models import Alert, AlertSeverity, Asset, Exposure, ThreatActorProfile, ThreatIndicator

NOW = datetime.now(timezone.utc)


def _asset(db, hostname, exposure=Exposure.INTERNAL):
    a = Asset(hostname=hostname, ip_address="10.0.0.1", criticality=3, exposure=exposure)
    db.add(a)
    db.flush()
    return a


def _alert(db, asset, title, technique_id, description="", minutes_ago=10):
    a = Alert(
        source="test",
        title=title,
        description=description,
        severity=AlertSeverity.HIGH,
        asset_id=asset.id,
        attack_technique_id=technique_id,
        occurred_at=NOW - timedelta(minutes=minutes_ago),
    )
    db.add(a)
    db.flush()
    return a


def test_evidence_mapped_from_technique(db_session):
    asset = _asset(db_session, "dc-01")
    alert = _alert(db_session, asset, "cred dump", "T1003")
    db_session.commit()

    threat_intel = threat_intel_agent.get_context(db_session, [alert])
    plan = build_evidence_plan([alert], threat_intel)

    assert plan
    assert all(e.asset_hostname == "dc-01" for e in plan)
    assert any(e.related_technique_id == "T1003" for e in plan)
    assert any("memory" in e.evidence_type.lower() for e in plan)
    assert not any(e.tied_to_threat_intel for e in plan)


def test_evidence_tied_to_ioc_match(db_session):
    actor = ThreatActorProfile(name="TEST-ACTOR", description="", associated_technique_ids="T1041")
    db_session.add(actor)
    db_session.flush()
    db_session.add(
        ThreatIndicator(indicator_type="ip", value="203.0.113.50", confidence=0.9,
                         description="known C2", threat_actor_id=actor.id)
    )
    db_session.commit()

    asset = _asset(db_session, "web-01", exposure=Exposure.INTERNET_FACING)
    alert = _alert(db_session, asset, "exfil", "T1041", description="sent data to 203.0.113.50")
    db_session.commit()

    threat_intel = threat_intel_agent.get_context(db_session, [alert])
    plan = build_evidence_plan([alert], threat_intel)

    ioc_items = [e for e in plan if e.tied_to_threat_intel]
    assert len(ioc_items) == 1
    assert ioc_items[0].related_ioc_value == "203.0.113.50"
    assert ioc_items[0].asset_hostname == "web-01"
    assert "TEST-ACTOR" in ioc_items[0].justification


def test_unmapped_technique_falls_back_to_default_evidence(db_session):
    asset = _asset(db_session, "host-1")
    alert = _alert(db_session, asset, "weird alert", None)
    db_session.commit()

    threat_intel = threat_intel_agent.get_context(db_session, [alert])
    plan = build_evidence_plan([alert], threat_intel)

    assert len(plan) == 1
    assert plan[0].related_technique_id is None
    assert plan[0].asset_hostname == "host-1"


def test_no_duplicate_technique_evidence_for_repeated_technique_on_same_host(db_session):
    asset = _asset(db_session, "host-1")
    alert1 = _alert(db_session, asset, "alert 1", "T1110", minutes_ago=30)
    alert2 = _alert(db_session, asset, "alert 2", "T1110", minutes_ago=10)
    db_session.commit()

    threat_intel = threat_intel_agent.get_context(db_session, [alert1, alert2])
    plan = build_evidence_plan([alert1, alert2], threat_intel)

    evidence_types = [e.evidence_type for e in plan]
    assert len(evidence_types) == len(set(evidence_types))
