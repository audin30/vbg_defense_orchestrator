"""Regression coverage for the mock-scenario alert dedup bug: ingest_alerts()
must not produce duplicates when the mock data's timestamps are recomputed
across a fresh process (see app/seed/mock_scenario.py's fixed _NOW anchor).
"""
import importlib

from app.models import AlertSeverity
from app.seed import mock_scenario
from app.services import ingestion_service


def test_mock_alert_timestamps_are_fixed_across_reimport():
    """Root cause check: MOCK_ALERTS' occurred_at values must be identical
    across a module reload (simulating a fresh process), not recomputed
    against datetime.now()."""
    before = [a["occurred_at"] for a in mock_scenario.MOCK_ALERTS]
    importlib.reload(mock_scenario)
    after = [a["occurred_at"] for a in mock_scenario.MOCK_ALERTS]

    assert before == after


def test_ingest_alerts_is_idempotent_within_a_process(db_session):
    ingestion_service.ingest_assets(db_session)

    first = ingestion_service.ingest_alerts(db_session)
    second = ingestion_service.ingest_alerts(db_session)

    assert len(first) == len(mock_scenario.MOCK_ALERTS)
    assert second == []


def test_ingest_alerts_round_trips_technique_and_finding_type(db_session):
    ingestion_service.ingest_assets(db_session)

    alerts = ingestion_service.ingest_alerts(db_session)

    by_title = {a.title: a for a in alerts}
    cloud_ransomware_alert = next(
        raw for raw in mock_scenario.MOCK_ALERTS if raw.get("finding_type") == "eventName:CreateKey"
    )
    ingested = by_title[cloud_ransomware_alert["title"]]

    assert ingested.attack_technique_id == cloud_ransomware_alert["attack_technique_id"]
    assert ingested.finding_type == cloud_ransomware_alert["finding_type"]
    assert ingested.severity == AlertSeverity(cloud_ransomware_alert["severity"])
