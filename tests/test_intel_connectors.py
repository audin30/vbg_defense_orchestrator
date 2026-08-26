import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from app.agents.threat_intel_agent import threat_intel_agent
from app.connectors import _http_cache
from app.connectors import cisa_kev, mitre_attack
from app.connectors.cisa_kev import CisaKevConnector
from app.connectors.mitre_attack import MitreAttackConnector
from app.connectors.mock import MockAttackCatalogConnector, MockKevCatalogConnector
from app.models import Alert, AlertSeverity, Asset, KevEntry, ThreatActorProfile, Vulnerability
from app.services import ingestion_service

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime.now(timezone.utc)


def _fixture(name):
    return json.loads((FIXTURES / name).read_text())


# --- Connector parsing ---


def test_kev_connector_parses_feed(monkeypatch):
    monkeypatch.setattr(cisa_kev, "fetch_json_cached", lambda *a: _fixture("kev_sample.json"))
    entries = CisaKevConnector().fetch_kev_entries()

    assert len(entries) == 2  # malformed no-CVE entry skipped
    citrix = next(e for e in entries if e["cve_id"] == "CVE-2023-4966")
    assert citrix["known_ransomware_use"] is True
    assert citrix["due_date"] == "2023-11-08"
    pan = next(e for e in entries if e["cve_id"] == "CVE-2024-3400")
    assert pan["known_ransomware_use"] is False


def test_mitre_connector_parses_stix_bundle(monkeypatch):
    monkeypatch.setattr(mitre_attack, "fetch_json_cached", lambda *a: _fixture("stix_sample.json"))
    connector = MitreAttackConnector()

    techniques = connector.fetch_techniques()
    ids = {t["id"] for t in techniques}
    assert ids == {"T1059", "T1003.001", "T1021"}  # deprecated T9998 excluded
    cred = next(t for t in techniques if t["id"] == "T1003.001")
    assert cred["tactic"] == "Credential Access"

    groups = connector.fetch_actor_groups()
    assert [g["name"] for g in groups] == ["TEST-GROUP-ALPHA"]  # sparse + revoked filtered
    alpha = groups[0]
    assert alpha["attack_technique_ids"] == ["T1003.001", "T1021", "T1059"]
    assert alpha["description"] == "First line of description."


def test_connector_returns_empty_when_no_data(monkeypatch):
    monkeypatch.setattr(cisa_kev, "fetch_json_cached", lambda *a: None)
    monkeypatch.setattr(mitre_attack, "fetch_json_cached", lambda *a: None)
    assert CisaKevConnector().fetch_kev_entries() == []
    connector = MitreAttackConnector()
    assert connector.fetch_techniques() == []
    assert connector.fetch_actor_groups() == []


def test_fetch_json_cached_falls_back_to_stale_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(_http_cache, "CACHE_DIR", tmp_path)
    cache_file = tmp_path / "feed.json"
    cache_file.write_text(json.dumps({"cached": True}))
    # Make the cache stale so a refetch is attempted, and fail the fetch.
    import os
    old = (datetime.now(timezone.utc) - timedelta(days=30)).timestamp()
    os.utime(cache_file, (old, old))

    def _boom(*a, **kw):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(_http_cache.httpx, "get", _boom)
    assert _http_cache.fetch_json_cached("https://example.invalid/feed", "feed.json", 60) == {"cached": True}


def test_fetch_json_cached_returns_none_without_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(_http_cache, "CACHE_DIR", tmp_path)

    def _boom(*a, **kw):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(_http_cache.httpx, "get", _boom)
    assert _http_cache.fetch_json_cached("https://example.invalid/feed", "feed.json", 60) is None


# --- Ingestion ---


def test_ingest_kev_catalog_upsert_idempotent(db_session, monkeypatch):
    monkeypatch.setattr(ingestion_service, "kev_connector", MockKevCatalogConnector())
    ingestion_service.ingest_kev_catalog(db_session)
    ingestion_service.ingest_kev_catalog(db_session)

    assert db_session.query(KevEntry).count() == 2


def test_kev_enrichment_recomputes_flags_from_catalog(db_session, monkeypatch):
    monkeypatch.setattr(ingestion_service, "kev_connector", MockKevCatalogConnector())
    asset = Asset(hostname="h1", ip_address="10.0.0.1", criticality=3)
    db_session.add(asset)
    db_session.flush()
    # Scanner said not KEV, but the catalog knows better -- and vice versa.
    db_session.add(Vulnerability(cve_id="CVE-2023-4966", title="t", cvss_score=7.5, kev_listed=False, asset_id=asset.id))
    db_session.add(Vulnerability(cve_id="CVE-1999-0001", title="t", cvss_score=5.0, kev_listed=True, asset_id=asset.id))
    db_session.commit()

    ingestion_service.ingest_kev_catalog(db_session)
    updated = ingestion_service.apply_kev_enrichment(db_session)

    assert updated == 2
    flags = {v.cve_id: v.kev_listed for v in db_session.query(Vulnerability).all()}
    assert flags == {"CVE-2023-4966": True, "CVE-1999-0001": False}


def test_kev_enrichment_noop_with_empty_catalog(db_session):
    asset = Asset(hostname="h1", ip_address="10.0.0.1", criticality=3)
    db_session.add(asset)
    db_session.flush()
    db_session.add(Vulnerability(cve_id="CVE-2024-3400", title="t", cvss_score=9.8, kev_listed=True, asset_id=asset.id))
    db_session.commit()

    assert ingestion_service.apply_kev_enrichment(db_session) == 0
    assert db_session.query(Vulnerability).one().kev_listed is True


def test_actor_group_ingestion_upsert_idempotent(db_session, monkeypatch):
    monkeypatch.setattr(ingestion_service, "attack_catalog_connector", MockAttackCatalogConnector())
    ingestion_service.ingest_actor_groups_from_attack_catalog(db_session)
    ingestion_service.ingest_actor_groups_from_attack_catalog(db_session)

    assert db_session.query(ThreatActorProfile).count() == 2


# --- Actor-match metric (incident coverage, not Jaccard) ---


def _incident_alerts(db, technique_ids):
    asset = Asset(hostname="h1", ip_address="10.0.0.1", criticality=3)
    db.add(asset)
    db.flush()
    alerts = []
    for i, tid in enumerate(technique_ids):
        a = Alert(
            source="test", title=f"a{i}", severity=AlertSeverity.HIGH,
            asset_id=asset.id, attack_technique_id=tid,
            occurred_at=NOW - timedelta(minutes=i),
        )
        db.add(a)
        alerts.append(a)
    db.commit()
    return alerts


def test_large_real_profile_matches_when_it_covers_incident(db_session):
    # A real-world-sized group: 200 known techniques, 3 of which appear in a
    # 4-technique incident. Jaccard would be ~0.015; coverage is 0.75.
    big_profile_techniques = [f"T{6000 + i}" for i in range(197)] + ["T1059", "T1003", "T1021"]
    db_session.add(ThreatActorProfile(
        name="BIG-GROUP", description="", associated_technique_ids=",".join(big_profile_techniques),
    ))
    alerts = _incident_alerts(db_session, ["T1059", "T1003", "T1021", "T1041"])

    report = threat_intel_agent.get_context(db_session, alerts)

    assert [m.threat_actor_name for m in report.actor_matches] == ["BIG-GROUP"]
    assert report.actor_matches[0].technique_overlap == 0.75


def test_single_shared_technique_is_not_a_match(db_session):
    db_session.add(ThreatActorProfile(
        name="NOISY-GROUP", description="", associated_technique_ids="T1059,T7001,T7002",
    ))
    alerts = _incident_alerts(db_session, ["T1059", "T1041", "T1003", "T1021"])

    report = threat_intel_agent.get_context(db_session, alerts)

    assert report.actor_matches == []


def test_actor_matches_capped_at_top_three(db_session):
    for i in range(6):
        db_session.add(ThreatActorProfile(
            name=f"GROUP-{i}", description="",
            associated_technique_ids="T1059,T1003" + ("," + ",".join(f"T{7100 + j}" for j in range(i))),
        ))
    alerts = _incident_alerts(db_session, ["T1059", "T1003"])

    report = threat_intel_agent.get_context(db_session, alerts)

    assert len(report.actor_matches) == 3
