"""Pulls raw data from connectors and normalizes it into ORM rows.

Idempotent by natural key (hostname, cve_id+hostname, alert title+asset+time)
so re-running ingestion against the same mock/real source doesn't duplicate rows.
"""
from datetime import datetime

from dateutil import parser as dateparser
from sqlalchemy.orm import Session

from app.connectors import (
    asset_inventory_connector,
    attack_catalog_connector,
    kev_connector,
    siem_connector,
    threat_intel_connector,
    vuln_scanner_connector,
)
from app.models import (
    Alert,
    AlertSeverity,
    Asset,
    Exposure,
    KevEntry,
    ThreatActorProfile,
    ThreatIndicator,
    Vulnerability,
)


def ingest_assets(db: Session) -> list[Asset]:
    created = []
    for raw in asset_inventory_connector.fetch_assets():
        existing = db.query(Asset).filter_by(hostname=raw["hostname"]).one_or_none()
        if existing:
            continue
        asset = Asset(
            hostname=raw["hostname"],
            ip_address=raw["ip_address"],
            criticality=raw["criticality"],
            exposure=Exposure(raw["exposure"]),
            data_sensitivity=raw.get("data_sensitivity", 1),
            business_unit=raw.get("business_unit", "unknown"),
            tags=raw.get("tags", ""),
        )
        db.add(asset)
        created.append(asset)
    db.commit()
    return created


def ingest_vulnerabilities(db: Session) -> list[Vulnerability]:
    created = []
    for raw in vuln_scanner_connector.fetch_vulnerabilities():
        asset = db.query(Asset).filter_by(hostname=raw["hostname"]).one_or_none()
        if asset is None:
            continue  # asset not yet known; run ingest_assets first
        existing = (
            db.query(Vulnerability)
            .filter_by(cve_id=raw["cve_id"], asset_id=asset.id)
            .one_or_none()
        )
        if existing:
            continue
        vuln = Vulnerability(
            cve_id=raw["cve_id"],
            title=raw["title"],
            cvss_score=raw["cvss_score"],
            epss_score=raw.get("epss_score", 0.0),
            kev_listed=raw.get("kev_listed", False),
            asset_id=asset.id,
        )
        db.add(vuln)
        created.append(vuln)
    db.commit()
    return created


def ingest_alerts(db: Session) -> list[Alert]:
    created = []
    for raw in siem_connector.fetch_alerts():
        asset = db.query(Asset).filter_by(hostname=raw["hostname"]).one_or_none()
        if asset is None:
            continue
        occurred_at: datetime = dateparser.isoparse(raw["occurred_at"])
        existing = (
            db.query(Alert)
            .filter_by(title=raw["title"], asset_id=asset.id, occurred_at=occurred_at)
            .one_or_none()
        )
        if existing:
            continue
        alert = Alert(
            source="mock-siem",
            title=raw["title"],
            description=raw.get("description", ""),
            severity=AlertSeverity(raw["severity"]),
            asset_id=asset.id,
            attack_technique_id=raw.get("attack_technique_id"),
            finding_type=raw.get("finding_type"),
            occurred_at=occurred_at,
        )
        db.add(alert)
        created.append(alert)
    db.commit()
    return created


def ingest_kev_catalog(db: Session) -> int:
    """Upsert the CISA KEV catalog. Idempotent by cve_id; existing entries
    are refreshed in place (due dates and ransomware attribution change)."""
    upserted = 0
    for raw in kev_connector.fetch_kev_entries():
        entry = db.get(KevEntry, raw["cve_id"])
        if entry is None:
            entry = KevEntry(cve_id=raw["cve_id"])
            db.add(entry)
        entry.vendor_project = raw.get("vendor_project", "")
        entry.product = raw.get("product", "")
        entry.vulnerability_name = raw.get("vulnerability_name", "")
        entry.date_added = raw.get("date_added", "")
        entry.due_date = raw.get("due_date", "")
        entry.known_ransomware_use = raw.get("known_ransomware_use", False)
        entry.short_description = raw.get("short_description", "")
        upserted += 1
    db.commit()
    return upserted


def apply_kev_enrichment(db: Session) -> int:
    """Recompute Vulnerability.kev_listed from the KEV table. Only runs when
    the catalog is populated -- with an empty catalog (offline, no cache) the
    scanner-provided flags are left untouched."""
    kev_cve_ids = {row[0] for row in db.query(KevEntry.cve_id).all()}
    if not kev_cve_ids:
        return 0
    updated = 0
    for vuln in db.query(Vulnerability).all():
        listed = vuln.cve_id in kev_cve_ids
        if vuln.kev_listed != listed:
            vuln.kev_listed = listed
            updated += 1
    db.commit()
    return updated


def ingest_actor_groups_from_attack_catalog(db: Session) -> int:
    """Upsert MITRE intrusion sets as ThreatActorProfile rows (same natural
    key -- name -- as TIP-fed profiles, so the two sources coexist)."""
    upserted = 0
    for raw in attack_catalog_connector.fetch_actor_groups():
        profile = db.query(ThreatActorProfile).filter_by(name=raw["name"]).one_or_none()
        if profile is None:
            profile = ThreatActorProfile(name=raw["name"])
            db.add(profile)
        profile.description = raw.get("description", "")
        profile.associated_technique_ids = ",".join(raw["attack_technique_ids"])
        upserted += 1
    db.commit()
    return upserted


def ingest_threat_intel(db: Session) -> dict[str, int]:
    profiles_created = 0
    for raw in threat_intel_connector.fetch_actor_profiles():
        existing = db.query(ThreatActorProfile).filter_by(name=raw["name"]).one_or_none()
        if existing:
            continue
        db.add(
            ThreatActorProfile(
                name=raw["name"],
                description=raw.get("description", ""),
                associated_technique_ids=",".join(raw["attack_technique_ids"]),
            )
        )
        profiles_created += 1
    db.commit()

    indicators_created = 0
    for raw in threat_intel_connector.fetch_indicators():
        existing = db.query(ThreatIndicator).filter_by(value=raw["value"]).one_or_none()
        if existing:
            continue
        actor = None
        if raw.get("threat_actor"):
            actor = db.query(ThreatActorProfile).filter_by(name=raw["threat_actor"]).one_or_none()
        db.add(
            ThreatIndicator(
                indicator_type=raw["indicator_type"],
                value=raw["value"],
                confidence=raw.get("confidence", 0.5),
                description=raw.get("description", ""),
                threat_actor_id=actor.id if actor else None,
            )
        )
        indicators_created += 1
    db.commit()

    return {"threat_actor_profiles": profiles_created, "threat_indicators": indicators_created}


def run_full_ingestion(db: Session) -> dict[str, int]:
    kev_entries = ingest_kev_catalog(db)
    assets = ingest_assets(db)
    vulns = ingest_vulnerabilities(db)
    kev_enriched = apply_kev_enrichment(db)
    alerts = ingest_alerts(db)
    threat_intel = ingest_threat_intel(db)
    actor_groups = ingest_actor_groups_from_attack_catalog(db)
    return {
        "kev_entries": kev_entries,
        "assets": len(assets),
        "vulnerabilities": len(vulns),
        "kev_flags_updated": kev_enriched,
        "alerts": len(alerts),
        **threat_intel,
        "attack_actor_groups": actor_groups,
    }
