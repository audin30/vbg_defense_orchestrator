"""MITRE ATT&CK technique registry and detection-coverage reporting."""
from collections import defaultdict

from sqlalchemy.orm import Session

from app.connectors import attack_catalog_connector
from app.models import AttackTechnique, DetectionRule
from app.seed.attack_techniques import ATTACK_TECHNIQUES


def seed_attack_techniques(db: Session) -> int:
    """Populate the technique registry from the ATT&CK catalog connector
    (the full Enterprise dataset when live/cached). Falls back to the
    curated seed when the connector has nothing, so offline bootstrap and
    tests keep working. Upsert by technique id."""
    techniques = attack_catalog_connector.fetch_techniques()
    if not techniques:
        techniques = [{"id": tid, "name": name, "tactic": tactic} for tid, name, tactic in ATTACK_TECHNIQUES]

    created = 0
    for raw in techniques:
        existing = db.get(AttackTechnique, raw["id"])
        if existing is not None:
            existing.name = raw["name"]
            existing.tactic = raw["tactic"]
            continue
        db.add(AttackTechnique(id=raw["id"], name=raw["name"], tactic=raw["tactic"]))
        created += 1
    db.commit()
    return created


def coverage_by_tactic(db: Session) -> dict[str, dict[str, float | int]]:
    """For each tactic: how many techniques have at least one enabled
    detection rule vs. total techniques known in that tactic."""
    techniques = db.query(AttackTechnique).all()
    covered_technique_ids = {
        rule.attack_technique_id
        for rule in db.query(DetectionRule).filter(DetectionRule.enabled.is_(True)).all()
    }

    by_tactic: dict[str, dict[str, float | int]] = defaultdict(lambda: {"total": 0, "covered": 0})
    for t in techniques:
        by_tactic[t.tactic]["total"] += 1
        if t.id in covered_technique_ids:
            by_tactic[t.tactic]["covered"] += 1

    for tactic, counts in by_tactic.items():
        counts["coverage_pct"] = round(100 * counts["covered"] / counts["total"], 1) if counts["total"] else 0.0

    return dict(by_tactic)


def uncovered_techniques(db: Session) -> list[AttackTechnique]:
    covered_ids = {
        rule.attack_technique_id
        for rule in db.query(DetectionRule).filter(DetectionRule.enabled.is_(True)).all()
    }
    return [t for t in db.query(AttackTechnique).all() if t.id not in covered_ids]
