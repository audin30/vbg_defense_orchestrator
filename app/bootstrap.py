"""One-shot bootstrap: create tables, seed reference data, ingest mock sources,
correlate incidents, and fire any matching playbooks. Safe to re-run.
"""
from sqlalchemy.orm import Session

from app.agents import incident_commander_agent, incident_response_agent
from app.db import Base, SessionLocal, engine
from app.models import DetectionRule, Playbook, ThreatAnalysis
from app.seed.detections_and_playbooks import DETECTION_RULES, PLAYBOOKS
from app.services import correlation_service, ingestion_service
from app.services.attack_mapping import seed_attack_techniques
from app.services.vuln_prioritization import recompute_all_risk_scores


def seed_detection_rules(db: Session) -> int:
    created = 0
    for name, technique_id, description in DETECTION_RULES:
        exists = db.query(DetectionRule).filter_by(name=name).one_or_none()
        if exists:
            continue
        db.add(
            DetectionRule(
                name=name,
                description=description,
                attack_technique_id=technique_id,
                enabled=True,
            )
        )
        created += 1
    db.commit()
    return created


def seed_playbooks(db: Session) -> int:
    created = 0
    for name, technique_id, min_severity, actions in PLAYBOOKS:
        exists = db.query(Playbook).filter_by(name=name).one_or_none()
        if exists:
            continue
        db.add(
            Playbook(
                name=name,
                trigger_attack_technique_id=technique_id,
                trigger_min_severity=min_severity,
                actions=actions,
            )
        )
        created += 1
    db.commit()
    return created


def run_bootstrap() -> dict:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        summary = {}
        summary["attack_techniques"] = seed_attack_techniques(db)
        summary["detection_rules"] = seed_detection_rules(db)
        summary["playbooks"] = seed_playbooks(db)
        summary["ingestion"] = ingestion_service.run_full_ingestion(db)

        summary["risk_scores_updated"] = recompute_all_risk_scores(db)

        incidents = correlation_service.correlate_alerts_into_incidents(db)
        summary["incidents_created"] = len(incidents)

        decisions_by_type = {}
        gated_in = 0
        for incident in incidents:
            # Threat Analyzer Agent correlates asset/vuln/threat-intel data
            # and recommends whether this incident is worth full triage --
            # the Commander's gate just acts on that recommendation.
            risk_assessment = incident_commander_agent.gate(db, incident)
            if risk_assessment.recommended:
                gated_in += 1
                triage = incident_response_agent.triage(db, incident, risk_assessment)
                decision = incident_commander_agent.decide(db, incident, triage)
            else:
                decision = incident_commander_agent.skip(db, incident, risk_assessment)
            decisions_by_type[decision.decision.value] = decisions_by_type.get(decision.decision.value, 0) + 1
        summary["commander_decisions"] = decisions_by_type
        summary["incidents_gated_into_triage"] = gated_in

        # Rank this batch's incidents by risk so the Commander's inbox can
        # surface the highest-risk cases first, independent of recommended/
        # skipped status.
        analyses = (
            db.query(ThreatAnalysis)
            .filter(ThreatAnalysis.incident_id.in_([i.id for i in incidents]))
            .order_by(ThreatAnalysis.risk_score.desc())
            .all()
        )
        for rank, analysis in enumerate(analyses, start=1):
            analysis.risk_rank = rank
        db.commit()

        return summary
    finally:
        db.close()


if __name__ == "__main__":
    import json

    print(json.dumps(run_bootstrap(), indent=2, default=str))
