from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.bootstrap import run_bootstrap
from app.db import get_db
from app.models import (
    Alert,
    Asset,
    CommanderDecision,
    DetectionRule,
    EvidenceItem,
    Incident,
    IncidentTriage,
    Playbook,
    PlaybookExecution,
    ResponseTask,
    ThreatActorProfile,
    ThreatIndicator,
    Vulnerability,
)
from app.services.attack_mapping import coverage_by_tactic, uncovered_techniques
from app.services.vuln_prioritization import ranked_vulnerabilities

router = APIRouter()


def _asset_dict(a: Asset) -> dict:
    return {
        "id": a.id,
        "hostname": a.hostname,
        "ip_address": a.ip_address,
        "criticality": a.criticality,
        "exposure": a.exposure.value,
        "data_sensitivity": a.data_sensitivity,
        "business_unit": a.business_unit,
        "tags": a.tags,
    }


def _vuln_dict(v: Vulnerability) -> dict:
    return {
        "id": v.id,
        "cve_id": v.cve_id,
        "title": v.title,
        "cvss_score": v.cvss_score,
        "epss_score": v.epss_score,
        "kev_listed": v.kev_listed,
        "status": v.status.value,
        "risk_score": v.risk_score,
        "asset": _asset_dict(v.asset),
    }


def _alert_dict(a: Alert) -> dict:
    return {
        "id": a.id,
        "source": a.source,
        "title": a.title,
        "description": a.description,
        "severity": a.severity.value,
        "asset_hostname": a.asset.hostname,
        "attack_technique_id": a.attack_technique_id,
        "occurred_at": a.occurred_at.isoformat(),
        "incident_id": a.incident_id,
    }


def _evidence_item_dict(e: EvidenceItem) -> dict:
    return {
        "id": e.id,
        "asset_hostname": e.asset_hostname,
        "evidence_type": e.evidence_type,
        "source": e.source,
        "justification": e.justification,
        "related_technique_id": e.related_technique_id,
        "related_ioc_value": e.related_ioc_value,
        "tied_to_threat_intel": e.related_ioc_value is not None,
    }


def _response_task_dict(t: ResponseTask) -> dict:
    return {
        "id": t.id,
        "incident_id": t.incident_id,
        "category": t.category,
        "runbook_name": t.runbook_name,
        "phase": t.phase,
        "step_order": t.step_order,
        "action": t.action,
        "scope_hostname": t.scope_hostname,
        "triggered_by_technique_ids": [x for x in t.triggered_by_technique_ids.split(",") if x],
        "dispatched_by": t.dispatched_by,
        "status": t.status.value,
    }


def _triage_dict(t: IncidentTriage | None, db: Session) -> dict | None:
    if t is None:
        return None
    evidence_items = db.query(EvidenceItem).filter_by(incident_id=t.incident_id).all()
    response_tasks = (
        db.query(ResponseTask)
        .filter_by(incident_id=t.incident_id, dispatched_by="ir_agent")
        .order_by(ResponseTask.category, ResponseTask.step_order)
        .all()
    )
    return {
        "criticality": t.criticality.value,
        "criticality_score": t.criticality_score,
        "asset_context_summary": t.asset_context_summary,
        "vuln_context_summary": t.vuln_context_summary,
        "threat_intel_summary": t.threat_intel_summary,
        "evidence_summary": t.evidence_summary,
        "evidence_items": [_evidence_item_dict(e) for e in evidence_items],
        "response_plan_summary": t.response_plan_summary,
        "response_tasks": [_response_task_dict(rt) for rt in response_tasks],
        "rationale": t.rationale,
        "reasoning_mode": t.reasoning_mode.value,
        "created_at": t.created_at.isoformat(),
    }


def _commander_decision_dict(d: CommanderDecision | None, db: Session) -> dict | None:
    if d is None:
        return None
    aws_tasks = (
        db.query(ResponseTask)
        .filter_by(incident_id=d.incident_id, dispatched_by="commander")
        .order_by(ResponseTask.category, ResponseTask.step_order)
        .all()
    )
    return {
        "decision": d.decision.value,
        "summary": d.summary,
        "reasoning_mode": d.reasoning_mode.value,
        "response_tasks": [_response_task_dict(t) for t in aws_tasks],
        "created_at": d.created_at.isoformat(),
    }


def _incident_dict(i: Incident, db: Session) -> dict:
    triage = db.query(IncidentTriage).filter_by(incident_id=i.id).one_or_none()
    decision = db.query(CommanderDecision).filter_by(incident_id=i.id).one_or_none()
    return {
        "id": i.id,
        "title": i.title,
        "severity": i.severity.value,
        "status": i.status.value,
        "confidence": i.confidence,
        "primary_asset_hostname": i.asset.hostname if i.asset else None,
        "created_at": i.created_at.isoformat(),
        "alerts": [_alert_dict(a) for a in i.alerts],
        "playbook_executions": [
            {
                "id": e.id,
                "playbook_id": e.playbook_id,
                "actions_taken": e.actions_taken.split("\n"),
                "executed_at": e.executed_at.isoformat(),
            }
            for e in i.playbook_executions
        ],
        "triage": _triage_dict(triage, db),
        "commander_decision": _commander_decision_dict(decision, db),
    }


@router.post("/bootstrap")
def bootstrap():
    """Create tables (if needed), seed reference data, ingest mock sources,
    correlate incidents, and run matching playbooks. Idempotent."""
    return run_bootstrap()


@router.get("/assets")
def list_assets(db: Session = Depends(get_db)):
    return [_asset_dict(a) for a in db.query(Asset).all()]


@router.get("/vulnerabilities")
def list_vulnerabilities(limit: int = 20, db: Session = Depends(get_db)):
    return [_vuln_dict(v) for v in ranked_vulnerabilities(db, limit=limit)]


@router.get("/alerts")
def list_alerts(db: Session = Depends(get_db)):
    return [_alert_dict(a) for a in db.query(Alert).order_by(Alert.occurred_at.desc()).all()]


@router.get("/incidents")
def list_incidents(db: Session = Depends(get_db)):
    return [_incident_dict(i, db) for i in db.query(Incident).order_by(Incident.created_at.desc()).all()]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _incident_dict(incident, db)


@router.get("/attack-coverage")
def attack_coverage(db: Session = Depends(get_db)):
    return {
        "by_tactic": coverage_by_tactic(db),
        "uncovered_techniques": [
            {"id": t.id, "name": t.name, "tactic": t.tactic} for t in uncovered_techniques(db)
        ],
    }


@router.get("/detection-rules")
def list_detection_rules(db: Session = Depends(get_db)):
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "attack_technique_id": r.attack_technique_id,
            "enabled": r.enabled,
        }
        for r in db.query(DetectionRule).all()
    ]


@router.get("/playbooks")
def list_playbooks(db: Session = Depends(get_db)):
    return [
        {
            "id": p.id,
            "name": p.name,
            "trigger_attack_technique_id": p.trigger_attack_technique_id,
            "trigger_min_severity": p.trigger_min_severity.value,
            "actions": p.actions.split(","),
        }
        for p in db.query(Playbook).all()
    ]


@router.get("/threat-actor-profiles")
def list_threat_actor_profiles(db: Session = Depends(get_db)):
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "attack_technique_ids": p.associated_technique_ids.split(","),
        }
        for p in db.query(ThreatActorProfile).all()
    ]


@router.get("/threat-indicators")
def list_threat_indicators(db: Session = Depends(get_db)):
    return [
        {
            "id": i.id,
            "indicator_type": i.indicator_type,
            "value": i.value,
            "confidence": i.confidence,
            "description": i.description,
            "threat_actor_name": i.threat_actor.name if i.threat_actor else None,
        }
        for i in db.query(ThreatIndicator).all()
    ]


@router.get("/evidence-items")
def list_evidence_items(db: Session = Depends(get_db)):
    return [_evidence_item_dict(e) for e in db.query(EvidenceItem).order_by(EvidenceItem.created_at.desc()).all()]


@router.get("/response-tasks")
def list_response_tasks(db: Session = Depends(get_db)):
    return [
        _response_task_dict(t)
        for t in db.query(ResponseTask)
        .order_by(ResponseTask.incident_id, ResponseTask.category, ResponseTask.step_order)
        .all()
    ]


@router.get("/playbook-executions")
def list_playbook_executions(db: Session = Depends(get_db)):
    return [
        {
            "id": e.id,
            "playbook_id": e.playbook_id,
            "incident_id": e.incident_id,
            "actions_taken": e.actions_taken.split("\n"),
            "executed_at": e.executed_at.isoformat(),
        }
        for e in db.query(PlaybookExecution).all()
    ]
