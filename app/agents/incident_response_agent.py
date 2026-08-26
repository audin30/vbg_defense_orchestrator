"""Incident Response Agent.

Owns triage: given a correlated Incident, gather everything the other
specialist agents know about it, compute a criticality assessment, and hand
a structured TriageReport to the Incident Commander Agent for a response
decision. This is the "hub" agent -- it doesn't have its own domain
expertise so much as it knows how to synthesize everyone else's.

Criticality scoring is deterministic and weighted (see _WEIGHTS below); the
rationale *text* explaining the score optionally gets an LLM pass (see
llm_reasoning.py) for a more readable narrative, with a deterministic
fallback that's always available.
"""
from sqlalchemy.orm import Session

from app.agents import llm_reasoning
from app.agents.context import TriageReport
from app.agents.evidence_planner import build_evidence_plan
from app.agents.inventory_agent import inventory_agent
from app.agents.threat_intel_agent import threat_intel_agent
from app.agents.vulnerability_agent import vulnerability_agent
from app.models import AlertSeverity, EvidenceItem, Incident, IncidentTriage, ReasoningMode

# Deterministic criticality-score weights. Each bounded contribution sums to
# at most 1.0. Tune these to match your org's risk appetite -- e.g. raise
# KEV_BONUS if actively-exploited CVEs should dominate the assessment.
_SEVERITY_VALUE = {
    AlertSeverity.LOW: 0.25,
    AlertSeverity.MEDIUM: 0.5,
    AlertSeverity.HIGH: 0.75,
    AlertSeverity.CRITICAL: 1.0,
}
_CONFIDENCE_WEIGHT = 0.25
_SEVERITY_WEIGHT = 0.20
_ASSET_CRITICALITY_WEIGHT = 0.20
_EXPOSURE_BONUS = 0.10
_KEV_BONUS = 0.15
_THREAT_INTEL_BONUS = 0.10

_CRITICALITY_THRESHOLDS = [
    (0.75, AlertSeverity.CRITICAL),
    (0.50, AlertSeverity.HIGH),
    (0.30, AlertSeverity.MEDIUM),
]


def _bucket(score: float) -> AlertSeverity:
    for threshold, level in _CRITICALITY_THRESHOLDS:
        if score >= threshold:
            return level
    return AlertSeverity.LOW


def _score(incident: Incident, inventory, vuln_mgmt, threat_intel) -> float:
    score = 0.0
    score += _CONFIDENCE_WEIGHT * incident.confidence
    score += _SEVERITY_WEIGHT * _SEVERITY_VALUE[incident.severity]
    score += _ASSET_CRITICALITY_WEIGHT * (inventory.max_criticality / 5)
    score += _EXPOSURE_BONUS if inventory.has_internet_facing_asset else 0.0
    score += _KEV_BONUS if vuln_mgmt.has_kev_listed else 0.0
    score += _THREAT_INTEL_BONUS if threat_intel.has_ioc_hit else _THREAT_INTEL_BONUS * threat_intel.top_actor_overlap
    return round(min(score, 1.0), 2)


def _deterministic_rationale(incident: Incident, inventory, vuln_mgmt, threat_intel, criticality, score) -> str:
    parts = [
        f"{criticality.value.upper()} (score {score}): correlation confidence {incident.confidence}, "
        f"{len(incident.alerts)} alert(s) across {len(inventory.assets)} asset(s)."
    ]
    if inventory.has_internet_facing_asset:
        parts.append("At least one affected asset is internet-facing.")
    if inventory.max_criticality >= 4:
        parts.append(f"Highest affected asset criticality: {inventory.max_criticality}/5.")
    if vuln_mgmt.has_kev_listed:
        cves = ", ".join(f.cve_id for f in vuln_mgmt.findings if f.kev_listed)
        parts.append(f"Affected asset(s) have known-exploited vulnerabilities open: {cves}.")
    if threat_intel.ioc_matches:
        actors = {m.threat_actor_name for m in threat_intel.ioc_matches if m.threat_actor_name}
        parts.append(f"Threat intel IOC match(es) found, linked to: {', '.join(actors) or 'unattributed indicator'}.")
    if threat_intel.actor_matches:
        top = threat_intel.actor_matches[0]
        parts.append(
            f"TTP pattern overlaps {int(top.technique_overlap * 100)}% with {top.threat_actor_name} "
            f"({', '.join(top.matched_technique_ids)})."
        )
    return " ".join(parts)


def _asset_summary(inventory) -> str:
    if not inventory.assets:
        return "No asset context available."
    return "; ".join(
        f"{a.hostname} (crit {a.criticality}/5, {a.exposure}, biz unit: {a.business_unit})"
        for a in inventory.assets
    )


def _vuln_summary(vuln_mgmt) -> str:
    if not vuln_mgmt.findings:
        return "No open vulnerabilities on affected assets."
    return "; ".join(
        f"{f.cve_id} on {f.hostname} (CVSS {f.cvss_score}{' , KEV' if f.kev_listed else ''})"
        for f in vuln_mgmt.findings
    )


def _threat_intel_summary(threat_intel) -> str:
    if not threat_intel.ioc_matches and not threat_intel.actor_matches:
        return "No IOC hits or TTP overlap with tracked threat actor profiles."
    bits = [f"IOC: {m.value} ({m.indicator_type}, {m.threat_actor_name or 'unattributed'})" for m in threat_intel.ioc_matches]
    bits += [f"TTP overlap: {a.threat_actor_name} ({int(a.technique_overlap * 100)}%)" for a in threat_intel.actor_matches]
    return "; ".join(bits)


def _evidence_summary(evidence_plan) -> str:
    if not evidence_plan:
        return "No evidence items identified."
    return "; ".join(
        f"{e.evidence_type} from {e.asset_hostname} ({e.source})"
        f"{' [IOC-tied]' if e.tied_to_threat_intel else ''}"
        for e in evidence_plan
    )


class IncidentResponseAgent:
    def triage(self, db: Session, incident: Incident) -> TriageReport:
        asset_ids = list({a.asset_id for a in incident.alerts})

        inventory = inventory_agent.get_context(db, asset_ids)
        vuln_mgmt = vulnerability_agent.get_context(db, asset_ids)
        threat_intel = threat_intel_agent.get_context(db, incident.alerts)
        evidence_plan = build_evidence_plan(incident.alerts, threat_intel)

        score = _score(incident, inventory, vuln_mgmt, threat_intel)
        criticality = _bucket(score)
        deterministic_text = _deterministic_rationale(incident, inventory, vuln_mgmt, threat_intel, criticality, score)

        rationale, mode = llm_reasoning.reason(
            system_prompt=(
                "You are a Tier-1 incident response analyst. Write a concise (3-5 sentence) "
                "triage rationale for a security incident, given structured findings from the "
                "Inventory, Vulnerability Management, and Threat Intel agents, plus the evidence "
                "collection plan. Be direct and specific about why this incident warrants its "
                "assigned criticality, and note anything evidence-collection-worthy."
            ),
            user_prompt=(
                f"Incident: {incident.title}\n"
                f"Correlation confidence: {incident.confidence}\n"
                f"Assigned criticality: {criticality.value} (score {score}/1.0)\n"
                f"Assets involved: {_asset_summary(inventory)}\n"
                f"Open vulnerabilities: {_vuln_summary(vuln_mgmt)}\n"
                f"Threat intel: {_threat_intel_summary(threat_intel)}\n"
                f"Evidence to preserve: {_evidence_summary(evidence_plan)}\n"
            ),
            fallback_text=deterministic_text,
            model=llm_reasoning.TRIAGE_MODEL,
        )

        db.add(
            IncidentTriage(
                incident_id=incident.id,
                criticality=criticality,
                criticality_score=score,
                asset_context_summary=_asset_summary(inventory),
                vuln_context_summary=_vuln_summary(vuln_mgmt),
                threat_intel_summary=_threat_intel_summary(threat_intel),
                evidence_summary=_evidence_summary(evidence_plan),
                rationale=rationale,
                reasoning_mode=ReasoningMode(mode),
            )
        )
        for item in evidence_plan:
            db.add(
                EvidenceItem(
                    incident_id=incident.id,
                    asset_hostname=item.asset_hostname,
                    evidence_type=item.evidence_type,
                    source=item.source,
                    justification=item.justification,
                    related_technique_id=item.related_technique_id,
                    related_ioc_value=item.related_ioc_value,
                )
            )
        db.commit()

        return TriageReport(
            incident_id=incident.id,
            criticality=criticality.value,
            criticality_score=score,
            inventory=inventory,
            vuln_management=vuln_mgmt,
            threat_intel=threat_intel,
            evidence_plan=evidence_plan,
            rationale=rationale,
            reasoning_mode=mode,
        )


incident_response_agent = IncidentResponseAgent()
