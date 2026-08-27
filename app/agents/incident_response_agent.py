"""Incident Response Agent.

Owns triage: given a correlated Incident (and the Threat Analyzer Agent's
risk assessment of it), build the evidence collection plan, spawn IRP
response sub-agents, and hand a structured TriageReport to the Incident
Commander Agent for a response decision. This is the "hub" agent -- it
doesn't have its own domain expertise so much as it knows how to synthesize
everyone else's.

Criticality scoring itself lives in threat_analyzer_agent.py -- the Threat
Analyzer already computed it (and gathered the Inventory/Vulnerability/
Threat Intel context) before this agent ever runs, so triage() reuses that
RiskAssessment rather than re-querying. The rationale *text* here elaborates
on it with evidence/response-plan detail, optionally through an LLM pass
(see llm_reasoning.py), with a deterministic fallback always available.
"""
from sqlalchemy.orm import Session

from app.agents import llm_reasoning
from app.agents.context import RiskAssessment, TriageReport
from app.agents.evidence_planner import build_evidence_plan
from app.agents.response import dispatch_response_subagents
from app.agents.threat_analyzer_agent import threat_analyzer_agent
from app.models import AlertSeverity, EvidenceItem, Incident, IncidentTriage, ReasoningMode, ResponseTask


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
        f"{f.cve_id} on {f.hostname} (CVSS {f.cvss_score}"
        f"{', KEV' if f.kev_listed else ''}"
        f"{', ransomware-associated' if f.kev_ransomware_use else ''}"
        f"{f', remediation due {f.kev_due_date}' if f.kev_due_date else ''})"
        for f in vuln_mgmt.findings
    )


def _threat_intel_summary(threat_intel) -> str:
    if not threat_intel.ioc_matches and not threat_intel.actor_matches:
        return "No IOC hits or TTP overlap with tracked threat actor profiles."
    bits = [f"IOC: {m.value} ({m.indicator_type}, {m.threat_actor_name or 'unattributed'})" for m in threat_intel.ioc_matches]
    bits += [f"TTP overlap: {a.threat_actor_name} ({int(a.technique_overlap * 100)}%)" for a in threat_intel.actor_matches]
    return "; ".join(bits)


def _response_plan_summary(response_plans) -> str:
    if not response_plans:
        return "No IRP category matched; no specialized runbook spawned."
    return "; ".join(
        f"{p.runbook_name} ({len(p.steps)} step(s), triggered by {', '.join(p.triggered_by_technique_ids) or 'behavioral match'})"
        for p in response_plans
    )


def _evidence_summary(evidence_plan) -> str:
    if not evidence_plan:
        return "No evidence items identified."
    return "; ".join(
        f"{e.evidence_type} from {e.asset_hostname} ({e.source})"
        f"{' [IOC-tied]' if e.tied_to_threat_intel else ''}"
        for e in evidence_plan
    )


class IncidentResponseAgent:
    def triage(self, db: Session, incident: Incident, risk_assessment: RiskAssessment | None = None) -> TriageReport:
        if risk_assessment is None:
            # Direct callers (tests, ad-hoc scripts) that skip the Commander's
            # gate still get a correct triage -- the Threat Analyzer just runs
            # inline instead of being reused from an earlier gate() call.
            risk_assessment = threat_analyzer_agent.analyze(db, incident)

        inventory = risk_assessment.inventory
        vuln_mgmt = risk_assessment.vuln_management
        threat_intel = risk_assessment.threat_intel
        evidence_plan = build_evidence_plan(incident.alerts, threat_intel)
        response_plans = dispatch_response_subagents(incident)

        score = risk_assessment.risk_score
        criticality = AlertSeverity(risk_assessment.risk_rating)
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
                f"Response runbooks spawned: {_response_plan_summary(response_plans)}\n"
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
                response_plan_summary=_response_plan_summary(response_plans),
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
        for plan in response_plans:
            for step in plan.steps:
                db.add(
                    ResponseTask(
                        incident_id=incident.id,
                        category=plan.category,
                        runbook_name=plan.runbook_name,
                        phase=step.phase,
                        step_order=step.order,
                        action=step.action,
                        scope_hostname=step.scope_hostname,
                        triggered_by_technique_ids=",".join(plan.triggered_by_technique_ids),
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
            response_plans=response_plans,
        )


incident_response_agent = IncidentResponseAgent()
