"""Incident Commander Agent.

Gatekeeper *and* final authority in the pipeline. Bookends every incident:

- `gate()` runs first, straight off the correlated Incident -- before the IR
  Agent does anything. It only looks at cheap signals (incident severity/
  confidence, plus one Inventory Agent lookup) and decides whether the
  incident is worth the full triage pipeline (vuln/threat-intel lookups,
  evidence planning, response sub-agent dispatch, LLM rationale) at all.
  Incidents that don't clear the gate never reach the IR Agent -- `skip()`
  records a direct MONITOR decision for them instead.
- `decide()` runs after the IR Agent's triage, for anything that did clear
  the gate, and picks the response tier. Remediation is never automatic
  (HITL): the strongest decision here is to QUEUE containment for human
  approval -- SOAR playbooks execute only when a person approves the
  resulting ContainmentApproval (services/approval_service.py).

    critical  -> CONTAIN_PENDING_APPROVAL (file containment request, wait for a human)
    high      -> ESCALATE                 (page on-call, file ticket, wait for a human)
    medium/low -> MONITOR                 (no action, just recorded)
"""
from sqlalchemy.orm import Session

from app.agents import llm_reasoning
from app.agents.context import TriageReport
from app.agents.inventory_agent import inventory_agent
from app.agents.response.aws import dispatch_aws_playbooks
from app.models import (
    AlertSeverity,
    CommanderDecision,
    ContainmentApproval,
    Incident,
    ReasoningMode,
    ResponseDecision,
    ResponseTask,
)
from app.services import soar_engine

_DECISION_BY_CRITICALITY = {
    "critical": ResponseDecision.CONTAIN_PENDING_APPROVAL,
    "high": ResponseDecision.ESCALATE,
    "medium": ResponseDecision.MONITOR,
    "low": ResponseDecision.MONITOR,
}

# Gate thresholds: an incident routes into full triage if it clears any one
# of these. Deliberately generous (an OR, not an AND) -- the gate exists to
# filter obvious background noise, not to second-guess the IR Agent's own
# weighted scoring. Tune alongside incident_response_agent._WEIGHTS if the
# two start disagreeing about what counts as "worth a look."
_GATE_MIN_CONFIDENCE = 0.4
_GATE_MIN_ASSET_CRITICALITY = 4


def _deterministic_summary(incident: Incident, triage: TriageReport, decision: ResponseDecision) -> str:
    action = {
        ResponseDecision.CONTAIN_PENDING_APPROVAL: (
            "Containment queued for human approval; no automated action until an analyst approves."
        ),
        ResponseDecision.ESCALATE: "Escalated to on-call for human review before containment action.",
        ResponseDecision.MONITOR: "No response action taken; logged for situational awareness.",
    }[decision]
    return f"{incident.title} — {triage.criticality.upper()} ({triage.criticality_score}/1.0). {action}"


def _deterministic_skip_summary(incident: Incident, inventory) -> str:
    return (
        f"{incident.title} — below triage threshold (severity {incident.severity.value}, "
        f"confidence {incident.confidence}, max asset criticality {inventory.max_criticality}/5, "
        f"internet-facing: {inventory.has_internet_facing_asset}). Monitored without full triage."
    )


class IncidentCommanderAgent:
    def gate(self, db: Session, incident: Incident) -> bool:
        """Cheap pre-triage screen. True routes the incident into the IR
        Agent's full pipeline; False means `skip()` should be called instead."""
        if incident.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
            return True
        if incident.confidence >= _GATE_MIN_CONFIDENCE:
            return True
        asset_ids = list({a.asset_id for a in incident.alerts})
        inventory = inventory_agent.get_context(db, asset_ids)
        return (
            inventory.has_internet_facing_asset
            or inventory.max_criticality >= _GATE_MIN_ASSET_CRITICALITY
        )

    def skip(self, db: Session, incident: Incident) -> CommanderDecision:
        """Records a direct MONITOR decision for an incident that didn't
        clear `gate()` -- no IncidentTriage row, no evidence plan, no
        response sub-agents spawned for it."""
        asset_ids = list({a.asset_id for a in incident.alerts})
        inventory = inventory_agent.get_context(db, asset_ids)
        commander_decision = CommanderDecision(
            incident_id=incident.id,
            decision=ResponseDecision.MONITOR,
            summary=_deterministic_skip_summary(incident, inventory),
            reasoning_mode=ReasoningMode.DETERMINISTIC,
        )
        db.add(commander_decision)
        db.commit()
        return commander_decision

    def decide(self, db: Session, incident: Incident, triage: TriageReport) -> CommanderDecision:
        decision = _DECISION_BY_CRITICALITY[triage.criticality]

        # The Commander's call is what activates AWS IRP playbooks: only an
        # ESCALATE/CONTAIN_PENDING_APPROVAL decision routes the incident into
        # the cloud playbook sub-agents (finding-type-triggered, see
        # agents/response/aws). These are recommendations, safe pre-approval.
        aws_plans = dispatch_aws_playbooks(incident, decision)

        deterministic_text = _deterministic_summary(incident, triage, decision)
        if aws_plans:
            deterministic_text += (
                " AWS IRP playbooks activated: "
                + "; ".join(p.runbook_name for p in aws_plans) + "."
            )

        summary, mode = llm_reasoning.reason(
            system_prompt=(
                "You are the Incident Commander in a security operations center. Given an "
                "IR analyst's triage rationale and your response decision, write a brief "
                "(2-4 sentence) executive summary suitable for a leadership incident channel. "
                "State the decision plainly and why."
            ),
            user_prompt=(
                f"Incident: {incident.title}\n"
                f"Triage rationale: {triage.rationale}\n"
                f"Response decision: {decision.value}\n"
                f"AWS IRP playbooks activated by this decision: "
                f"{'; '.join(p.runbook_name for p in aws_plans) or 'none'}\n"
            ),
            fallback_text=deterministic_text,
            model=llm_reasoning.COMMANDER_MODEL,
        )

        commander_decision = CommanderDecision(
            incident_id=incident.id,
            decision=decision,
            summary=summary,
            reasoning_mode=ReasoningMode(mode),
        )
        db.add(commander_decision)
        for plan in aws_plans:
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
                        dispatched_by="commander",
                    )
                )
        if decision == ResponseDecision.CONTAIN_PENDING_APPROVAL:
            # HITL gate: file the containment request with a preview of what
            # approval would execute. Nothing runs until a human approves.
            would_run = soar_engine.matching_playbooks(db, incident)
            preview = (
                "; ".join(f"{p.name} ({p.actions})" for p in would_run)
                or "No SOAR playbooks currently match; approval would execute nothing."
            )
            db.add(ContainmentApproval(incident_id=incident.id, requested_actions=preview))
        db.commit()

        return commander_decision


incident_commander_agent = IncidentCommanderAgent()
