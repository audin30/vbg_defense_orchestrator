"""Incident Commander Agent.

Final authority in the pipeline: takes the IR Agent's TriageReport and
decides the response tier. Remediation is never automatic (HITL): the
strongest decision the Commander can make is to QUEUE containment for
human approval -- SOAR playbooks execute only when a person approves the
resulting ContainmentApproval (services/approval_service.py).

    critical  -> CONTAIN_PENDING_APPROVAL (file containment request, wait for a human)
    high      -> ESCALATE                 (page on-call, file ticket, wait for a human)
    medium/low -> MONITOR                 (no action, just recorded)
"""
from sqlalchemy.orm import Session

from app.agents import llm_reasoning
from app.agents.context import TriageReport
from app.agents.response.aws import dispatch_aws_playbooks
from app.models import (
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


def _deterministic_summary(incident: Incident, triage: TriageReport, decision: ResponseDecision) -> str:
    action = {
        ResponseDecision.CONTAIN_PENDING_APPROVAL: (
            "Containment queued for human approval; no automated action until an analyst approves."
        ),
        ResponseDecision.ESCALATE: "Escalated to on-call for human review before containment action.",
        ResponseDecision.MONITOR: "No response action taken; logged for situational awareness.",
    }[decision]
    return f"{incident.title} — {triage.criticality.upper()} ({triage.criticality_score}/1.0). {action}"


class IncidentCommanderAgent:
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
