"""Incident Commander Agent.

Final authority in the pipeline: takes the IR Agent's TriageReport and
decides the response tier. This is the gate on automated containment --
only CRITICAL-scored incidents get playbooks executed automatically;
HIGH gets escalated to on-call for a human call before anything disruptive
happens; everything else is logged for situational awareness.

    critical  -> AUTO_CONTAIN  (run matching SOAR playbooks now)
    high      -> ESCALATE      (page on-call, file ticket, wait for a human)
    medium/low -> MONITOR      (no action, just recorded)
"""
from sqlalchemy.orm import Session

from app.agents import llm_reasoning
from app.agents.context import TriageReport
from app.models import CommanderDecision, Incident, ReasoningMode, ResponseDecision
from app.services import soar_engine

_DECISION_BY_CRITICALITY = {
    "critical": ResponseDecision.AUTO_CONTAIN,
    "high": ResponseDecision.ESCALATE,
    "medium": ResponseDecision.MONITOR,
    "low": ResponseDecision.MONITOR,
}


def _deterministic_summary(incident: Incident, triage: TriageReport, decision: ResponseDecision) -> str:
    action = {
        ResponseDecision.AUTO_CONTAIN: "Automated containment authorized; matching SOAR playbooks executed.",
        ResponseDecision.ESCALATE: "Escalated to on-call for human review before containment action.",
        ResponseDecision.MONITOR: "No response action taken; logged for situational awareness.",
    }[decision]
    return f"{incident.title} — {triage.criticality.upper()} ({triage.criticality_score}/1.0). {action}"


class IncidentCommanderAgent:
    def decide(self, db: Session, incident: Incident, triage: TriageReport) -> CommanderDecision:
        decision = _DECISION_BY_CRITICALITY[triage.criticality]
        deterministic_text = _deterministic_summary(incident, triage, decision)

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
        db.commit()

        if decision == ResponseDecision.AUTO_CONTAIN:
            soar_engine.evaluate_and_execute(db, incident)

        return commander_decision


incident_commander_agent = IncidentCommanderAgent()
