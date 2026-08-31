"""Incident Commander Agent.

Final authority in the pipeline, bookending every incident around the
Threat Analyzer and IR Agent:

- `gate()` runs first, straight off the correlated Incident -- before the IR
  Agent does anything. It delegates to the Threat Analyzer Agent
  (threat_analyzer_agent.py), which correlates Inventory/Vulnerability
  Management/Threat Intel data into a risk score and recommendation. The
  Commander itself does no scoring here; it just acts on the Analyzer's
  `RiskAssessment.recommended`. Incidents the Analyzer doesn't recommend
  never reach the IR Agent -- `skip()` records a direct MONITOR decision
  for them instead, citing the Analyzer's rationale.
- `decide()` runs after the IR Agent's triage, for anything the Analyzer did
  recommend, and picks the response tier. Remediation is never automatic
  (HITL): the strongest decision here is to QUEUE containment for human
  approval -- SOAR playbooks execute only when a person approves the
  resulting ContainmentApproval (services/approval_service.py).

    critical  -> CONTAIN_PENDING_APPROVAL (file containment request, wait for a human)
    high      -> ESCALATE                 (page on-call, file ticket, wait for a human)
    medium/low -> MONITOR                 (no action, just recorded)

- `request_reanalysis()` is the disagreement path: a human commander who
  believes the Analyzer under-rated an incident can ask for it to be
  recomputed with a stated reason and an optional risk-rating floor. It is
  a bounded escalation, not a loop -- one retry per incident, and the floor
  can only raise the rating, never suppress it (see threat_analyzer_agent's
  `_RATING_ORDER` comment). Both the prior and resulting assessment are
  recorded in a CommanderReanalysisRequest row for audit.
- `handle_containment_outcome()` is the other feedback loop: HITL rejected a
  ContainmentApproval, or approved one that turned out to match no SOAR
  playbook (services/approval_service.py calls this in both cases). The
  Commander falls back to the next response tier down from
  CONTAIN_PENDING_APPROVAL -- ESCALATE -- rather than leaving the incident
  stuck on a request that isn't going to execute. This is terminal, not a
  loop: ESCALATE files no approval of its own, so there's nothing further to
  reject or fail.
- `manual_override()` is the break-glass path: a human sets the response tier
  directly, bypassing the Threat Analyzer's scoring and decide()'s
  criticality mapping entirely. Requires both a reason and a named approver
  -- a higher audit bar than the two loops above, since this is the one place
  a human overrides the deterministic pipeline outright rather than sending
  it back through it. Intended for once request_reanalysis()'s one retry is
  exhausted and a human still disagrees, but not gated on that state.
"""
from sqlalchemy.orm import Session

from app.agents import llm_reasoning
from app.agents.context import RiskAssessment, TriageReport
from app.agents.response.aws import dispatch_aws_playbooks
from app.agents.threat_analyzer_agent import threat_analyzer_agent
from app.models import (
    AlertSeverity,
    CommanderContainmentReview,
    CommanderDecision,
    CommanderManualOverride,
    CommanderReanalysisRequest,
    ContainmentApproval,
    ContainmentOutcome,
    Incident,
    ReasoningMode,
    ResponseDecision,
    ResponseTask,
    ThreatAnalysis,
)
from app.services import soar_engine


class ReanalysisAlreadyRequested(Exception):
    """Raised when an incident has already used its one re-analysis retry."""


class NoFallbackAvailable(Exception):
    """Raised if handle_containment_outcome() is asked to review a decision
    that has no next tier to fall back to (only CONTAIN_PENDING_APPROVAL
    does today)."""

_DECISION_BY_CRITICALITY = {
    "critical": ResponseDecision.CONTAIN_PENDING_APPROVAL,
    "high": ResponseDecision.ESCALATE,
    "medium": ResponseDecision.MONITOR,
    "low": ResponseDecision.MONITOR,
}

# The next response tier down when the current one can't proceed. Only
# CONTAIN_PENDING_APPROVAL has anywhere to fall back to -- ESCALATE and
# MONITOR don't file an approval in the first place, so there's nothing for
# HITL to reject or fail on them.
_FALLBACK_DECISION = {
    ResponseDecision.CONTAIN_PENDING_APPROVAL: ResponseDecision.ESCALATE,
}

_OUTCOME_REASON = {
    ContainmentOutcome.REJECTED: "the containment request was rejected by human review",
    ContainmentOutcome.NO_PLAYBOOK_MATCH: "approval was granted, but no SOAR playbook matched this incident -- containment wasn't actually possible",
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


def _deterministic_skip_summary(incident: Incident, risk_assessment: RiskAssessment) -> str:
    return f"{incident.title} — {risk_assessment.rationale} No IR Agent triage run."


def supersede_commander_decision(db: Session, decision: CommanderDecision | None) -> None:
    """Deletes an existing CommanderDecision so a replacement can be recorded
    in its place (CommanderDecision.incident_id is unique -- there's only ever
    one current decision per incident). Flushes but doesn't commit; callers
    add the replacement and commit both in the same transaction. Shared by
    both places that replace rather than append a decision:
    handle_containment_outcome() below, and the reanalyze API route when a
    skipped incident flips into full triage."""
    if decision is not None:
        db.delete(decision)
        db.flush()


class IncidentCommanderAgent:
    def gate(self, db: Session, incident: Incident) -> RiskAssessment:
        """Delegates the pre-triage risk assessment to the Threat Analyzer
        Agent. Callers should route to `incident_response_agent.triage()`
        (passing this same RiskAssessment, to avoid re-querying) when
        `.recommended` is True, or call `skip()` otherwise."""
        return threat_analyzer_agent.analyze(db, incident)

    def skip(self, db: Session, incident: Incident, risk_assessment: RiskAssessment) -> CommanderDecision:
        """Records a direct MONITOR decision for an incident the Threat
        Analyzer didn't recommend -- no IncidentTriage row, no evidence
        plan, no response sub-agents spawned for it."""
        commander_decision = CommanderDecision(
            incident_id=incident.id,
            decision=ResponseDecision.MONITOR,
            summary=_deterministic_skip_summary(incident, risk_assessment),
            reasoning_mode=ReasoningMode.DETERMINISTIC,
        )
        db.add(commander_decision)
        db.commit()
        return commander_decision

    def request_reanalysis(
        self,
        db: Session,
        incident: Incident,
        reason: str,
        override_floor: AlertSeverity | None = None,
    ) -> RiskAssessment:
        """A human commander disagrees with the current ThreatAnalysis and
        wants it recomputed. `reason` is required and stored for audit;
        `override_floor`, if given, raises the resulting rating to at least
        that level (never lowers it -- see threat_analyzer_agent). Capped
        at one request per incident: a second call raises
        ReanalysisAlreadyRequested rather than looping. Callers should
        re-run the recommended/skip routing (triage() or skip()) against
        the returned RiskAssessment, since `.recommended` may have flipped.
        """
        prior = db.query(ThreatAnalysis).filter_by(incident_id=incident.id).one_or_none()
        if prior is not None and prior.revision > 1:
            raise ReanalysisAlreadyRequested(
                f"Incident {incident.id} was already re-analyzed once (revision {prior.revision}); "
                "escalate to a human decision instead of requesting another automated pass."
            )
        prior_score = prior.risk_score if prior else 0.0
        prior_rating = prior.risk_rating if prior else AlertSeverity.LOW
        prior_recommended = prior.recommended if prior else False

        risk_assessment = threat_analyzer_agent.analyze(
            db, incident, override_floor=override_floor, override_reason=reason
        )

        db.add(
            CommanderReanalysisRequest(
                incident_id=incident.id,
                reason=reason,
                requested_floor=override_floor,
                prior_risk_score=prior_score,
                prior_risk_rating=prior_rating,
                prior_recommended=prior_recommended,
                new_risk_score=risk_assessment.risk_score,
                new_risk_rating=AlertSeverity(risk_assessment.risk_rating),
                new_recommended=risk_assessment.recommended,
            )
        )
        db.commit()
        return risk_assessment

    def handle_containment_outcome(
        self,
        db: Session,
        incident: Incident,
        approval: ContainmentApproval,
        outcome: ContainmentOutcome,
        note: str = "",
    ) -> CommanderDecision:
        """Containment didn't happen -- HITL rejected it, or approved it but
        no playbook matched. Replaces the stale CONTAIN_PENDING_APPROVAL
        CommanderDecision with the next tier down (today, always ESCALATE)
        and logs a CommanderContainmentReview for audit. Raises
        NoFallbackAvailable if called against a decision with no fallback
        (shouldn't happen in practice -- only CONTAIN_PENDING_APPROVAL files
        an approval at all)."""
        prior_decision = db.query(CommanderDecision).filter_by(incident_id=incident.id).one_or_none()
        prior_response = prior_decision.decision if prior_decision else ResponseDecision.CONTAIN_PENDING_APPROVAL
        fallback = _FALLBACK_DECISION.get(prior_response)
        if fallback is None:
            raise NoFallbackAvailable(
                f"No fallback response tier defined for {prior_response.value} on incident {incident.id}"
            )

        deterministic_text = (
            f"{incident.title} — containment did not proceed because {_OUTCOME_REASON[outcome]}"
            f"{f' ({note})' if note else ''}. Falling back to {fallback.value.upper()}: "
            "escalated to on-call for manual response."
        )
        summary, mode = llm_reasoning.reason(
            system_prompt=(
                "You are the Incident Commander in a security operations center. A containment "
                "request you filed did not go through as planned. Write a brief (2-4 sentence) "
                "executive summary explaining why, and what response tier the incident is falling "
                "back to instead."
            ),
            user_prompt=(
                f"Incident: {incident.title}\n"
                f"Original decision: {prior_response.value}\n"
                f"Why containment didn't proceed: {_OUTCOME_REASON[outcome]}\n"
                f"Reviewer note: {note or 'none'}\n"
                f"Fallback response tier: {fallback.value}\n"
            ),
            fallback_text=deterministic_text,
            model=llm_reasoning.COMMANDER_MODEL,
        )

        supersede_commander_decision(db, prior_decision)
        new_decision = CommanderDecision(
            incident_id=incident.id,
            decision=fallback,
            summary=summary,
            reasoning_mode=ReasoningMode(mode),
        )
        db.add(new_decision)
        db.add(
            CommanderContainmentReview(
                incident_id=incident.id,
                approval_id=approval.id,
                outcome=outcome,
                note=note,
                prior_decision=prior_response,
                new_decision=fallback,
            )
        )
        db.commit()
        return new_decision

    def manual_override(
        self,
        db: Session,
        incident: Incident,
        decision: ResponseDecision,
        reason: str,
        approver: str,
    ) -> CommanderDecision:
        """Break-glass: a human sets the response tier directly, bypassing
        the Threat Analyzer and decide()'s criticality mapping outright.
        Requires a non-empty `reason` and a named `approver` -- unlike
        request_reanalysis() (still scored by the Analyzer) or
        handle_containment_outcome() (only ever falls back), this is a human
        overriding the deterministic pipeline's conclusion entirely, so it
        gets the highest audit bar of the three feedback paths. Replaces any
        existing CommanderDecision. If the override decision is
        CONTAIN_PENDING_APPROVAL, files a ContainmentApproval exactly as
        decide() would -- overriding the response *tier* never bypasses
        execution approval -- unless one already exists for this incident
        (ContainmentApproval is one-per-incident; re-requesting containment
        after a prior approval was already decided isn't supported yet)."""
        if not reason or not reason.strip():
            raise ValueError("manual_override requires a reason")
        if not approver or not approver.strip():
            raise ValueError("manual_override requires a named approver")

        prior_decision = db.query(CommanderDecision).filter_by(incident_id=incident.id).one_or_none()
        prior_response = prior_decision.decision if prior_decision else None
        supersede_commander_decision(db, prior_decision)

        summary = (
            f"{incident.title} — manual override by {approver}: {reason} "
            f"(response tier set to {decision.value.upper()})"
        )
        new_decision = CommanderDecision(
            incident_id=incident.id,
            decision=decision,
            summary=summary,
            reasoning_mode=ReasoningMode.HUMAN_OVERRIDE,
        )
        db.add(new_decision)
        db.add(
            CommanderManualOverride(
                incident_id=incident.id,
                decision=decision,
                reason=reason,
                approver=approver,
                prior_decision=prior_response,
            )
        )
        if decision == ResponseDecision.CONTAIN_PENDING_APPROVAL:
            existing_approval = db.query(ContainmentApproval).filter_by(incident_id=incident.id).one_or_none()
            if existing_approval is None:
                would_run = soar_engine.matching_playbooks(db, incident)
                preview = (
                    "; ".join(f"{p.name} ({p.actions})" for p in would_run)
                    or "No SOAR playbooks currently match; approval would execute nothing."
                )
                db.add(ContainmentApproval(incident_id=incident.id, requested_actions=preview))
        db.commit()
        return new_decision

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
