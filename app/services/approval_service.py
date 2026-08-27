"""Human-in-the-loop containment approval.

The Commander never executes remediation. For incidents warranting
containment it files a ContainmentApproval (status: pending) previewing
which SOAR playbooks would run. This service is the only path from that
request to actual execution: a human approves (playbooks run, incident
marked contained) or rejects (nothing runs). Both outcomes record who
decided, when, and why -- the audit trail is the point.

Neither outcome is a dead end, though: a rejection, or an approval that
turns out to match no SOAR playbook (containment wasn't actually possible),
is fed straight back to incident_commander_agent.handle_containment_outcome()
so the incident falls back to the next response tier (ESCALATE) instead of
sitting on a containment request that was never going to execute.
"""
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.agents import incident_commander_agent
from app.models import (
    ApprovalStatus,
    ContainmentApproval,
    ContainmentOutcome,
    Incident,
    IncidentStatus,
    PlaybookExecution,
)
from app.services import soar_engine


class ApprovalNotPending(Exception):
    """Raised when acting on an approval that doesn't exist or was already decided."""


def _load_pending(db: Session, approval_id: str) -> ContainmentApproval:
    approval = db.get(ContainmentApproval, approval_id)
    if approval is None:
        raise ApprovalNotPending(f"No containment approval with id {approval_id}")
    if approval.status != ApprovalStatus.PENDING:
        raise ApprovalNotPending(
            f"Approval {approval_id} was already {approval.status.value} by {approval.decided_by}"
        )
    return approval


def approve_containment(
    db: Session, approval_id: str, approver: str, note: str = ""
) -> tuple[ContainmentApproval, list[PlaybookExecution]]:
    approval = _load_pending(db, approval_id)
    approval.status = ApprovalStatus.APPROVED
    approval.decided_at = datetime.now(timezone.utc)
    approval.decided_by = approver
    approval.decision_note = note

    incident = db.get(Incident, approval.incident_id)
    executions = soar_engine.evaluate_and_execute(db, incident)
    if executions:
        incident.status = IncidentStatus.CONTAINED
    db.commit()

    if not executions:
        # Approved, but nothing actually matched -- containment isn't
        # possible for this incident as currently understood. Send it back
        # to the Commander to fall back to the next response tier rather
        # than leaving it "approved" with no effect.
        incident_commander_agent.handle_containment_outcome(
            db, incident, approval, ContainmentOutcome.NO_PLAYBOOK_MATCH, note
        )

    return approval, executions


def reject_containment(db: Session, approval_id: str, approver: str, note: str = "") -> ContainmentApproval:
    approval = _load_pending(db, approval_id)
    approval.status = ApprovalStatus.REJECTED
    approval.decided_at = datetime.now(timezone.utc)
    approval.decided_by = approver
    approval.decision_note = note
    db.commit()

    incident = db.get(Incident, approval.incident_id)
    incident_commander_agent.handle_containment_outcome(
        db, incident, approval, ContainmentOutcome.REJECTED, note
    )

    return approval
