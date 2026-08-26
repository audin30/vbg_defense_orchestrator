"""Human-in-the-loop containment approval.

The Commander never executes remediation. For incidents warranting
containment it files a ContainmentApproval (status: pending) previewing
which SOAR playbooks would run. This service is the only path from that
request to actual execution: a human approves (playbooks run, incident
marked contained) or rejects (nothing runs). Both outcomes record who
decided, when, and why -- the audit trail is the point.
"""
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import ApprovalStatus, ContainmentApproval, Incident, IncidentStatus, PlaybookExecution
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
    return approval, executions


def reject_containment(db: Session, approval_id: str, approver: str, note: str = "") -> ContainmentApproval:
    approval = _load_pending(db, approval_id)
    approval.status = ApprovalStatus.REJECTED
    approval.decided_at = datetime.now(timezone.utc)
    approval.decided_by = approver
    approval.decision_note = note
    db.commit()
    return approval
