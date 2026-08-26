"""AWS IRP playbook sub-agents — the Commander-stage dispatch.

Unlike the generic category sub-agents (spawned by the IR Agent at triage),
these activate only on the Incident Commander's call: an ESCALATE or
AUTO_CONTAIN decision routes the incident into every AWS playbook whose
finding-type triggers match. MONITOR never activates them — mirroring the
AWS triage guide, where P3/P4 events are handled internally without opening
a full playbook.
"""
from app.agents.response.aws.catalog import AWS_PLAYBOOK_SUBAGENTS
from app.models import Incident, ResponseDecision

# Which Commander decisions activate AWS playbooks. Tunable: an org with a
# lower risk appetite might restrict this to AUTO_CONTAIN only.
_ACTIVATING_DECISIONS = {ResponseDecision.AUTO_CONTAIN, ResponseDecision.ESCALATE}


def dispatch_aws_playbooks(incident: Incident, decision: ResponseDecision):
    """Spawn every AWS playbook sub-agent whose finding-type triggers match
    the incident's alerts, gated on the Commander's decision. Returns the
    list of ResponsePlan (empty when gated out or nothing matches)."""
    if decision not in _ACTIVATING_DECISIONS:
        return []
    observed = {a.attack_technique_id for a in incident.alerts if a.attack_technique_id}
    return [
        agent.respond(incident, observed)
        for agent in AWS_PLAYBOOK_SUBAGENTS
        if agent.matches(incident, observed)
    ]
