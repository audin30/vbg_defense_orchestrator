"""Base class for AWS IRP playbook sub-agents.

These are distilled from the AWS incident response playbook checkout at
`playbooks/aws-incident-response-playbooks/` (each subclass cites its source
document). They differ from the generic IRP-category sub-agents in two ways:

1. **Trigger vocabulary** — AWS playbooks key on GuardDuty finding types and
   CloudTrail eventNames (`Alert.finding_type`), not ATT&CK technique IDs.
   Matching is by prefix so one trigger covers a finding family (e.g.
   "Impact:S3/" covers both .Delete and .Write variants).
2. **Dispatch stage** — they are activated by the Incident Commander's
   ESCALATE/AUTO_CONTAIN call after triage, not by the IR Agent during
   triage (see `dispatch_aws_playbooks` in `aws/__init__.py`). This mirrors
   the AWS triage guide, where P1/P2 severity is what routes a responder
   into a full playbook.

Phases map from the AWS playbook template: Part 2 (Detect & Analyze) ->
"analyze", Part 3 (Contain) -> "contain", Part 4 (Eradicate & Recover) ->
"eradicate"/"recover". Parts 1 and 5 are not incident-scoped and are not
modeled as tasks.
"""
from app.agents.response.base import ResponseSubAgent
from app.models import Incident


class AwsPlaybookSubAgent(ResponseSubAgent):
    """Subclasses set `trigger_finding_prefixes` and `source_playbook` in
    addition to the inherited category/runbook_name/runbook attributes.
    `trigger_technique_ids` stays empty -- technique-based dispatch at triage
    time never spawns these."""

    trigger_technique_ids: frozenset[str] = frozenset()
    trigger_finding_prefixes: frozenset[str]
    source_playbook: str  # filename within the playbooks/ checkout

    def _alert_matches(self, alert) -> bool:
        finding = alert.finding_type or ""
        return any(finding.startswith(prefix) for prefix in self.trigger_finding_prefixes)

    def _matched_signals(self, incident: Incident, observed_technique_ids: set[str]) -> list[str]:
        return sorted({a.finding_type for a in incident.alerts if self._alert_matches(a)})

    def matches(self, incident: Incident, observed_technique_ids: set[str]) -> bool:
        return any(self._alert_matches(a) for a in incident.alerts)
