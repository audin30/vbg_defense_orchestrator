"""Base class for IRP-category response sub-agents.

Each sub-agent is one annex of the Incident Response Playbook: it owns a
category (malware, ransomware, phishing, ...), a set of ATT&CK technique IDs
that trigger it, and a runbook -- an ordered list of actions across the
NIST 800-61 response phases. The Incident Response Agent spawns every
sub-agent whose trigger matches the incident's observed techniques; each
spawned sub-agent instantiates its runbook against the specific assets
where its trigger techniques were seen.

Sub-agents recommend, they don't execute: containment authority stays with
the Incident Commander Agent's SOAR gate, which is the only place automated
response actions get triggered.
"""
from app.agents.context import ResponsePlan, RunbookStep
from app.models import Incident

# NIST 800-61 lifecycle order (detection/analysis through post-incident is
# collapsed into the four phases the runbooks actually direct actions in).
PHASES = ("analyze", "contain", "eradicate", "recover")


class ResponseSubAgent:
    """Subclasses define the four class attributes; `respond()` is shared.

    `runbook` entries are (phase, action, per_affected_host) -- when
    per_affected_host is True the step is repeated once per asset on which a
    trigger technique was observed, otherwise it's a single incident-wide step.
    """

    category: str
    runbook_name: str
    trigger_technique_ids: frozenset[str]
    runbook: list[tuple[str, str, bool]]

    def matches(self, incident: Incident, observed_technique_ids: set[str]) -> bool:
        """Should this sub-agent be spawned for the incident? The default is
        a simple trigger-set intersection; subclasses may override for
        categories that are behavioral patterns rather than single techniques
        (see the Ransomware sub-agent)."""
        return bool(observed_technique_ids & self.trigger_technique_ids)

    def respond(self, incident: Incident, observed_technique_ids: set[str]) -> ResponsePlan:
        triggered = sorted(observed_technique_ids & self.trigger_technique_ids)
        affected_hostnames = sorted(
            {
                alert.asset.hostname
                for alert in incident.alerts
                if alert.attack_technique_id in self.trigger_technique_ids
            }
        )
        # A behavioral match (custom matches() override) can fire without any
        # single trigger technique present; fall back to all incident assets.
        if not affected_hostnames:
            affected_hostnames = sorted({alert.asset.hostname for alert in incident.alerts})

        steps: list[RunbookStep] = []
        order = 1
        for phase, action, per_host in self.runbook:
            if per_host:
                for hostname in affected_hostnames:
                    steps.append(RunbookStep(order=order, phase=phase, action=action, scope_hostname=hostname))
                    order += 1
            else:
                steps.append(RunbookStep(order=order, phase=phase, action=action, scope_hostname=None))
                order += 1

        return ResponsePlan(
            category=self.category,
            runbook_name=self.runbook_name,
            triggered_by_technique_ids=triggered,
            steps=steps,
        )
