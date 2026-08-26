"""Playbook matching and (simulated) response execution.

Actions are logged, not actually performed -- there's no real EDR/firewall/IdP
wired up yet. When real connectors land, each action name below maps to one
real API call (e.g. "isolate_host" -> EDR isolate-endpoint call). Keeping the
action set as plain strings now means playbooks defined today keep working
unchanged once real integrations replace the simulated ones.
"""
from sqlalchemy.orm import Session

from app.models import AlertSeverity, Incident, Playbook, PlaybookExecution

_SEVERITY_ORDER = [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]

# Simulated action handlers. A real deployment replaces these with calls into
# EDR/firewall/IdP/ticketing connectors.
_ACTION_HANDLERS = {
    "isolate_host": lambda incident: f"[SIMULATED] Isolated host for asset {incident.asset_id} via EDR",
    "disable_account": lambda incident: "[SIMULATED] Disabled associated service/user accounts via IdP",
    "block_ip": lambda incident: "[SIMULATED] Pushed C2/exfil destination IP to firewall block list",
    "snapshot_forensics": lambda incident: "[SIMULATED] Captured memory + disk snapshot for forensics",
    "create_ticket": lambda incident: f"[SIMULATED] Filed incident ticket for '{incident.title}'",
    "notify_oncall": lambda incident: "[SIMULATED] Paged security on-call via notification system",
}


def _meets_trigger(playbook: Playbook, incident: Incident) -> bool:
    severity_ok = _SEVERITY_ORDER.index(incident.severity) >= _SEVERITY_ORDER.index(
        playbook.trigger_min_severity
    )
    if not severity_ok:
        return False
    if playbook.trigger_attack_technique_id is None:
        return True
    incident_technique_ids = {a.attack_technique_id for a in incident.alerts if a.attack_technique_id}
    return playbook.trigger_attack_technique_id in incident_technique_ids


def evaluate_and_execute(db: Session, incident: Incident) -> list[PlaybookExecution]:
    """Find every playbook whose trigger matches this incident and run it."""
    executions = []
    for playbook in db.query(Playbook).all():
        if not _meets_trigger(playbook, incident):
            continue

        results = []
        for action_name in playbook.actions.split(","):
            action_name = action_name.strip()
            handler = _ACTION_HANDLERS.get(action_name)
            result = handler(incident) if handler else f"[SKIPPED] Unknown action '{action_name}'"
            results.append(result)

        execution = PlaybookExecution(
            playbook_id=playbook.id,
            incident_id=incident.id,
            actions_taken="\n".join(results),
        )
        db.add(execution)
        executions.append(execution)

    db.commit()
    return executions
