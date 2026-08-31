"""Ransomware Response sub-agent (IRP annex: ransomware / destructive attack).

Unlike the other categories, ransomware is a *behavioral pattern*, not a
single technique: by the time T1486 (Data Encrypted for Impact) fires, the
response window is mostly gone. Mature IRPs therefore also treat precursor
combinations -- backup tampering plus exfiltration, credential dumping plus
lateral movement toward backup infrastructure -- as ransomware-likely and
spin up this runbook early.
"""
from app.agents.response.base import ResponseSubAgent
from app.models import Incident
from app.services.correlation_service import LATERAL_MOVEMENT_TECHNIQUES

# Precursor signals, evaluated together rather than as single triggers -- any
# one of these alone is too noisy (lateral movement and credential dumping
# both show up in plenty of non-ransomware intrusions), but each combination
# below is specific enough to real ransomware playbooks (double-extortion
# staging, backup-tampering-before-encryption) to justify spinning up the
# runbook before T1486/T1490 ever fires.
_CREDENTIAL_DUMPING = frozenset({"T1003"})
_EXFILTRATION = frozenset({"T1041"})


class RansomwareResponseAgent(ResponseSubAgent):
    category = "ransomware"
    runbook_name = "Ransomware Response Runbook"
    # Direct indicators: encryption for impact, inhibit system recovery.
    trigger_technique_ids = frozenset({"T1486", "T1490"})
    runbook = [
        ("analyze", "Identify the ransomware family from the ransom note / file extension; check for a known decryptor", False),
        ("analyze", "Determine encryption scope: hosts, shares, and whether backups were reached", False),
        ("contain", "Isolate affected hosts and disable write access to reachable file shares", True),
        ("contain", "Verify backup integrity and disconnect the backup vault from the network until the intrusion path is closed", False),
        ("eradicate", "Remove the encryption payload, its persistence, and the initial-access foothold", True),
        ("recover", "Restore from last known-good backup; any ransom-payment discussion goes through executive and legal leadership only", False),
    ]

    def matches(self, incident: Incident, observed_technique_ids: set[str]) -> bool:
        # Direct indicators always trigger.
        if super().matches(incident, observed_technique_ids):
            return True

        has_lateral_movement = bool(observed_technique_ids & LATERAL_MOVEMENT_TECHNIQUES)
        if not has_lateral_movement:
            return False  # neither precursor pattern below fires without it

        # Credential dumping + lateral movement toward backup infrastructure:
        # the classic pre-encryption staging move, since backups are the
        # thing that makes ransom leverage go away.
        if observed_technique_ids & _CREDENTIAL_DUMPING:
            touches_backup_asset = any(
                "backup" in {t.strip() for t in (alert.asset.tags or "").split(",")}
                for alert in incident.alerts
            )
            if touches_backup_asset:
                return True

        # Exfiltration + lateral movement: double-extortion staging (steal
        # first, encrypt second) even before any backup-tagged asset is hit.
        if observed_technique_ids & _EXFILTRATION:
            return True

        return False


ransomware_response_agent = RansomwareResponseAgent()
