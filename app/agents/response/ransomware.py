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

        # TODO(you): precursor heuristic -- should this runbook ALSO spin up
        # before encryption starts, based on a combination of earlier-stage
        # signals? This is a judgment call about false-positive tolerance:
        # firing early buys the response team the only window in which backups
        # can still be protected, but too loose a pattern spawns a ransomware
        # runbook on every noisy intrusion.
        #
        # Signals you have available here:
        #   observed_technique_ids            e.g. {"T1003", "T1021", "T1041"}
        #   incident.alerts[i].asset.tags     comma-separated, e.g. "backup,isolated"
        #   incident.alerts[i].asset.hostname
        #
        # Patterns real IRPs use (pick/combine, or design your own):
        #   - credential dumping (T1003) + lateral movement (T1021) + any alert
        #     touching an asset tagged "backup"
        #   - exfiltration (T1041) + lateral movement (double-extortion staging)
        #   - shadow-copy deletion (T1490) alone is already a direct trigger above
        #
        # Return True to spawn this runbook for the incident.
        return False


ransomware_response_agent = RansomwareResponseAgent()
