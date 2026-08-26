"""ATT&CK technique -> forensic evidence catalog.

Maps each curated technique (see attack_techniques.py) to the artifact
types worth collecting and preserving if that technique is observed, and
where they'd typically be pulled from. Used by the Incident Response
Agent's evidence planner (app/agents/evidence_planner.py) -- not exhaustive
forensic doctrine, just enough to drive a defensible first-response
collection list per technique.

Each entry: technique_id -> list of (evidence_type, source_system) tuples.
"""

TECHNIQUE_EVIDENCE_MAP: dict[str, list[tuple[str, str]]] = {
    "T1566": [("Email headers and attachments", "Email gateway"), ("Endpoint process execution log", "EDR")],
    "T1190": [("Web/application server access logs", "Web server"), ("WAF request logs", "WAF"), ("Network packet capture", "NDR")],
    "T1078": [("Authentication logs", "IdP/Directory"), ("Sign-in risk/location history", "IdP")],
    "T1059": [("Process execution log / command-line history", "EDR"), ("Shell history file", "Endpoint")],
    "T1204": [("Endpoint process execution log", "EDR"), ("Browser download history", "Endpoint")],
    "T1053": [("Scheduled task/cron artifacts", "Endpoint"), ("Process execution log", "EDR")],
    "T1547": [("Registry autorun keys", "Endpoint"), ("Startup folder / launch agent artifacts", "Endpoint")],
    "T1548": [("Privilege/token change events", "System event log"), ("Process execution log", "EDR")],
    "T1055": [("Memory dump", "EDR"), ("Process injection telemetry", "EDR")],
    "T1562": [("Security tool configuration change log", "EDR/SIEM"), ("System event log", "Endpoint")],
    "T1070": [("Centralized log copy (pre-tamper)", "SIEM"), ("EDR telemetry (tamper-resistant)", "EDR")],
    "T1027": [("Suspicious file sample", "Endpoint"), ("Memory dump", "EDR")],
    "T1003": [("Full memory dump", "EDR"), ("LSASS process dump", "EDR"), ("Security event log (logon/credential events)", "Endpoint")],
    "T1110": [("Authentication logs", "IdP/Directory"), ("Account lockout events", "IdP")],
    "T1087": [("Directory service query logs", "Directory"), ("LDAP/AD audit log", "Directory")],
    "T1082": [("Process execution log", "EDR")],
    "T1021": [("Authentication logs (source+destination)", "IdP/Directory"), ("Network flow log", "NDR"), ("RDP/SMB session logs", "Endpoint")],
    "T1560": [("File system artifacts (archive location)", "Endpoint"), ("Disk image", "Endpoint")],
    "T1071": [("Network packet capture", "NDR"), ("Proxy logs", "Proxy")],
    "T1105": [("Network flow log", "NDR"), ("Transferred file sample", "EDR"), ("Proxy logs", "Proxy")],
    "T1041": [("Network flow log", "NDR"), ("Full packet capture (destination-scoped)", "NDR"), ("DNS query logs", "DNS")],
    "T1486": [("Disk image", "Endpoint"), ("Ransom note / encrypted file sample", "Endpoint"), ("File system change log", "EDR")],
    "T1489": [("System/service event log", "Endpoint"), ("Service configuration snapshot", "Endpoint")],
}

# Used when an alert has no mapped technique (or no technique at all).
DEFAULT_EVIDENCE: list[tuple[str, str]] = [("General system event log export", "SIEM")]

# Evidence to collect for a direct threat-intel IOC hit, keyed by indicator type.
IOC_EVIDENCE_BY_TYPE: dict[str, tuple[str, str]] = {
    "ip": ("Network flow / firewall connection logs (IOC-scoped)", "Firewall/NDR"),
    "domain": ("DNS resolution & proxy logs (IOC-scoped)", "DNS/Proxy"),
    "hash": ("File sample acquisition & hash verification", "EDR"),
}
DEFAULT_IOC_EVIDENCE = ("Indicator-related artifact export", "SIEM")
