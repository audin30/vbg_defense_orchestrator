"""Curated subset of MITRE ATT&CK (Enterprise) techniques.

This is not the full framework (600+ techniques) -- it's a representative
sample across tactics, enough to demonstrate detection coverage mapping and
alert-to-technique correlation. Extend as real detection rules are added.
"""

ATTACK_TECHNIQUES = [
    # (id, name, tactic)
    ("T1566", "Phishing", "Initial Access"),
    ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    ("T1078", "Valid Accounts", "Initial Access"),
    ("T1059", "Command and Scripting Interpreter", "Execution"),
    ("T1204", "User Execution", "Execution"),
    ("T1053", "Scheduled Task/Job", "Persistence"),
    ("T1547", "Boot or Logon Autostart Execution", "Persistence"),
    ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    ("T1055", "Process Injection", "Privilege Escalation"),
    ("T1562", "Impair Defenses", "Defense Evasion"),
    ("T1070", "Indicator Removal", "Defense Evasion"),
    ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
    ("T1003", "OS Credential Dumping", "Credential Access"),
    ("T1110", "Brute Force", "Credential Access"),
    ("T1087", "Account Discovery", "Discovery"),
    ("T1082", "System Information Discovery", "Discovery"),
    ("T1021", "Remote Services", "Lateral Movement"),
    ("T1560", "Archive Collected Data", "Collection"),
    ("T1071", "Application Layer Protocol", "Command and Control"),
    ("T1105", "Ingress Tool Transfer", "Command and Control"),
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    ("T1486", "Data Encrypted for Impact", "Impact"),
    ("T1489", "Service Stop", "Impact"),
]
