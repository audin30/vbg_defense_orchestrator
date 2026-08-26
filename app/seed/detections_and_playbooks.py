"""Seed detection rules and SOAR playbooks tied to the curated ATT&CK subset.

Coverage is intentionally incomplete -- a handful of techniques in
ATTACK_TECHNIQUES have no rule below, so the coverage report has real gaps to
show rather than 100% coverage on day one.
"""

DETECTION_RULES = [
    # (name, attack_technique_id, description)
    ("WAF: known exploit signature match", "T1190", "Matches CVE-tagged payload patterns at the WAF."),
    ("EDR: suspicious child process from web worker", "T1059", "www-data/nginx spawning a shell."),
    ("EDR: LSASS memory access", "T1003", "Non-whitelisted process opening a handle to lsass.exe."),
    ("NDR: anomalous internal auth pairing", "T1021", "Auth between hosts with no prior baseline."),
    ("NDR: large outbound transfer to unknown IP", "T1041", "Outbound volume anomaly to a non-allowlisted destination."),
    ("IdP: brute-force lockout threshold", "T1110", "N failed logins within a short window."),
    ("EDR: scheduled task created by non-admin change process", "T1053", "Scheduled task outside change window."),
    ("Email gateway: phishing indicators", "T1566", "Known phishing kit / sender reputation match."),
]

PLAYBOOKS = [
    # (name, trigger_attack_technique_id, trigger_min_severity, actions)
    (
        "Credential dumping response",
        "T1003",
        "high",
        "isolate_host,snapshot_forensics,disable_account,notify_oncall,create_ticket",
    ),
    (
        "Exfiltration response",
        "T1041",
        "high",
        "isolate_host,block_ip,notify_oncall,create_ticket",
    ),
    (
        "Public-facing exploit attempt",
        "T1190",
        "high",
        "block_ip,create_ticket",
    ),
    (
        "Generic critical incident escalation",
        None,
        "critical",
        "notify_oncall,create_ticket",
    ),
]
