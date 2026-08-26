"""Synthetic dataset shared by all three mock connectors.

Designed as one coherent scenario rather than random noise: a public-facing
web server gets phished, an attacker escalates and dumps credentials, then
pivots to the domain controller and exfiltrates data. A few unrelated
low-severity alerts are mixed in as background noise. This gives the
correlation engine, ATT&CK coverage view, and SOAR playbooks something
realistic to operate on.
"""
from datetime import datetime, timedelta, timezone

_NOW = datetime.now(timezone.utc)


def _t(minutes_ago: int) -> str:
    return (_NOW - timedelta(minutes=minutes_ago)).isoformat()


MOCK_ASSETS = [
    {
        "hostname": "web-prod-01",
        "ip_address": "203.0.113.10",
        "criticality": 4,
        "exposure": "internet_facing",
        "data_sensitivity": 3,
        "business_unit": "ecommerce",
        "tags": "web,public,pci-adjacent",
    },
    {
        "hostname": "dc-01",
        "ip_address": "10.0.0.5",
        "criticality": 5,
        "exposure": "internal",
        "data_sensitivity": 5,
        "business_unit": "it-infra",
        "tags": "domain-controller,tier0",
    },
    {
        "hostname": "db-finance-01",
        "ip_address": "10.0.1.20",
        "criticality": 5,
        "exposure": "internal",
        "data_sensitivity": 5,
        "business_unit": "finance",
        "tags": "database,pii,financial",
    },
    {
        "hostname": "ws-jsmith",
        "ip_address": "10.0.5.44",
        "criticality": 2,
        "exposure": "internal",
        "data_sensitivity": 2,
        "business_unit": "sales",
        "tags": "workstation",
    },
    {
        "hostname": "backup-vault-01",
        "ip_address": "10.0.9.2",
        "criticality": 4,
        "exposure": "isolated",
        "data_sensitivity": 4,
        "business_unit": "it-infra",
        "tags": "backup,isolated",
    },
]

MOCK_VULNERABILITIES = [
    {
        "hostname": "web-prod-01",
        "cve_id": "CVE-2024-3400",
        "title": "Command injection in web application firewall bypass",
        "cvss_score": 9.8,
        "epss_score": 0.94,
        "kev_listed": True,
    },
    {
        "hostname": "web-prod-01",
        "cve_id": "CVE-2023-4966",
        "title": "Sensitive information disclosure via buffer overflow",
        "cvss_score": 7.5,
        "epss_score": 0.61,
        "kev_listed": True,
    },
    {
        "hostname": "dc-01",
        "cve_id": "CVE-2021-42287",
        "title": "Active Directory privilege escalation (sAMAccountName spoofing)",
        "cvss_score": 8.8,
        "epss_score": 0.55,
        "kev_listed": False,
    },
    {
        "hostname": "db-finance-01",
        "cve_id": "CVE-2022-21500",
        "title": "Oracle database unauthorized data access",
        "cvss_score": 6.5,
        "epss_score": 0.12,
        "kev_listed": False,
    },
    {
        "hostname": "ws-jsmith",
        "cve_id": "CVE-2023-21608",
        "title": "Adobe Acrobat Reader use-after-free",
        "cvss_score": 7.8,
        "epss_score": 0.08,
        "kev_listed": False,
    },
    {
        "hostname": "backup-vault-01",
        "cve_id": "CVE-2020-1938",
        "title": "Ghostcat file read/inclusion vulnerability",
        "cvss_score": 5.4,
        "epss_score": 0.03,
        "kev_listed": False,
    },
]

# The attack chain: phishing -> execution -> cred dumping -> lateral movement -> exfil,
# plus two unrelated noise alerts on other assets.
MOCK_ALERTS = [
    {
        "hostname": "web-prod-01",
        "title": "Suspicious inbound request matching CVE-2024-3400 exploit pattern",
        "description": "WAF logged a command-injection payload against the login endpoint.",
        "severity": "critical",
        "attack_technique_id": "T1190",
        "occurred_at": _t(120),
    },
    {
        "hostname": "web-prod-01",
        "title": "Unusual child process spawned by web server worker",
        "description": "www-data spawned /bin/bash -c with base64-encoded payload.",
        "severity": "high",
        "attack_technique_id": "T1059",
        "occurred_at": _t(115),
    },
    {
        "hostname": "web-prod-01",
        "title": "LSASS memory access detected",
        "description": "Non-standard process opened a handle to lsass.exe with PROCESS_VM_READ.",
        "severity": "critical",
        "attack_technique_id": "T1003",
        "occurred_at": _t(100),
    },
    {
        "hostname": "dc-01",
        "title": "Anomalous authentication from web-prod-01 service account",
        "description": "svc-web authenticated to dc-01 via SMB, no prior baseline for this pairing.",
        "severity": "high",
        "attack_technique_id": "T1021",
        "occurred_at": _t(80),
    },
    {
        "hostname": "dc-01",
        "title": "Large outbound data transfer to unfamiliar external IP",
        "description": "dc-01 sent 1.2GB to 198.51.100.77 over HTTPS outside business hours.",
        "severity": "critical",
        "attack_technique_id": "T1041",
        "occurred_at": _t(60),
    },
    # Noise
    {
        "hostname": "ws-jsmith",
        "title": "Multiple failed login attempts",
        "description": "5 failed RDP logins within 2 minutes, then a success.",
        "severity": "medium",
        "attack_technique_id": "T1110",
        "occurred_at": _t(400),
    },
    {
        "hostname": "backup-vault-01",
        "title": "Scheduled task created outside change window",
        "description": "New scheduled task registered by local admin account.",
        "severity": "low",
        "attack_technique_id": "T1053",
        "occurred_at": _t(600),
    },
]
