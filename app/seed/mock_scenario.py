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
    # Cloud estate modeled as an asset: the production AWS account. Alerts on
    # it carry GuardDuty/CloudTrail finding_type values, which is what routes
    # them to the AWS IRP playbook sub-agents at the Commander stage.
    {
        "hostname": "aws-prod-account",
        "ip_address": "0.0.0.0",
        "criticality": 5,
        "exposure": "internet_facing",
        "data_sensitivity": 5,
        "business_unit": "platform",
        "tags": "aws,cloud-account,production",
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
    # Second chain: cloud-native ransomware in the AWS account, modeled on the
    # game-day scenario in the AWS IRP-Ransomware playbook (stolen instance
    # credentials -> S3 versioning suspended + bulk deletion -> attacker KMS
    # key re-encryption + ransom notes). Three alerts on one asset within the
    # cluster window -> one incident, confidence 0.9. With the live MITRE
    # catalog ingested, real ransomware groups (BlackByte, Scattered Spider)
    # fully cover the T1078/T1490/T1486 set -> criticality CRITICAL ->
    # CONTAIN_PENDING_APPROVAL (queued for human sign-off, HITL); offline
    # with only mock actor profiles it lands HIGH -> ESCALATE. Either
    # decision activates the matching AWS IRP playbooks.
    {
        "hostname": "aws-prod-account",
        "title": "GuardDuty: EC2 instance credentials used from external IP",
        "description": "Credentials for role prod-app-role exfiltrated via IMDS and used from an IP outside AWS.",
        "severity": "high",
        "attack_technique_id": "T1078",
        "finding_type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "occurred_at": _t(90),
    },
    {
        "hostname": "aws-prod-account",
        "title": "S3 versioning suspended and bulk object deletion in progress",
        "description": "PutBucketVersioning (Suspended) on 3 production buckets followed by mass DeleteObjects calls.",
        "severity": "critical",
        "attack_technique_id": "T1490",
        "finding_type": "Impact:S3/AnomalousBehavior.Delete",
        "occurred_at": _t(45),
    },
    {
        "hostname": "aws-prod-account",
        "title": "Unrecognized KMS key created; EBS volumes re-encrypted and RANSOM_NOTE.txt uploaded",
        "description": "CreateKey from unfamiliar principal, bulk ReEncrypt on production volumes, ransom notes written to affected buckets.",
        "severity": "critical",
        "attack_technique_id": "T1486",
        "finding_type": "eventName:CreateKey",
        "occurred_at": _t(40),
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
