"""AWS IRP playbook sub-agents, one per playbook present in the
`playbooks/aws-incident-response-playbooks/` checkout.

Runbooks are distilled from each document's Part 2 (Detect & Analyze),
Part 3 (Contain), and Part 4 (Eradicate & Recover). They are condensed --
the source playbook remains the authoritative full procedure; each class
cites its source file. Trigger prefixes come from each playbook's
"Applicable Finding Types" table. Overlapping triggers across playbooks are
intentional and mirror the source documents' cross-referencing (e.g. an
InstanceCredentialExfiltration finding routes to STS Token Abuse, while
ransomware-adjacent IAM anomalies also appear in IRP-Ransomware).
"""
from app.agents.response.aws.base import AwsPlaybookSubAgent


class AwsCredCompromiseAgent(AwsPlaybookSubAgent):
    category = "aws_credential_compromise"
    runbook_name = "AWS IRP: Credential Compromise"
    source_playbook = "IRP-CredCompromise.md"
    trigger_finding_prefixes = frozenset({
        "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess",
        "CredentialAccess:IAMUser/",
        "InitialAccess:IAMUser/",
        "Discovery:IAMUser/",
        "Persistence:IAMUser/",
        "eventName:CreateAccessKey",
        "eventName:ConsoleLogin",
    })
    runbook = [
        ("analyze", "Identify the compromised principal and enumerate all API activity via CloudTrail/Athena since first anomalous call", False),
        ("analyze", "Generate IAM credential report; list access keys, MFA devices, and login profiles changed in the window", False),
        ("contain", "Long-term access key: deactivate (do not delete) and monitor CloudTrail 30 min for continued use", False),
        ("contain", "Console password: attach explicit deny-all inline policy; delete login profile and attacker-registered MFA devices", False),
        ("contain", "STS sessions: revoke via inline deny policy with aws:TokenIssueTime DateLessThan condition", False),
        ("eradicate", "Remove attacker-created IAM users, keys, roles, and policy attachments; verify no residual persistence", False),
        ("recover", "Issue new credentials to the legitimate owner; confirm application recovery; keep enhanced monitoring on the principal", False),
    ]


class AwsStsTokenAbuseAgent(AwsPlaybookSubAgent):
    category = "aws_sts_token_abuse"
    runbook_name = "AWS IRP: STS Token Abuse"
    source_playbook = "IRP-STSTokenAbuse.md"
    trigger_finding_prefixes = frozenset({
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        "eventName:AssumeRole",
        "eventName:GetSessionToken",
    })
    runbook = [
        ("analyze", "Map the AssumeRole chain: originating principal, roles assumed, cross-account hops, session names", False),
        ("analyze", "If IMDS theft suspected, identify the source instance and check for SSRF or instance compromise", True),
        ("contain", "Revoke all active role sessions via inline deny policy keyed on aws:TokenIssueTime", False),
        ("contain", "Modify role trust policies to remove unauthorized principals; apply SCP to block cross-account AssumeRole if lateral movement is active", False),
        ("contain", "Enforce IMDSv2 with hop limit 1 on affected instances", True),
        ("eradicate", "Reduce role session duration limits; remove attacker modifications to trust policies", False),
        ("recover", "Restore legitimate trust relationships with least-privilege hardening; validate workload role assumption", False),
    ]


class AwsRansomwareAgent(AwsPlaybookSubAgent):
    category = "aws_ransomware"
    runbook_name = "AWS IRP: Ransomware"
    source_playbook = "IRP-Ransomware.md"
    trigger_finding_prefixes = frozenset({
        "Impact:S3/AnomalousBehavior",
        "Execution:EC2/MaliciousFile",
        "Execution:ECS/MaliciousFile",
        "Impact:EC2/BitcoinDomainRequest",
        "eventName:CreateKey",
        "eventName:ScheduleKeyDeletion",
        "eventName:DeleteSnapshot",
        "eventName:PutBucketVersioning",
        "eventName:DeleteBackupVault",
    })
    runbook = [
        ("analyze", "Determine destructive activity type (EBS re-encryption, S3 deletion, snapshot/backup destruction) and whether the threat actor is still active", False),
        ("analyze", "Verify backup integrity: AWS Backup recovery points, S3 versioned objects, Vault Lock status; check for lifecycle/retention tampering", False),
        ("contain", "Revoke threat actor access (route credential containment to AWS IRP: Credential Compromise) — containment runs in parallel with evidence collection for active destruction", False),
        ("contain", "Deploy emergency SCP blocking kms:ScheduleKeyDeletion, s3:PutBucketVersioning, snapshot and backup-vault deletion org-wide", False),
        ("contain", "Copy surviving snapshots to the forensic account; lock remaining EBS snapshots; deny delete operations on critical S3 buckets", False),
        ("eradicate", "Remove threat-actor KMS keys/grants, restore bucket versioning, and close the initial-access path", False),
        ("recover", "Restore from known-good recovery points by business priority; ransom decisions go through Executive Sponsor and Legal only", False),
    ]


class AwsDataAccessAgent(AwsPlaybookSubAgent):
    category = "aws_data_access"
    runbook_name = "AWS IRP: Unauthorized Data Access"
    source_playbook = "IRP-DataAccess.md"
    trigger_finding_prefixes = frozenset({
        "Exfiltration:S3/",
        "Discovery:S3/",
        "UnauthorizedAccess:S3/",
        "Policy:S3/",
        "eventName:GetSecretValue",
    })
    runbook = [
        ("analyze", "Identify the access path: principal, buckets/tables/secrets touched, object counts and bytes via CloudTrail data events", False),
        ("analyze", "Determine data classification of accessed objects (route to AWS IRP: Personal Data Breach if personal data confirmed)", False),
        ("contain", "Block unauthorized S3 access: bucket policy deny, Block Public Access, revoke S3 Access Grants and Lake Formation permissions", False),
        ("contain", "Rotate any secrets or parameters read by the unauthorized principal", False),
        ("eradicate", "Remove attacker-granted resource policies, ACLs, and access points; correct the misconfiguration that exposed the data", False),
        ("recover", "Re-enable legitimate access with least privilege; add data-event monitoring on the affected stores", False),
    ]


class AwsPersonalDataBreachAgent(AwsPlaybookSubAgent):
    category = "aws_personal_data_breach"
    runbook_name = "AWS IRP: Personal Data Breach"
    source_playbook = "IRP-PersonalDataBreach.md"
    trigger_finding_prefixes = frozenset({
        "SensitiveData:S3Object/",
        "Policy:IAMUser/S3BucketPublic",
        "UnauthorizedAccess:S3/TorIPCaller",
    })
    runbook = [
        ("analyze", "Confirm personal data involvement via Macie findings and object inventory; identify data subjects and jurisdictions", False),
        ("analyze", "Document the notification clock start (time of breach confirmation) — regulatory windows (e.g. GDPR 72h) run from discovery", False),
        ("contain", "Stop further access in coordination with the technical playbook handling the access vector", False),
        ("contain", "Preserve evidence under legal hold: CloudTrail logs, affected objects, access records to the forensic bucket", False),
        ("eradicate", "Close the exposure path and verify no residual public/unauthorized access to personal data stores", False),
        ("recover", "Execute regulatory and data-subject notifications with Legal/Compliance; document scope, impact, and remediation for regulators", False),
    ]


class AwsDosAgent(AwsPlaybookSubAgent):
    category = "aws_dos"
    runbook_name = "AWS IRP: Denial of Service"
    source_playbook = "IRP-DoS.md"
    trigger_finding_prefixes = frozenset({
        "Backdoor:EC2/DenialOfService",
        "Impact:EC2/PortSweep",
        "AWS/DDoSProtection",
    })
    runbook = [
        ("analyze", "Classify the attack: L3/4 volumetric vs application-layer; identify targeted resources and traffic signature", False),
        ("analyze", "Check Shield/WAF metrics and 5xx rates; engage Shield Response Team if Shield Advanced is enrolled", False),
        ("contain", "Volumetric: move origin behind CloudFront, restrict security groups to edge ranges, engage Shield mitigations", False),
        ("contain", "Application-layer: deploy WAF rate-based rules, geographic and bot controls on targeted endpoints", False),
        ("eradicate", "Fix the exposure that made the attack effective: public origin, missing rate limits, expensive endpoints", False),
        ("recover", "Restore normal traffic policies gradually; validate autoscaling limits against both availability and cost", False),
    ]


class AwsInsiderThreatAgent(AwsPlaybookSubAgent):
    category = "aws_insider_threat"
    runbook_name = "AWS IRP: Insider Threat"
    source_playbook = "IRP-InsiderThreat.md"
    trigger_finding_prefixes = frozenset({
        "PrivilegeEscalation:IAMUser/",
    })
    runbook = [
        ("analyze", "Enable enhanced CloudTrail logging and CloudWatch metric filters scoped to the subject's activity — observe before alerting the subject", False),
        ("analyze", "Monitor data exfiltration paths: S3 access patterns, snapshot sharing, cross-account transfers", False),
        ("contain", "Quietly reduce IAM permissions to the minimum for current duties; restrict VPC endpoint policies against cross-account transfer", False),
        ("contain", "On HR/Legal authorization: attach deny-all policy and deactivate all access keys simultaneously", False),
        ("eradicate", "Audit and revert unauthorized changes made by the subject; review resources they shared externally", False),
        ("recover", "Coordinate evidence package with HR/Legal; review privilege-granting process gaps that enabled the escalation", False),
    ]


class AwsIdentityCenterCompromiseAgent(AwsPlaybookSubAgent):
    category = "aws_identity_center_compromise"
    runbook_name = "AWS IRP: Identity Center Compromise"
    source_playbook = "IRP-IdentityCenterCompromise.md"
    trigger_finding_prefixes = frozenset({
        "eventName:CreatePermissionSet",
        "eventName:CreateAccountAssignment",
        "eventName:AttachManagedPolicyToPermissionSet",
        "eventName:PutInlinePolicyToPermissionSet",
    })
    runbook = [
        ("analyze", "Enumerate sso.amazonaws.com and identitystore.amazonaws.com CloudTrail events: permission sets, assignments, and identities created or modified", False),
        ("contain", "Disable the compromised user in the identity store and revoke active SSO sessions", False),
        ("contain", "Remove unauthorized permission set assignments and permission sets; disable delegated administrator if compromised", False),
        ("contain", "P1 option: restrict Identity Center administration via SCP for the duration of the incident", False),
        ("eradicate", "Remove all threat-actor-created identity store entities; sweep member accounts for persistence (local IAM users, roles)", False),
        ("recover", "Verify Identity Center configuration integrity against baseline; restore legitimate assignments with review", False),
    ]


class AwsFederatedAccessAbuseAgent(AwsPlaybookSubAgent):
    category = "aws_federated_access_abuse"
    runbook_name = "AWS IRP: Federated Access Abuse"
    source_playbook = "IRP-FederatedAccessAbuse.md"
    trigger_finding_prefixes = frozenset({
        "eventName:AssumeRoleWithSAML",
        "eventName:AssumeRoleWithWebIdentity",
        "eventName:CreateSAMLProvider",
        "eventName:UpdateSAMLProvider",
        "eventName:CreateOpenIDConnectProvider",
    })
    runbook = [
        ("analyze", "Correlate federated sessions with IdP logs (Okta/Entra): SAML assertions, principals, source IPs — determine if the IdP itself is compromised", False),
        ("contain", "Revoke all active federated sessions on affected roles; modify trust policies to temporarily block federation", False),
        ("contain", "Apply SCP blocking SAML/OIDC provider modifications during the incident; coordinate IdP-side containment with the identity team", False),
        ("eradicate", "Remove or re-verify tampered identity providers; validate provider thumbprints and metadata against known-good", False),
        ("recover", "Re-establish federation with the verified IdP; restore hardened trust policies and remove containment controls", False),
    ]


class AwsSatelliteOperationsAgent(AwsPlaybookSubAgent):
    category = "aws_satellite_operations"
    runbook_name = "AWS IRP: Satellite Operations"
    source_playbook = "IRP-SatelliteOperations.md"
    trigger_finding_prefixes = frozenset({
        "eventName:ReserveContact",
        "eventName:DeleteDataflowEndpointGroup",
    })
    runbook = [
        ("analyze", "Distinguish cyber activity from environmental anomaly (SEU); review Ground Station contact reservations and dataflow endpoint changes", False),
        ("analyze", "Audit command uplink integrity for the affected mission profiles within recent contact windows", False),
        ("contain", "Suspend unauthorized contact reservations; isolate the compromised ground segment components (mission control, processing pipeline)", False),
        ("contain", "Protect the command path: restrict Ground Station API access to break-glass principals only", False),
        ("eradicate", "Rebuild affected ground segment infrastructure from trusted baselines; rotate all mission credentials", False),
        ("recover", "Validate space segment state on next contact window before resuming normal operations", False),
    ]


AWS_PLAYBOOK_SUBAGENTS: list[AwsPlaybookSubAgent] = [
    AwsRansomwareAgent(),
    AwsPersonalDataBreachAgent(),
    AwsDataAccessAgent(),
    AwsCredCompromiseAgent(),
    AwsStsTokenAbuseAgent(),
    AwsIdentityCenterCompromiseAgent(),
    AwsFederatedAccessAbuseAgent(),
    AwsInsiderThreatAgent(),
    AwsDosAgent(),
    AwsSatelliteOperationsAgent(),
]
