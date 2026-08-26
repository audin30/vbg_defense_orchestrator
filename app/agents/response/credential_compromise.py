"""Credential Compromise Response sub-agent (IRP annex: credential theft/abuse).

Covers credential dumping, brute force, password-store access, and abuse of
valid accounts.
"""
from app.agents.response.base import ResponseSubAgent


class CredentialCompromiseResponseAgent(ResponseSubAgent):
    category = "credential_compromise"
    runbook_name = "Credential Compromise Response Runbook"
    trigger_technique_ids = frozenset({"T1003", "T1110", "T1555", "T1078"})
    runbook = [
        ("analyze", "Enumerate accounts exposed on the host: active logon sessions, cached credentials, service accounts", True),
        ("analyze", "Review authentication logs for anomalous use of the exposed accounts since first alert", False),
        ("contain", "Force password reset and revoke sessions/tokens for all exposed accounts", False),
        ("contain", "If a domain controller or tier-0 asset is involved, rotate the KRBTGT account password twice", False),
        ("eradicate", "Audit for attacker-created accounts and unauthorized privilege or group-membership changes", False),
        ("recover", "Place affected accounts under enhanced authentication monitoring for 30 days", False),
    ]


credential_compromise_response_agent = CredentialCompromiseResponseAgent()
