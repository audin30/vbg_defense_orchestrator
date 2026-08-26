"""Phishing Response sub-agent (IRP annex: email-borne social engineering).

Not triggered by the current mock scenario (no T1566/T1204 alerts seeded),
but wired in so a real SIEM connector's phishing detections route here with
no further changes.
"""
from app.agents.response.base import ResponseSubAgent


class PhishingResponseAgent(ResponseSubAgent):
    category = "phishing"
    runbook_name = "Phishing Response Runbook"
    trigger_technique_ids = frozenset({"T1566", "T1204"})
    runbook = [
        ("analyze", "Extract sender, URLs, and attachments from the reported message; detonate in sandbox", False),
        ("analyze", "Search the mail store for all recipients of the same or similar messages", False),
        ("contain", "Purge the message from all mailboxes; block sender domain and embedded URLs", False),
        ("contain", "Reset credentials and revoke sessions for any user who interacted with the message", True),
        ("eradicate", "Check interacted users' hosts for dropped payloads or persistence", True),
        ("recover", "Notify affected users and circulate an awareness note describing the lure", False),
    ]


phishing_response_agent = PhishingResponseAgent()
