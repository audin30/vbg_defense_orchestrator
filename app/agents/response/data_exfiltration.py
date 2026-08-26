"""Data Exfiltration Response sub-agent (IRP annex: data loss / breach).

Covers exfiltration over C2 channels, alternative protocols, and web services.
The recover phase deliberately includes the legal/notification assessment --
breach-notification clocks start at discovery, not at containment.
"""
from app.agents.response.base import ResponseSubAgent


class DataExfiltrationResponseAgent(ResponseSubAgent):
    category = "data_exfiltration"
    runbook_name = "Data Exfiltration Response Runbook"
    trigger_technique_ids = frozenset({"T1041", "T1048", "T1567"})
    runbook = [
        ("analyze", "Quantify transfer volume, destination, and time window from NetFlow/proxy logs", True),
        ("analyze", "Identify what data was staged or accessible to the exfiltrating process", True),
        ("contain", "Block the destination IPs/domains at the egress firewall and proxy", False),
        ("contain", "Suspend outbound transfers from the affected host pending review", True),
        ("eradicate", "Locate and remove staging artifacts (archives, compressed bundles, temp exports)", True),
        ("recover", "Assess data-breach notification obligations with legal/compliance based on the data classification involved", False),
    ]


data_exfiltration_response_agent = DataExfiltrationResponseAgent()
