"""IRP-category response sub-agents, spawned by the Incident Response Agent.

The registry order is the order plans appear in triage output; keep the more
time-critical categories (ransomware, exfiltration) early.
"""
from app.agents.response.base import ResponseSubAgent
from app.agents.response.credential_compromise import credential_compromise_response_agent
from app.agents.response.data_exfiltration import data_exfiltration_response_agent
from app.agents.response.lateral_movement import lateral_movement_response_agent
from app.agents.response.malware import malware_response_agent
from app.agents.response.phishing import phishing_response_agent
from app.agents.response.ransomware import ransomware_response_agent
from app.models import Incident

RESPONSE_SUBAGENTS: list[ResponseSubAgent] = [
    ransomware_response_agent,
    data_exfiltration_response_agent,
    credential_compromise_response_agent,
    lateral_movement_response_agent,
    malware_response_agent,
    phishing_response_agent,
]


def dispatch_response_subagents(incident: Incident):
    """Classify the incident by its observed ATT&CK techniques and spawn
    every matching sub-agent. Returns the list of ResponsePlan they produce
    (empty if nothing matches -- e.g. an unmapped or benign technique)."""
    observed = {a.attack_technique_id for a in incident.alerts if a.attack_technique_id}
    return [
        agent.respond(incident, observed)
        for agent in RESPONSE_SUBAGENTS
        if agent.matches(incident, observed)
    ]
