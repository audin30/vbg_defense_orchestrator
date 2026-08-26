"""Lateral Movement Response sub-agent (IRP annex: internal propagation).

Trigger set intentionally mirrors the correlation service's cross-asset
chaining techniques -- if correlation chained two assets on one of these,
this runbook is what handles the bridge.
"""
from app.agents.response.base import ResponseSubAgent


class LateralMovementResponseAgent(ResponseSubAgent):
    category = "lateral_movement"
    runbook_name = "Lateral Movement Response Runbook"
    trigger_technique_ids = frozenset({"T1021", "T1570", "T1091", "T1210"})
    runbook = [
        ("analyze", "Map the authentication graph: source host, target host, account used, and protocol", False),
        ("analyze", "Baseline-compare remote-service logons on the target host for the last 30 days", True),
        ("contain", "Restrict the lateral protocol (SMB/RDP/WinRM) between the affected network segments", False),
        ("contain", "Isolate pivot-destination hosts pending compromise assessment", True),
        ("eradicate", "Hunt for the same movement technique from the affected hosts to any peer asset", False),
        ("recover", "Re-enable inter-segment connectivity only after both endpoints are verified clean", False),
    ]


lateral_movement_response_agent = LateralMovementResponseAgent()
