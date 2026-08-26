"""Synthetic threat intel data for the mock connector.

Cluster names are fictional (mock) -- not real attributed threat actors.
One indicator and one actor profile are designed to deliberately match the
attack chain in mock_scenario.py (the 198.51.100.77 exfil destination, and
the T1190->T1059->T1003->T1021->T1041 technique sequence), so the Threat
Intel Agent has something real to correlate against in the demo.
"""

MOCK_THREAT_ACTOR_PROFILES = [
    {
        "name": "Tracked Cluster: SILENT-ORCHID (mock)",
        "description": (
            "Opportunistic intrusion set observed exploiting public-facing web "
            "apps for initial access, followed by credential dumping and rapid "
            "lateral movement to domain controllers for bulk data theft."
        ),
        "attack_technique_ids": ["T1190", "T1059", "T1003", "T1021", "T1041"],
    },
    {
        "name": "Tracked Cluster: RUSTY-FALCON (mock)",
        "description": (
            "Phishing-driven access broker; sells validated credentials and "
            "initial footholds to follow-on ransomware affiliates."
        ),
        "attack_technique_ids": ["T1566", "T1204", "T1110", "T1078"],
    },
]

MOCK_THREAT_INDICATORS = [
    {
        "indicator_type": "ip",
        "value": "198.51.100.77",
        "confidence": 0.9,
        "description": "C2/exfil egress IP observed in prior SILENT-ORCHID intrusions (mock)",
        "threat_actor": "Tracked Cluster: SILENT-ORCHID (mock)",
    },
    {
        "indicator_type": "domain",
        "value": "update-delivery-cdn.net",
        "confidence": 0.7,
        "description": "Fake CDN domain used for second-stage payload delivery (mock)",
        "threat_actor": "Tracked Cluster: SILENT-ORCHID (mock)",
    },
    {
        "indicator_type": "hash",
        "value": "9f4d6e2c1a7b3e8f0c5d2a1b6e9f3c7d",
        "confidence": 0.6,
        "description": "Credential-harvesting phishing attachment (mock)",
        "threat_actor": "Tracked Cluster: RUSTY-FALCON (mock)",
    },
]
