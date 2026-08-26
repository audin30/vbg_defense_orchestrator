"""Mock connectors backed by the synthetic scenario in app/seed/mock_scenario.py.

Each mock connector implements the same interface a real product connector
would (see base.py). Replace with e.g. app/connectors/splunk.py implementing
SIEMConnector, and swap the import in app/services/ingestion_service.py --
nothing else in the app needs to change.
"""
from typing import Any

from app.connectors.base import (
    AssetInventoryConnector,
    AttackCatalogConnector,
    KevCatalogConnector,
    SIEMConnector,
    ThreatIntelConnector,
    VulnScannerConnector,
)
from app.seed.attack_techniques import ATTACK_TECHNIQUES
from app.seed.mock_scenario import MOCK_ALERTS, MOCK_ASSETS, MOCK_VULNERABILITIES
from app.seed.mock_threat_intel import MOCK_THREAT_ACTOR_PROFILES, MOCK_THREAT_INDICATORS


class MockSIEMConnector(SIEMConnector):
    def fetch_alerts(self) -> list[dict[str, Any]]:
        return list(MOCK_ALERTS)


class MockVulnScannerConnector(VulnScannerConnector):
    def fetch_vulnerabilities(self) -> list[dict[str, Any]]:
        return list(MOCK_VULNERABILITIES)


class MockAssetInventoryConnector(AssetInventoryConnector):
    def fetch_assets(self) -> list[dict[str, Any]]:
        return list(MOCK_ASSETS)


class MockThreatIntelConnector(ThreatIntelConnector):
    def fetch_indicators(self) -> list[dict[str, Any]]:
        return list(MOCK_THREAT_INDICATORS)

    def fetch_actor_profiles(self) -> list[dict[str, Any]]:
        return list(MOCK_THREAT_ACTOR_PROFILES)


class MockKevCatalogConnector(KevCatalogConnector):
    """Mirrors the two KEV-listed CVEs in the mock vuln data, so the KEV
    enrichment path is exercised deterministically without network."""

    def fetch_kev_entries(self) -> list[dict[str, Any]]:
        return [
            {
                "cve_id": "CVE-2024-3400",
                "vendor_project": "Palo Alto Networks",
                "product": "PAN-OS",
                "vulnerability_name": "Command injection in web application firewall bypass",
                "date_added": "2024-04-12",
                "due_date": "2024-04-19",
                "known_ransomware_use": False,
                "short_description": "Command injection vulnerability exploited in the wild.",
            },
            {
                "cve_id": "CVE-2023-4966",
                "vendor_project": "Citrix",
                "product": "NetScaler ADC",
                "vulnerability_name": "Sensitive information disclosure via buffer overflow",
                "date_added": "2023-10-18",
                "due_date": "2023-11-08",
                "known_ransomware_use": True,
                "short_description": "Buffer overflow leaking session tokens; used in ransomware campaigns.",
            },
        ]


class MockAttackCatalogConnector(AttackCatalogConnector):
    """Backed by the curated seed -- keeps tests and offline bootstrap
    working with the same data the app shipped with."""

    def fetch_techniques(self) -> list[dict[str, Any]]:
        return [{"id": tid, "name": name, "tactic": tactic} for tid, name, tactic in ATTACK_TECHNIQUES]

    def fetch_actor_groups(self) -> list[dict[str, Any]]:
        return list(MOCK_THREAT_ACTOR_PROFILES)
