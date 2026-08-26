"""Mock connectors backed by the synthetic scenario in app/seed/mock_scenario.py.

Each mock connector implements the same interface a real product connector
would (see base.py). Replace with e.g. app/connectors/splunk.py implementing
SIEMConnector, and swap the import in app/services/ingestion_service.py --
nothing else in the app needs to change.
"""
from typing import Any

from app.connectors.base import (
    AssetInventoryConnector,
    SIEMConnector,
    ThreatIntelConnector,
    VulnScannerConnector,
)
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
