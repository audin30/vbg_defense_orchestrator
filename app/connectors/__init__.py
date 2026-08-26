"""Active connector wiring.

This is the single place that decides which concrete connector backs each
interface. Today everything points at the mock implementations. Moving to a
real product means: write app/connectors/<product>.py implementing the
matching base class, then change the import below -- ingestion_service and
everything upstream of it is unaffected.
"""
from app.connectors.mock import (
    MockAssetInventoryConnector,
    MockSIEMConnector,
    MockThreatIntelConnector,
    MockVulnScannerConnector,
)

siem_connector = MockSIEMConnector()
vuln_scanner_connector = MockVulnScannerConnector()
asset_inventory_connector = MockAssetInventoryConnector()
threat_intel_connector = MockThreatIntelConnector()
