"""Active connector wiring.

This is the single place that decides which concrete connector backs each
interface. SIEM, vuln scanner, asset inventory, and IOC/TIP feeds still
point at the mocks; the KEV catalog and ATT&CK catalog are live (both
degrade gracefully offline -- stale local cache first, then the curated
seed/scanner flags). Moving another source to a real product means: write
app/connectors/<product>.py implementing the matching base class, then
change the import below -- ingestion_service and everything upstream of it
is unaffected.
"""
from app.connectors.base import NullIocEnrichmentConnector
from app.connectors.cisa_kev import CisaKevConnector
from app.connectors.mitre_attack import MitreAttackConnector
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
kev_connector = CisaKevConnector()
attack_catalog_connector = MitreAttackConnector()
# Swap for a VirusTotalConnector (reads VIRUSTOTAL_API_KEY) when implemented.
ioc_enrichment_connector = NullIocEnrichmentConnector()
