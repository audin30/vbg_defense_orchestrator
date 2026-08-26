"""CISA Known Exploited Vulnerabilities catalog connector.

Live feed: a single JSON document (~1300 entries, no auth) republished by
CISA as vulnerabilities are confirmed exploited in the wild. Cached locally
for 24h; on network failure the stale cache is served, and with no cache at
all the connector returns [] so bootstrap continues with scanner-provided
kev_listed flags.
"""
from typing import Any

from app.connectors._http_cache import fetch_json_cached
from app.connectors.base import KevCatalogConnector

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE_FILENAME = "kev_catalog.json"
_MAX_AGE_SECONDS = 24 * 3600


class CisaKevConnector(KevCatalogConnector):
    def fetch_kev_entries(self) -> list[dict[str, Any]]:
        data = fetch_json_cached(KEV_FEED_URL, _CACHE_FILENAME, _MAX_AGE_SECONDS)
        if not data:
            return []
        return [
            {
                "cve_id": v.get("cveID", ""),
                "vendor_project": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "vulnerability_name": v.get("vulnerabilityName", ""),
                "date_added": v.get("dateAdded", ""),
                "due_date": v.get("dueDate", ""),
                "known_ransomware_use": v.get("knownRansomwareCampaignUse", "") == "Known",
                "short_description": v.get("shortDescription", ""),
            }
            for v in data.get("vulnerabilities", [])
            if v.get("cveID")
        ]
