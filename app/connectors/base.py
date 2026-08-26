"""Connector interfaces.

Every data source (SIEM, vulnerability scanner, EDR/asset inventory) implements
one of these abstract base classes. The rest of the app (ingestion, correlation,
prioritization, SOAR) talks only to these interfaces -- never to a concrete
product. Swapping `MockSIEMConnector` for `SplunkConnector` later means writing
one new file that implements `fetch_alerts()`, nothing else changes.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class SIEMConnector(ABC):
    """Source of security alerts (e.g. Splunk, Elastic, Sentinel, or a mock)."""

    @abstractmethod
    def fetch_alerts(self) -> list[dict[str, Any]]:
        """Return raw alert dicts. Fields: hostname, title, description,
        severity, attack_technique_id (optional), occurred_at."""
        raise NotImplementedError


class VulnScannerConnector(ABC):
    """Source of vulnerability findings (e.g. Nessus, Qualys, OpenVAS, or a mock)."""

    @abstractmethod
    def fetch_vulnerabilities(self) -> list[dict[str, Any]]:
        """Return raw vuln dicts. Fields: hostname, cve_id, title, cvss_score,
        epss_score, kev_listed."""
        raise NotImplementedError


class AssetInventoryConnector(ABC):
    """Source of asset/CMDB data (e.g. an EDR agent list, a CMDB export, or a mock)."""

    @abstractmethod
    def fetch_assets(self) -> list[dict[str, Any]]:
        """Return raw asset dicts. Fields: hostname, ip_address, criticality,
        exposure, data_sensitivity, business_unit, tags."""
        raise NotImplementedError


class ThreatIntelConnector(ABC):
    """Source of threat intelligence (e.g. a TIP like MISP/Recorded Future, or a mock)."""

    @abstractmethod
    def fetch_indicators(self) -> list[dict[str, Any]]:
        """Return raw IOC dicts. Fields: indicator_type, value, confidence,
        description, threat_actor (name, optional)."""
        raise NotImplementedError

    @abstractmethod
    def fetch_actor_profiles(self) -> list[dict[str, Any]]:
        """Return raw threat-actor/cluster dicts. Fields: name, description,
        attack_technique_ids (list of str)."""
        raise NotImplementedError
