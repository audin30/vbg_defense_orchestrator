"""Evidence collection & preservation planning.

Called by the Incident Response Agent as part of triage. Produces a list of
EvidenceFinding directing what to pull from which impacted asset, and why --
every item is traceable back to either the ATT&CK technique that justified
it (via TECHNIQUE_EVIDENCE_MAP) or a direct threat-intel IOC hit. That
traceability is the point: an evidence request with no cited technique or
indicator isn't defensible in an incident report.
"""
from app.agents.context import EvidenceFinding, ThreatIntelReport
from app.models import Alert
from app.seed.evidence_catalog import (
    DEFAULT_EVIDENCE,
    DEFAULT_IOC_EVIDENCE,
    IOC_EVIDENCE_BY_TYPE,
    TECHNIQUE_EVIDENCE_MAP,
)


def build_evidence_plan(alerts: list[Alert], threat_intel: ThreatIntelReport) -> list[EvidenceFinding]:
    items: list[EvidenceFinding] = []
    seen_technique_items: set[tuple[str, str]] = set()

    for alert in alerts:
        hostname = alert.asset.hostname
        technique_id = alert.attack_technique_id
        mapped = TECHNIQUE_EVIDENCE_MAP.get(technique_id, DEFAULT_EVIDENCE)
        for evidence_type, source in mapped:
            key = (hostname, evidence_type)
            if key in seen_technique_items:
                continue
            seen_technique_items.add(key)
            justification = (
                f"Technique {technique_id} observed on {hostname} ('{alert.title}')."
                if technique_id
                else f"Alert '{alert.title}' observed on {hostname} (no mapped technique)."
            )
            items.append(
                EvidenceFinding(
                    asset_hostname=hostname,
                    evidence_type=evidence_type,
                    source=source,
                    justification=justification,
                    related_technique_id=technique_id,
                    related_ioc_value=None,
                )
            )

    # IOC-driven evidence is always included, even if it duplicates an
    # evidence type already queued by technique -- the justification (a
    # confirmed indicator match) is independently strong enough to preserve
    # on its own, and matters for chain-of-custody documentation.
    for ioc in threat_intel.ioc_matches:
        evidence_type, source = IOC_EVIDENCE_BY_TYPE.get(ioc.indicator_type, DEFAULT_IOC_EVIDENCE)
        actor = ioc.threat_actor_name or "an unattributed source"
        items.append(
            EvidenceFinding(
                asset_hostname=ioc.matched_hostname,
                evidence_type=evidence_type,
                source=source,
                justification=(
                    f"Confirmed threat intel IOC match on {ioc.matched_hostname}: "
                    f"{ioc.value} ({ioc.indicator_type}), attributed to {actor}. {ioc.description}"
                ),
                related_technique_id=None,
                related_ioc_value=ioc.value,
            )
        )

    return items
