"""Threat Analyzer Agent.

Runs before the Incident Commander sees an incident at all, and before the
Incident Response Agent does any evidence planning or response sub-agent
dispatch. Its one job: correlate everything the Inventory, Vulnerability
Management, and Threat Intel agents know about an incident's assets into a
single deterministic risk score, and recommend whether the incident is worth
the full triage pipeline.

Criticality scoring here is the canonical implementation -- the Incident
Commander's gate() consults it to decide route-vs-skip, and the Incident
Response Agent reuses its output (score, rating, and the already-gathered
context reports) instead of re-querying the same three agents a second time.
"""
from sqlalchemy.orm import Session

from app.agents.context import RiskAssessment
from app.agents.inventory_agent import inventory_agent
from app.agents.threat_intel_agent import threat_intel_agent
from app.agents.vulnerability_agent import vulnerability_agent
from app.models import AlertSeverity, Incident, ThreatAnalysis

# Deterministic risk-score weights. Each bounded contribution sums to at most
# 1.0. Tune these to match your org's risk appetite -- e.g. raise KEV_BONUS
# if actively-exploited CVEs should dominate the assessment.
_SEVERITY_VALUE = {
    AlertSeverity.LOW: 0.25,
    AlertSeverity.MEDIUM: 0.5,
    AlertSeverity.HIGH: 0.75,
    AlertSeverity.CRITICAL: 1.0,
}
_CONFIDENCE_WEIGHT = 0.25
_SEVERITY_WEIGHT = 0.20
_ASSET_CRITICALITY_WEIGHT = 0.20
_EXPOSURE_BONUS = 0.10
_KEV_BONUS = 0.15
_THREAT_INTEL_BONUS = 0.10

_CRITICALITY_THRESHOLDS = [
    (0.75, AlertSeverity.CRITICAL),
    (0.50, AlertSeverity.HIGH),
    (0.30, AlertSeverity.MEDIUM),
]

# An incident is recommended into full triage once it rates HIGH or above --
# the same bar the Commander's old inline gate approximated with cheap OR'd
# heuristics. This is now a single weighted judgment instead.
_RECOMMEND_AT = (AlertSeverity.HIGH, AlertSeverity.CRITICAL)

# Ordinal ranking used only to compare a Commander-supplied override floor
# against the computed rating -- a floor can only raise the rating, never
# suppress it. A human commander escalating a case they believe is
# under-scored is a safe operation; letting an override silently downgrade
# a legitimately high finding is not, so that direction isn't supported.
_RATING_ORDER = [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]


def _bucket(score: float) -> AlertSeverity:
    for threshold, level in _CRITICALITY_THRESHOLDS:
        if score >= threshold:
            return level
    return AlertSeverity.LOW


def _score(incident: Incident, inventory, vuln_mgmt, threat_intel) -> float:
    score = 0.0
    score += _CONFIDENCE_WEIGHT * incident.confidence
    score += _SEVERITY_WEIGHT * _SEVERITY_VALUE[incident.severity]
    score += _ASSET_CRITICALITY_WEIGHT * (inventory.max_criticality / 5)
    score += _EXPOSURE_BONUS if inventory.has_internet_facing_asset else 0.0
    score += _KEV_BONUS if vuln_mgmt.has_kev_listed else 0.0
    score += _THREAT_INTEL_BONUS if threat_intel.has_ioc_hit else _THREAT_INTEL_BONUS * threat_intel.top_actor_overlap
    return round(min(score, 1.0), 2)


def _rationale(incident: Incident, inventory, vuln_mgmt, threat_intel, rating: AlertSeverity, score: float, recommended: bool) -> str:
    parts = [
        f"{rating.value.upper()} risk (score {score}/1.0): correlation confidence {incident.confidence}, "
        f"{len(incident.alerts)} alert(s) across {len(inventory.assets)} asset(s)."
    ]
    if inventory.has_internet_facing_asset:
        parts.append("At least one affected asset is internet-facing.")
    if inventory.max_criticality >= 4:
        parts.append(f"Highest affected asset criticality: {inventory.max_criticality}/5.")
    if vuln_mgmt.has_kev_listed:
        cves = ", ".join(f.cve_id for f in vuln_mgmt.findings if f.kev_listed)
        parts.append(f"Known-exploited vulnerabilities open: {cves}.")
    if threat_intel.ioc_matches:
        actors = {m.threat_actor_name for m in threat_intel.ioc_matches if m.threat_actor_name}
        parts.append(f"Threat intel IOC match(es), linked to: {', '.join(actors) or 'unattributed indicator'}.")
    if threat_intel.actor_matches:
        top = threat_intel.actor_matches[0]
        parts.append(f"TTP overlap {int(top.technique_overlap * 100)}% with {top.threat_actor_name}.")
    parts.append(
        "Recommended for full IR Agent triage." if recommended else "Below the triage recommendation threshold."
    )
    return " ".join(parts)


class ThreatAnalyzerAgent:
    def analyze(
        self,
        db: Session,
        incident: Incident,
        override_floor: AlertSeverity | None = None,
        override_reason: str | None = None,
    ) -> RiskAssessment:
        """Computes the deterministic risk assessment. `override_floor` is
        set only when the Commander is requesting re-analysis
        (incident_commander_agent.request_reanalysis()): if the computed
        rating is below the floor, the rating is raised to it and
        `recommended` is re-derived from the raised rating -- the floor
        never lowers a rating the deterministic formula produced."""
        asset_ids = list({a.asset_id for a in incident.alerts})

        inventory = inventory_agent.get_context(db, asset_ids)
        vuln_mgmt = vulnerability_agent.get_context(db, asset_ids)
        threat_intel = threat_intel_agent.get_context(db, incident.alerts)

        score = _score(incident, inventory, vuln_mgmt, threat_intel)
        rating = _bucket(score)

        overridden = override_floor is not None and _RATING_ORDER.index(override_floor) > _RATING_ORDER.index(rating)
        if overridden:
            rating = override_floor

        recommended = rating in _RECOMMEND_AT
        rationale = _rationale(incident, inventory, vuln_mgmt, threat_intel, rating, score, recommended)
        if overridden:
            rationale += f" Commander override: raised to {rating.value.upper()} -- {override_reason}"

        analysis = db.query(ThreatAnalysis).filter_by(incident_id=incident.id).one_or_none()
        if analysis is None:
            analysis = ThreatAnalysis(incident_id=incident.id)
            db.add(analysis)
        elif overridden:
            analysis.revision += 1
        analysis.risk_score = score
        analysis.risk_rating = rating
        analysis.recommended = recommended
        analysis.rationale = rationale
        analysis.override_reason = override_reason if overridden else analysis.override_reason
        db.commit()

        return RiskAssessment(
            incident_id=incident.id,
            risk_score=score,
            risk_rating=rating.value,
            inventory=inventory,
            vuln_management=vuln_mgmt,
            threat_intel=threat_intel,
            rationale=rationale,
            recommended=recommended,
        )


threat_analyzer_agent = ThreatAnalyzerAgent()
