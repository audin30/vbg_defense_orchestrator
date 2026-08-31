"""Asset exposure/criticality-weighted vulnerability risk scoring.

This is deliberately separate from raw CVSS: two hosts with the identical CVE
can warrant very different urgency depending on what the asset is and how
exposed it is. A 9.8 CVSS finding on an isolated backup vault is not the same
risk as a 7.5 on an internet-facing e-commerce server.
"""
from sqlalchemy.orm import Session

from app.models import Asset, Exposure, Vulnerability

# Multiplicative: internet-facing findings are treated as near-top-priority
# almost regardless of CVSS, since attacker access cost is close to zero;
# isolated assets are discounted since an attacker needs another foothold
# first. Applied to the CVSS base rather than added, so it separates
# "critical everything" from "low everything" more sharply than a flat bonus.
_EXPOSURE_MULTIPLIER = {
    Exposure.INTERNET_FACING: 1.5,
    Exposure.INTERNAL: 1.0,
    Exposure.ISOLATED: 0.5,
}
# Additive, on top of the exposure-weighted CVSS base -- these don't need the
# same sharp separation, just a consistent nudge.
_CRITICALITY_WEIGHT = 0.4  # per point of asset.criticality (1-5) -> up to +2.0
_EPSS_WEIGHT = 2.0  # applied to epss_score (0-1) -- EPSS is often a better
# real-world exploitation predictor than CVSS alone, so it earns its own term
# rather than being folded into the CVSS base.
_KEV_BONUS = 3.0  # confirmed active exploitation (CISA KEV) -- a flat boost
# rather than a multiplier, since it should matter even on a low-CVSS finding
# that's nonetheless being actively exploited in the wild.


def compute_risk_score(vuln: Vulnerability, asset: Asset) -> float:
    """Combine CVSS severity with asset criticality and exposure into one
    prioritization score. Higher = fix sooner. Not directly comparable across
    orgs/tunings -- only the relative ordering within this deployment matters,
    since the API layer sorts descending."""
    score = vuln.cvss_score * _EXPOSURE_MULTIPLIER[asset.exposure]
    score += asset.criticality * _CRITICALITY_WEIGHT
    score += vuln.epss_score * _EPSS_WEIGHT
    if vuln.kev_listed:
        score += _KEV_BONUS
    return round(score, 2)


def recompute_all_risk_scores(db: Session) -> int:
    """Recompute and persist risk_score for every vulnerability. Call after
    ingestion, or on a schedule once real scanners are wired up."""
    updated = 0
    for vuln in db.query(Vulnerability).all():
        vuln.risk_score = compute_risk_score(vuln, vuln.asset)
        updated += 1
    db.commit()
    return updated


def ranked_vulnerabilities(db: Session, limit: int = 20) -> list[Vulnerability]:
    """Highest-priority open vulnerabilities, asset-weighted score descending."""
    return (
        db.query(Vulnerability)
        .join(Asset)
        .filter(Vulnerability.status == "open")
        .order_by(Vulnerability.risk_score.desc())
        .limit(limit)
        .all()
    )
