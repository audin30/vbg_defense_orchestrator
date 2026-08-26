"""Asset exposure/criticality-weighted vulnerability risk scoring.

This is deliberately separate from raw CVSS: two hosts with the identical CVE
can warrant very different urgency depending on what the asset is and how
exposed it is. A 9.8 CVSS finding on an isolated backup vault is not the same
risk as a 7.5 on an internet-facing e-commerce server.
"""
from sqlalchemy.orm import Session

from app.models import Asset, Vulnerability


def compute_risk_score(vuln: Vulnerability, asset: Asset) -> float:
    """Combine CVSS severity with asset criticality and exposure into one
    prioritization score. Higher = fix sooner.

    TODO(you): This is the core judgment call of the whole vuln-management
    pipeline, and there's no single right answer -- it encodes your org's risk
    appetite. Implement the weighting here.

    Inputs available:
      vuln.cvss_score   float, 0-10 (severity if exploited)
      vuln.epss_score   float, 0-1  (probability of exploitation in the wild;
                                     0.0 if the mock scanner didn't supply one)
      vuln.kev_listed   bool        (CISA Known Exploited Vulnerabilities --
                                     already being used in active attacks)
      asset.criticality       int, 1-5 (business importance of the asset)
      asset.exposure           Exposure enum: INTERNET_FACING / INTERNAL / ISOLATED
      asset.data_sensitivity  int, 1-5 (how sensitive the data on it is)

    Trade-offs to weigh:
      - How much should internet-facing amplify risk vs. internal? A common
        approach: internet-facing findings get treated as top priority almost
        regardless of CVSS, since attacker access cost is near zero.
      - Should KEV-listed vulns override everything else (i.e. floor/boost the
        score) since they're confirmed under active exploitation?
      - Do you want a multiplicative model (cvss * criticality_weight *
        exposure_weight) or additive (cvss + bonus_points)? Multiplicative
        tends to separate "critical everything" from "low everything" more
        sharply; additive is easier to reason about and tune incrementally.
      - Where does EPSS fit relative to CVSS -- EPSS is often a *better*
        predictor of real-world exploitation than CVSS alone.

    Return a float; the API layer sorts descending, so scale doesn't matter as
    long as it's consistent (e.g. keep results roughly in the 0-10 or 0-100 range).
    """
    raise NotImplementedError(
        "Implement compute_risk_score() in app/services/vuln_prioritization.py "
        "-- see the docstring for inputs and trade-offs to consider."
    )


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
