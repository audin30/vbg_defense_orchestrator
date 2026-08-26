"""Correlates raw alerts into incidents.

Two-stage approach, mirroring how real SIEM/SOAR correlation typically works:

1. Per-asset time-window clustering: alerts on the same host within
   `CLUSTER_WINDOW` of each other are almost certainly related (same actor,
   same session).
2. Cross-asset chaining: if a cluster contains a lateral-movement-style
   technique (the attacker moved from one host to another), and another
   asset's cluster ended shortly before that alert, merge the two clusters --
   it's very likely one continuous intrusion rather than two coincidences.

This is a heuristic, not a full graph-based correlation engine, but it's
enough to turn "5 separate alerts across 2 hosts" into "1 incident: web
server compromise pivoting to the domain controller."
"""
from datetime import timedelta

from sqlalchemy.orm import Session

from app.models import Alert, AlertSeverity, AttackTechnique, Incident

CLUSTER_WINDOW = timedelta(hours=3)
CROSS_ASSET_CHAIN_WINDOW = timedelta(hours=2)
LATERAL_MOVEMENT_TECHNIQUES = {"T1021", "T1570", "T1091", "T1210"}

_SEVERITY_ORDER = [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]


def _cluster_by_asset(alerts: list[Alert]) -> list[list[Alert]]:
    by_asset: dict[str, list[Alert]] = {}
    for a in alerts:
        by_asset.setdefault(a.asset_id, []).append(a)

    clusters: list[list[Alert]] = []
    for asset_alerts in by_asset.values():
        asset_alerts.sort(key=lambda a: a.occurred_at)
        current: list[Alert] = []
        for a in asset_alerts:
            if current and a.occurred_at - current[-1].occurred_at > CLUSTER_WINDOW:
                clusters.append(current)
                current = []
            current.append(a)
        if current:
            clusters.append(current)
    return clusters


def _chain_clusters(clusters: list[list[Alert]]) -> list[list[Alert]]:
    """Merge clusters that look like a continuous multi-host intrusion."""
    clusters = sorted(clusters, key=lambda c: c[0].occurred_at)
    merged = True
    while merged:
        merged = False
        for i, cluster_a in enumerate(clusters):
            has_pivot = any(a.attack_technique_id in LATERAL_MOVEMENT_TECHNIQUES for a in cluster_a)
            if not has_pivot:
                continue
            pivot_time = min(
                a.occurred_at for a in cluster_a if a.attack_technique_id in LATERAL_MOVEMENT_TECHNIQUES
            )
            for j, cluster_b in enumerate(clusters):
                if i == j:
                    continue
                asset_a = {a.asset_id for a in cluster_a}
                asset_b = {a.asset_id for a in cluster_b}
                if asset_a & asset_b:
                    continue  # already same asset, would've been one cluster already
                cluster_b_end = max(a.occurred_at for a in cluster_b)
                if timedelta(0) <= pivot_time - cluster_b_end <= CROSS_ASSET_CHAIN_WINDOW:
                    clusters[i] = cluster_a + cluster_b
                    clusters.pop(j)
                    merged = True
                    break
            if merged:
                break
    return clusters


def _confidence(cluster: list[Alert]) -> float:
    num_assets = len({a.asset_id for a in cluster})
    num_tactics = len({a.attack_technique_id for a in cluster if a.attack_technique_id})
    max_severity = max((a.severity for a in cluster), key=_SEVERITY_ORDER.index)
    severity_bonus = _SEVERITY_ORDER.index(max_severity) / (len(_SEVERITY_ORDER) - 1) * 0.3

    score = 0.1 * len(cluster) + 0.1 * num_tactics + (0.25 if num_assets > 1 else 0) + severity_bonus
    return round(min(score, 1.0), 2)


def correlate_alerts_into_incidents(db: Session) -> list[Incident]:
    """Correlate any alert not yet attached to an incident. Existing incidents
    are left untouched (call this incrementally after each ingestion run)."""
    unassigned = db.query(Alert).filter(Alert.incident_id.is_(None)).all()
    if not unassigned:
        return []

    clusters = _chain_clusters(_cluster_by_asset(unassigned))

    created: list[Incident] = []
    for cluster in clusters:
        cluster.sort(key=lambda a: a.occurred_at)
        max_severity = max((a.severity for a in cluster), key=_SEVERITY_ORDER.index)
        primary_asset_id = cluster[0].asset_id  # earliest alert = likely entry point
        technique_names = _technique_titles(db, cluster)

        incident = Incident(
            title=f"{'Multi-host ' if len({a.asset_id for a in cluster}) > 1 else ''}"
            f"incident: {technique_names}",
            severity=max_severity,
            asset_id=primary_asset_id,
            confidence=_confidence(cluster),
        )
        db.add(incident)
        db.flush()  # assign incident.id

        for a in cluster:
            a.incident_id = incident.id

        created.append(incident)

    db.commit()
    return created


def _technique_titles(db: Session, cluster: list[Alert]) -> str:
    ids = [a.attack_technique_id for a in cluster if a.attack_technique_id]
    if not ids:
        return "uncategorized activity"
    first_id = ids[0]
    last_id = ids[-1]
    first = db.get(AttackTechnique, first_id)
    last = db.get(AttackTechnique, last_id)
    if first_id == last_id or last is None:
        return first.name if first else first_id
    return f"{first.name if first else first_id} -> {last.name}"
