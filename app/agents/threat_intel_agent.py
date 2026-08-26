"""Threat Intel Agent: expertise = does this activity match known adversary behavior.

Two independent signals, either of which is meaningful on its own:
1. Direct IOC hit -- an indicator value (IP/domain/hash) literally appears in
   an alert's text. High confidence, low recall (only catches known infra).
   Each hit is optionally enriched via the IOC enrichment connector
   (VirusTotal once wired; a no-op by default).
2. TTP overlap -- how much of the incident's ATT&CK technique set a tracked
   actor profile covers. Measured as incident coverage (|overlap| /
   |incident techniques|), NOT Jaccard: real MITRE intrusion sets know
   hundreds of techniques, which makes Jaccard vanish for any small incident
   regardless of how well the actor explains it.
"""
from sqlalchemy.orm import Session

from app.agents.context import ActorMatch, IocMatch, ThreatIntelReport
from app.connectors import ioc_enrichment_connector
from app.models import Alert, ThreatActorProfile, ThreatIndicator

# An actor matches when it covers at least half the incident's techniques,
# with at least 2 techniques in common (1 shared common technique like T1059
# says nothing). Only the strongest few matches are worth reporting -- common
# techniques make many real groups partially match any incident.
MIN_INCIDENT_COVERAGE = 0.5
MIN_OVERLAP_COUNT = 2
MAX_ACTOR_MATCHES = 3


class ThreatIntelAgent:
    def get_context(self, db: Session, alerts: list[Alert]) -> ThreatIntelReport:
        incident_technique_ids = {a.attack_technique_id for a in alerts if a.attack_technique_id}

        ioc_matches = []
        indicators = db.query(ThreatIndicator).all()
        for alert in alerts:
            alert_text = f"{alert.title} {alert.description}".lower()
            for indicator in indicators:
                if indicator.value.lower() in alert_text:
                    ioc_matches.append(
                        IocMatch(
                            indicator_type=indicator.indicator_type,
                            value=indicator.value,
                            confidence=indicator.confidence,
                            description=indicator.description,
                            threat_actor_name=indicator.threat_actor.name if indicator.threat_actor else None,
                            matched_hostname=alert.asset.hostname,
                            enrichment=ioc_enrichment_connector.enrich(
                                indicator.indicator_type, indicator.value
                            ),
                        )
                    )

        actor_matches = []
        if incident_technique_ids:
            for profile in db.query(ThreatActorProfile).all():
                profile_technique_ids = set(profile.associated_technique_ids.split(","))
                overlap_ids = incident_technique_ids & profile_technique_ids
                if len(overlap_ids) < MIN_OVERLAP_COUNT:
                    continue
                coverage = len(overlap_ids) / len(incident_technique_ids)
                if coverage >= MIN_INCIDENT_COVERAGE:
                    actor_matches.append(
                        ActorMatch(
                            threat_actor_name=profile.name,
                            description=profile.description,
                            technique_overlap=round(coverage, 2),
                            matched_technique_ids=sorted(overlap_ids),
                        )
                    )
        actor_matches.sort(key=lambda a: (a.technique_overlap, len(a.matched_technique_ids)), reverse=True)
        actor_matches = actor_matches[:MAX_ACTOR_MATCHES]

        return ThreatIntelReport(ioc_matches=ioc_matches, actor_matches=actor_matches)


threat_intel_agent = ThreatIntelAgent()
