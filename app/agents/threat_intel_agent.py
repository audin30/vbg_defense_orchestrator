"""Threat Intel Agent: expertise = does this activity match known adversary behavior.

Two independent signals, either of which is meaningful on its own:
1. Direct IOC hit -- an indicator value (IP/domain/hash) literally appears in
   an alert's text. High confidence, low recall (only catches known infra).
2. TTP overlap -- the set of ATT&CK techniques seen in the incident overlaps
   a tracked actor profile's known technique set. Lower confidence on its
   own (many actors share common techniques), but doesn't require the
   attacker to reuse known infrastructure.
"""
from sqlalchemy.orm import Session

from app.agents.context import ActorMatch, IocMatch, ThreatIntelReport
from app.models import Alert, ThreatActorProfile, ThreatIndicator

MIN_TECHNIQUE_OVERLAP = 0.3


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
                        )
                    )

        actor_matches = []
        if incident_technique_ids:
            for profile in db.query(ThreatActorProfile).all():
                profile_technique_ids = set(profile.associated_technique_ids.split(","))
                overlap_ids = incident_technique_ids & profile_technique_ids
                if not overlap_ids:
                    continue
                jaccard = len(overlap_ids) / len(incident_technique_ids | profile_technique_ids)
                if jaccard >= MIN_TECHNIQUE_OVERLAP:
                    actor_matches.append(
                        ActorMatch(
                            threat_actor_name=profile.name,
                            description=profile.description,
                            technique_overlap=round(jaccard, 2),
                            matched_technique_ids=sorted(overlap_ids),
                        )
                    )
        actor_matches.sort(key=lambda a: a.technique_overlap, reverse=True)

        return ThreatIntelReport(ioc_matches=ioc_matches, actor_matches=actor_matches)


threat_intel_agent = ThreatIntelAgent()
