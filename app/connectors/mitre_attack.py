"""MITRE ATT&CK Enterprise catalog connector.

Consumes the official STIX 2.1 bundle published by MITRE (~40MB JSON).
Cached locally for 7 days -- the dataset changes a few times a year. Yields
two datasets:

- techniques: every non-deprecated attack-pattern, sub-techniques included
  (ids like "T1003.001"), with a single primary tactic (the first
  kill-chain phase, matching the existing AttackTechnique schema).
- actor groups: every non-deprecated intrusion-set with >= MIN_GROUP_TECHNIQUES
  "uses" relationships to techniques, shaped like
  ThreatIntelConnector.fetch_actor_profiles output so both feed
  ThreatActorProfile rows.

With no network and no cache, both fetches return [] and bootstrap falls
back to the curated seed via services/attack_mapping.
"""
from typing import Any

from app.connectors._http_cache import fetch_json_cached
from app.connectors.base import AttackCatalogConnector

ATTACK_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
_CACHE_FILENAME = "enterprise-attack.json"
_MAX_AGE_SECONDS = 7 * 24 * 3600

# Groups with almost no mapped techniques add noise without enabling
# meaningful TTP-overlap matching.
MIN_GROUP_TECHNIQUES = 3


def _mitre_external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _is_active(obj: dict) -> bool:
    return not obj.get("x_mitre_deprecated", False) and not obj.get("revoked", False)


def _tactic_display(phase_name: str) -> str:
    return phase_name.replace("-", " ").title()


class MitreAttackConnector(AttackCatalogConnector):
    def __init__(self) -> None:
        self._bundle: dict | None = None
        self._loaded = False

    def _objects(self) -> list[dict]:
        if not self._loaded:
            self._bundle = fetch_json_cached(ATTACK_BUNDLE_URL, _CACHE_FILENAME, _MAX_AGE_SECONDS)
            self._loaded = True
        if not self._bundle:
            return []
        return self._bundle.get("objects", [])

    def fetch_techniques(self) -> list[dict[str, Any]]:
        techniques = []
        for obj in self._objects():
            if obj.get("type") != "attack-pattern" or not _is_active(obj):
                continue
            tid = _mitre_external_id(obj)
            phases = obj.get("kill_chain_phases", [])
            if not tid or not tid.startswith("T") or not phases:
                continue
            techniques.append(
                {
                    "id": tid,
                    "name": obj.get("name", ""),
                    "tactic": _tactic_display(phases[0].get("phase_name", "unknown")),
                }
            )
        return techniques

    def fetch_actor_groups(self) -> list[dict[str, Any]]:
        objects = self._objects()
        if not objects:
            return []

        # STIX internal id -> ATT&CK technique id, for resolving relationships.
        pattern_tid_by_stix_id: dict[str, str] = {}
        groups_by_stix_id: dict[str, dict] = {}
        for obj in objects:
            if not _is_active(obj):
                continue
            if obj.get("type") == "attack-pattern":
                tid = _mitre_external_id(obj)
                if tid:
                    pattern_tid_by_stix_id[obj["id"]] = tid
            elif obj.get("type") == "intrusion-set":
                groups_by_stix_id[obj["id"]] = obj

        technique_ids_by_group: dict[str, set[str]] = {gid: set() for gid in groups_by_stix_id}
        for obj in objects:
            if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
                continue
            source, target = obj.get("source_ref", ""), obj.get("target_ref", "")
            if source in technique_ids_by_group and target in pattern_tid_by_stix_id:
                technique_ids_by_group[source].add(pattern_tid_by_stix_id[target])

        groups = []
        for gid, obj in groups_by_stix_id.items():
            technique_ids = technique_ids_by_group[gid]
            if len(technique_ids) < MIN_GROUP_TECHNIQUES:
                continue
            groups.append(
                {
                    "name": obj.get("name", ""),
                    "description": (obj.get("description", "") or "").split("\n")[0][:500],
                    "attack_technique_ids": sorted(technique_ids),
                }
            )
        return groups
