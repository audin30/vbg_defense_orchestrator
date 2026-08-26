"""Typed handoff objects passed between agents.

Each specialist agent (Inventory, Vulnerability Management, Threat Intel)
returns one of these from its query method rather than raw ORM rows -- it's
the "contract" the Incident Response Agent correlates across. Keeping these
as plain dataclasses (not ORM models) means an agent can be swapped for a
smarter implementation later without changing what it hands back.
"""
from dataclasses import dataclass, field


@dataclass
class AssetFinding:
    asset_id: str
    hostname: str
    criticality: int  # 1-5
    exposure: str  # "internet_facing" | "internal" | "isolated"
    data_sensitivity: int  # 1-5
    business_unit: str


@dataclass
class VulnFinding:
    cve_id: str
    title: str
    cvss_score: float
    epss_score: float
    kev_listed: bool
    hostname: str


@dataclass
class IocMatch:
    indicator_type: str
    value: str
    confidence: float
    description: str
    threat_actor_name: str | None
    matched_hostname: str  # which asset's alert text contained the indicator


@dataclass
class ActorMatch:
    threat_actor_name: str
    description: str
    technique_overlap: float  # 0-1, jaccard similarity of TTPs
    matched_technique_ids: list[str]


@dataclass
class InventoryReport:
    assets: list[AssetFinding] = field(default_factory=list)

    @property
    def max_criticality(self) -> int:
        return max((a.criticality for a in self.assets), default=0)

    @property
    def has_internet_facing_asset(self) -> bool:
        return any(a.exposure == "internet_facing" for a in self.assets)


@dataclass
class VulnManagementReport:
    findings: list[VulnFinding] = field(default_factory=list)

    @property
    def has_kev_listed(self) -> bool:
        return any(f.kev_listed for f in self.findings)

    @property
    def max_cvss(self) -> float:
        return max((f.cvss_score for f in self.findings), default=0.0)


@dataclass
class ThreatIntelReport:
    ioc_matches: list[IocMatch] = field(default_factory=list)
    actor_matches: list[ActorMatch] = field(default_factory=list)

    @property
    def has_ioc_hit(self) -> bool:
        return len(self.ioc_matches) > 0

    @property
    def top_actor_overlap(self) -> float:
        return max((a.technique_overlap for a in self.actor_matches), default=0.0)


@dataclass
class EvidenceFinding:
    """One artifact the IR Agent directs be collected/preserved, and why."""

    asset_hostname: str
    evidence_type: str
    source: str  # collection system, e.g. "EDR", "SIEM", "Firewall/NDR"
    justification: str
    related_technique_id: str | None
    related_ioc_value: str | None  # set when this item exists because of a threat-intel IOC hit

    @property
    def tied_to_threat_intel(self) -> bool:
        return self.related_ioc_value is not None


@dataclass
class RunbookStep:
    """One action from a response sub-agent's runbook, ordered within its plan."""

    order: int
    phase: str  # "analyze" | "contain" | "eradicate" | "recover"
    action: str
    scope_hostname: str | None  # None = incident-wide, else scoped to one asset


@dataclass
class ResponsePlan:
    """One IRP-category response sub-agent's output: its runbook instantiated
    against this incident's affected assets. Steps are recommendations only --
    execution authority stays with the Incident Commander gate."""

    category: str  # e.g. "malware", "ransomware", "phishing"
    runbook_name: str
    triggered_by_technique_ids: list[str]
    steps: list[RunbookStep] = field(default_factory=list)


@dataclass
class TriageReport:
    """The Incident Response Agent's handoff to the Incident Commander Agent."""

    incident_id: str
    criticality: str  # AlertSeverity value: low/medium/high/critical
    criticality_score: float  # 0-1
    inventory: InventoryReport
    vuln_management: VulnManagementReport
    threat_intel: ThreatIntelReport
    evidence_plan: list[EvidenceFinding]
    rationale: str
    reasoning_mode: str  # "deterministic" | "llm"
    response_plans: list[ResponsePlan] = field(default_factory=list)
