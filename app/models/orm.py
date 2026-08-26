"""SQLAlchemy ORM models for the defense orchestrator's core entities."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Exposure(str, enum.Enum):
    INTERNET_FACING = "internet_facing"
    INTERNAL = "internal"
    ISOLATED = "isolated"


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    hostname: Mapped[str] = mapped_column(String, unique=True)
    ip_address: Mapped[str] = mapped_column(String)
    criticality: Mapped[int] = mapped_column(Integer)  # 1 (low) - 5 (crown jewel)
    exposure: Mapped[Exposure] = mapped_column(Enum(Exposure), default=Exposure.INTERNAL)
    data_sensitivity: Mapped[int] = mapped_column(Integer, default=1)  # 1-5
    business_unit: Mapped[str] = mapped_column(String, default="unknown")
    tags: Mapped[str] = mapped_column(String, default="")  # comma-separated

    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="asset")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="asset")


class VulnStatus(str, enum.Enum):
    OPEN = "open"
    MITIGATED = "mitigated"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    cve_id: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String)
    cvss_score: Mapped[float] = mapped_column(Float)
    epss_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0-1 exploitation probability
    kev_listed: Mapped[bool] = mapped_column(Boolean, default=False)  # CISA Known Exploited Vulns
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    status: Mapped[VulnStatus] = mapped_column(Enum(VulnStatus), default=VulnStatus.OPEN)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    # Populated by the risk-scoring service, not set directly by connectors.
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    asset: Mapped["Asset"] = relationship(back_populates="vulnerabilities")


class AlertSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    source: Mapped[str] = mapped_column(String)  # e.g. "mock-siem", "splunk", "crowdstrike"
    title: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[AlertSeverity] = mapped_column(Enum(AlertSeverity))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    attack_technique_id: Mapped[str | None] = mapped_column(
        ForeignKey("attack_techniques.id"), nullable=True
    )
    detection_rule_id: Mapped[str | None] = mapped_column(
        ForeignKey("detection_rules.id"), nullable=True
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="alerts")
    attack_technique: Mapped["AttackTechnique | None"] = relationship()


class AttackTechnique(Base):
    """A curated subset of MITRE ATT&CK (Enterprise) techniques."""

    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(String, primary_key=True)  # e.g. "T1059"
    name: Mapped[str] = mapped_column(String)
    tactic: Mapped[str] = mapped_column(String)  # e.g. "Execution"


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text, default="")
    attack_technique_id: Mapped[str] = mapped_column(ForeignKey("attack_techniques.id"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    attack_technique: Mapped["AttackTechnique"] = relationship()


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String)
    severity: Mapped[AlertSeverity] = mapped_column(Enum(AlertSeverity))
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)  # 0-1
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    asset: Mapped["Asset"] = relationship()
    alerts: Mapped[list["Alert"]] = relationship(foreign_keys=[Alert.incident_id])
    playbook_executions: Mapped[list["PlaybookExecution"]] = relationship(back_populates="incident")


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    trigger_attack_technique_id: Mapped[str | None] = mapped_column(
        ForeignKey("attack_techniques.id"), nullable=True
    )
    trigger_min_severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity), default=AlertSeverity.HIGH
    )
    actions: Mapped[str] = mapped_column(String)  # comma-separated action names, executed in order


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    playbook_id: Mapped[str] = mapped_column(ForeignKey("playbooks.id"))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    actions_taken: Mapped[str] = mapped_column(Text)  # log of simulated action results
    executed_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    incident: Mapped["Incident"] = relationship(back_populates="playbook_executions")


class ThreatActorProfile(Base):
    """A tracked threat cluster (mock/fictional labels, not real attributed groups).

    Associated with a set of ATT&CK techniques so the Threat Intel Agent can
    flag TTP overlap even when there's no direct IOC hit.
    """

    __tablename__ = "threat_actor_profiles"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text, default="")
    associated_technique_ids: Mapped[str] = mapped_column(String)  # comma-separated


class ThreatIndicator(Base):
    """A single IOC (IP, domain, or hash)."""

    __tablename__ = "threat_indicators"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    indicator_type: Mapped[str] = mapped_column(String)  # "ip" | "domain" | "hash"
    value: Mapped[str] = mapped_column(String, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    description: Mapped[str] = mapped_column(Text, default="")
    threat_actor_id: Mapped[str | None] = mapped_column(
        ForeignKey("threat_actor_profiles.id"), nullable=True
    )

    threat_actor: Mapped["ThreatActorProfile | None"] = relationship()


class ReasoningMode(str, enum.Enum):
    DETERMINISTIC = "deterministic"
    LLM = "llm"


class IncidentTriage(Base):
    """The Incident Response Agent's structured handoff to the Incident
    Commander Agent -- one row per incident, produced by cross-referencing
    the Inventory, Vulnerability Management, and Threat Intel agents."""

    __tablename__ = "incident_triages"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), unique=True)
    criticality: Mapped[AlertSeverity] = mapped_column(Enum(AlertSeverity))
    criticality_score: Mapped[float] = mapped_column(Float)  # 0-1, before bucketing
    asset_context_summary: Mapped[str] = mapped_column(Text)
    vuln_context_summary: Mapped[str] = mapped_column(Text)
    threat_intel_summary: Mapped[str] = mapped_column(Text)
    evidence_summary: Mapped[str] = mapped_column(Text, default="")
    rationale: Mapped[str] = mapped_column(Text)
    reasoning_mode: Mapped[ReasoningMode] = mapped_column(Enum(ReasoningMode))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    incident: Mapped["Incident"] = relationship()


class EvidenceItem(Base):
    """One piece of evidence the Incident Response Agent has directed be
    collected and preserved from an impacted asset -- derived either from
    the ATT&CK technique observed (see evidence_catalog.py) or from a direct
    threat-intel IOC match, so the chain of custody records *why* each
    artifact was pulled."""

    __tablename__ = "evidence_items"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    asset_hostname: Mapped[str] = mapped_column(String)
    evidence_type: Mapped[str] = mapped_column(String)
    source: Mapped[str] = mapped_column(String)  # e.g. "EDR", "SIEM", "Firewall/NDR"
    justification: Mapped[str] = mapped_column(Text)
    related_technique_id: Mapped[str | None] = mapped_column(
        ForeignKey("attack_techniques.id"), nullable=True
    )
    related_ioc_value: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class ResponseDecision(str, enum.Enum):
    MONITOR = "monitor"
    ESCALATE = "escalate"
    AUTO_CONTAIN = "auto_contain"


class CommanderDecision(Base):
    """The Incident Commander Agent's final call on an incident, made from
    the IR Agent's triage report."""

    __tablename__ = "commander_decisions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), unique=True)
    decision: Mapped[ResponseDecision] = mapped_column(Enum(ResponseDecision))
    summary: Mapped[str] = mapped_column(Text)
    reasoning_mode: Mapped[ReasoningMode] = mapped_column(Enum(ReasoningMode))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    incident: Mapped["Incident"] = relationship()
