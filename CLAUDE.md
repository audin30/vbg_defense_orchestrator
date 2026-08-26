# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A defense orchestrator combining SIEM alert correlation, MITRE ATT&CK-mapped
detection coverage, asset-weighted vulnerability prioritization, and a
five-agent SOAR triage/response pipeline. Backend is FastAPI + SQLAlchemy
(SQLite), frontend is a single static HTML/vanilla-JS dashboard with no
build step, served by FastAPI itself.

All external data sources (SIEM, vuln scanner, asset inventory, threat
intel) are currently **mocked** with a deliberately coherent synthetic
attack scenario — see "The mock scenario" below.

## Commands

```bash
# Setup (first time)
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Run the dev server (dashboard at http://127.0.0.1:8000/)
.venv/bin/uvicorn app.main:app --reload

# Seed reference data + ingest mock sources + correlate + run the agent pipeline
# (idempotent — safe to re-run; also exposed as POST /bootstrap)
.venv/bin/python -m app.bootstrap

# Run tests
.venv/bin/python -m pytest tests/ -v

# Run a single test
.venv/bin/python -m pytest tests/test_correlation_service.py::test_lateral_movement_chains_two_assets_into_one_incident -v
```

There is no linter/formatter configured in this repo yet.

The SQLite DB file is `orchestrator.db` at the repo root, created on first
`run_bootstrap()` call. Delete it to reset all state; nothing in the app
depends on it persisting across runs.

## Architecture

### Connector abstraction — the mock-to-real seam

`app/connectors/base.py` defines four abstract interfaces: `SIEMConnector`,
`VulnScannerConnector`, `AssetInventoryConnector`, `ThreatIntelConnector`.
Every service in the app talks only to these interfaces, never to a
concrete product. `app/connectors/mock.py` implements all four against
synthetic data; `app/connectors/__init__.py` is the single wiring point that
decides which concrete connector backs each interface (`siem_connector`,
`vuln_scanner_connector`, `asset_inventory_connector`,
`threat_intel_connector`). To add a real integration (Splunk, Qualys,
CrowdStrike, a TIP), implement the matching base class in a new
`app/connectors/<product>.py` and change the import in `__init__.py` —
nothing else in the app changes.

### Data pipeline

`app/bootstrap.py::run_bootstrap()` is the orchestration entry point (also
exposed as `POST /bootstrap`):

1. `services/attack_mapping.seed_attack_techniques` + seed detection
   rules/playbooks from `app/seed/detections_and_playbooks.py`
2. `services/ingestion_service.run_full_ingestion` — pulls from all four
   connectors, normalizes into ORM rows, idempotent by natural key
   (hostname, cve_id+asset, alert title+asset+time, indicator value)
3. `services/vuln_prioritization.recompute_all_risk_scores` — currently
   raises `NotImplementedError` (see "Known incomplete piece" below);
   bootstrap catches this and continues
4. `services/correlation_service.correlate_alerts_into_incidents` — clusters
   unassigned alerts per-asset by time window, then chains clusters across
   assets when a lateral-movement technique (T1021/T1570/T1091/T1210)
   bridges them within `CROSS_ASSET_CHAIN_WINDOW`
5. For each new `Incident`: `agents.incident_response_agent.triage()` then
   `agents.incident_commander_agent.decide()` (see "Agent pipeline" below)

### Agent pipeline

Five agents in `app/agents/`, each wrapping existing services behind a
typed contract (`app/agents/context.py` dataclasses — `AssetFinding`,
`VulnFinding`, `IocMatch`, `ActorMatch`, `EvidenceFinding`, `TriageReport`,
etc.) rather than raw ORM rows:

- **Inventory Agent** (`inventory_agent.py`) — asset criticality/exposure/
  business-unit context for a set of asset IDs
- **Vulnerability Management Agent** (`vulnerability_agent.py`) — open
  findings on those assets, KEV-listed first
- **Threat Intel Agent** (`threat_intel_agent.py`) — two independent
  signals, evaluated per-alert (so each match is attributed to the specific
  asset it was found on, via `IocMatch.matched_hostname`): direct IOC
  substring match against alert text, and ATT&CK technique-set Jaccard
  overlap against tracked actor profiles (`MIN_TECHNIQUE_OVERLAP = 0.3`)
- **Incident Response Agent** (`incident_response_agent.py`) — the hub:
  calls the three agents above, computes a deterministic weighted
  criticality score (`_CONFIDENCE_WEIGHT`, `_SEVERITY_WEIGHT`,
  `_ASSET_CRITICALITY_WEIGHT`, `_EXPOSURE_BONUS`, `_KEV_BONUS`,
  `_THREAT_INTEL_BONUS` — sum to 1.0 by construction, tune to change risk
  appetite), builds an evidence collection/preservation plan (see below),
  spawns IRP response sub-agents (see "Response sub-agents" below),
  persists an `IncidentTriage` row, hands a `TriageReport` to the Commander
- **Incident Commander Agent** (`incident_commander_agent.py`) — gates
  response by criticality: `critical → AUTO_CONTAIN` (executes matching
  SOAR playbooks via `services/soar_engine`), `high → ESCALATE` (notify
  only, no automated containment), `medium`/`low → MONITOR` (no action).
  Persists a `CommanderDecision` row. **This is the only place SOAR
  playbooks get triggered** — nothing executes automated response outside
  this gate.

### Response sub-agents (IRP annexes)

`app/agents/response/` holds one sub-agent per Incident Response Playbook
category — malware, ransomware, phishing, credential compromise, lateral
movement, data exfiltration — each a `ResponseSubAgent` subclass
(`base.py`) carrying its own runbook: an ordered list of
`(phase, action, per_affected_host)` steps across the NIST 800-61 phases
(`analyze`/`contain`/`eradicate`/`recover`). During `triage()`, the IR
Agent calls `dispatch_response_subagents(incident)`
(`response/__init__.py`), which classifies the incident by its observed
ATT&CK technique IDs and spawns every sub-agent whose trigger set
intersects them; each spawned sub-agent instantiates its runbook, scoping
per-host steps to the assets its trigger techniques were actually seen on.

Two invariants to preserve:

1. **Sub-agents recommend, they never execute.** Their output is persisted
   as `ResponseTask` rows (status `recommended`) and surfaced via
   `TriageReport.response_plans`, `triage.response_tasks` in
   `GET /incidents`, and `GET /response-tasks`. Automated containment still
   happens only through the Commander's SOAR gate.
2. **Ransomware is behavioral, not technique-triggered.** Its
   `matches()` override exists so precursor combinations (e.g. cred dump +
   lateral movement toward backup-tagged assets) can spawn the runbook
   before T1486 fires — the heuristic body is a deliberate placeholder
   (returns `False` beyond the direct T1486/T1490 triggers), same pattern
   as `compute_risk_score()`.

To add a category: subclass `ResponseSubAgent` in a new
`app/agents/response/<category>.py` and append its instance to
`RESPONSE_SUBAGENTS` in `response/__init__.py`.

### Evidence collection & preservation

`app/agents/evidence_planner.py::build_evidence_plan()` is called by the IR
Agent as part of `triage()`, not a separate agent. It produces a list of
`EvidenceFinding`, each traceable to exactly one of two sources:

1. **ATT&CK technique** — every alert's `attack_technique_id` is looked up
   in `app/seed/evidence_catalog.py::TECHNIQUE_EVIDENCE_MAP` (technique →
   list of `(evidence_type, source_system)`; falls back to
   `DEFAULT_EVIDENCE` when unmapped). Deduped per `(hostname, evidence_type)`
   so repeated alerts of the same technique on the same host don't produce
   duplicate items.
2. **Threat intel IOC match** — every `IocMatch` from the Threat Intel
   Agent's report generates one evidence item via
   `IOC_EVIDENCE_BY_TYPE[indicator_type]`, scoped to `matched_hostname`.
   These are **never deduped** against technique-driven items — a confirmed
   IOC hit is independently justified and matters for chain-of-custody even
   if it recommends the same artifact type. `EvidenceFinding.tied_to_threat_intel`
   (true iff `related_ioc_value is not None`) is how callers distinguish
   the two origins.

Persisted as `EvidenceItem` rows (one per finding, FK'd to `incident_id`),
surfaced via `IncidentTriage.evidence_summary` (one-line text) and the
`GET /incidents` → `triage.evidence_items` array, and standalone at
`GET /evidence-items`.

### Hybrid LLM reasoning (optional)

`app/agents/llm_reasoning.py::reason()` is used by both the IR Agent and
Commander Agent to generate rationale/summary *text* on top of the
already-computed structured/deterministic data. If `ANTHROPIC_API_KEY` is
unset, or the API call fails for any reason, it silently falls back to a
deterministic templated string — the pipeline's decisions are never gated
on LLM availability, only the explanatory text changes. IR Agent uses
`claude-haiku-4-5-20251001` (runs on every incident), Commander uses
`claude-sonnet-5` (runs once per incident, higher stakes). Every
`IncidentTriage`/`CommanderDecision` row records which mode
(`deterministic`/`llm`) actually produced it.

### Known incomplete piece

`app/services/vuln_prioritization.py::compute_risk_score()` intentionally
raises `NotImplementedError` — the asset exposure/criticality-weighted risk
formula is left as a deliberate placeholder (see the function's docstring
for inputs and trade-offs). `recompute_all_risk_scores()` catches this
during bootstrap so the rest of the app runs fine with `risk_score: 0.0`
everywhere. `tests/test_vuln_prioritization.py` has three `@pytest.mark.skip`
tests to un-skip once it's implemented.

### The mock scenario

`app/seed/mock_scenario.py` (assets/vulns/alerts) and
`app/seed/mock_threat_intel.py` (IOCs/actor profiles) are **not
independent random fixtures** — they're one coherent attack chain designed
to exercise the whole pipeline: a public-facing web server
(`web-prod-01`) gets exploited via a KEV-listed CVE, credentials are
dumped, the attacker pivots to the domain controller (`dc-01`) via SMB,
then exfiltrates to an IP (`198.51.100.77`) that's also a seeded threat
indicator attributed to a mock actor profile (`SILENT-ORCHID`) whose
`attack_technique_ids` exactly match the alert chain's technique sequence.
Two unrelated low-severity alerts are mixed in as background noise. If you
add mock data, keep hostnames/IPs/technique IDs cross-referenced the same
way, or the correlation/threat-intel-matching demo value is lost.

### ORM models

All SQLAlchemy models live in one file, `app/models/orm.py` (re-exported
via `app/models/__init__.py`). Notable relationships: `Alert.incident_id`
is nullable and set by the correlation service, not at alert-creation time;
`IncidentTriage` and `CommanderDecision` are both one-per-incident
(`unique=True` on `incident_id`).

### Frontend

`app/static/index.html` is a single self-contained file (inline CSS/JS, no
build step) served at `GET /` by `app/main.py`. It calls the JSON API
directly via `fetch()` — `/assets`, `/vulnerabilities`, `/alerts`,
`/incidents` (embeds `triage`, including `triage.evidence_items`, +
`commander_decision` per incident), `/attack-coverage`,
`/threat-actor-profiles`, `/threat-indicators`, `/evidence-items`,
`/playbooks`, `/playbook-executions` — and a "Run Ingestion + Refresh"
button that POSTs `/bootstrap` then reloads. Dark-theme only, no light-mode
handling.
