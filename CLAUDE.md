# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A defense orchestrator combining SIEM alert correlation, MITRE ATT&CK-mapped
detection coverage, asset-weighted vulnerability prioritization, and a
six-agent SOAR triage/response pipeline. Backend is FastAPI + SQLAlchemy
(SQLite), frontend is a single static HTML/vanilla-JS dashboard with no
build step, served by FastAPI itself.

SIEM, vuln scanner, asset inventory, and IOC/TIP feeds are currently
**mocked** with a deliberately coherent synthetic attack scenario — see
"The mock scenario" below. Two intel sources are **live**: the CISA KEV
catalog and the MITRE ATT&CK Enterprise dataset (see "Live threat intel"
below); both degrade gracefully offline.

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

### Database

SQLite by default: the DB file is `orchestrator.db` at the repo root,
created on first `run_bootstrap()` call. Delete it to reset all state;
nothing in the app depends on it persisting across runs.

For the full stack, point `DATABASE_URL` at Postgres (SQLAlchemy makes the
engine a connection-string concern only):

```bash
docker compose up -d   # starts postgres:16 on localhost:5433 (offset from the
                        # default 5432 in case a native Postgres is already there)
DATABASE_URL=postgresql+psycopg2://orchestrator:orchestrator@localhost:5433/orchestrator \
  .venv/bin/python -m app.bootstrap
```

`.mcp.json` configures a read-only postgres MCP server
(`uvx postgres-mcp --access-mode=restricted`) against the same database, so
Claude Code can query the intel warehouse (KEV entries, actor profiles,
incidents) directly during dev/IR sessions. Tests always use in-memory
SQLite regardless of `DATABASE_URL`.

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

### Live threat intel (CISA KEV + MITRE ATT&CK)

Two connectors are live rather than mocked, both built on
`app/connectors/_http_cache.py::fetch_json_cached` (serve fresh cache →
refetch when stale → stale cache on failure → `None`; cache files live in
the gitignored `data/` dir):

- **CISA KEV** (`app/connectors/cisa_kev.py`, 24h cache) → upserted into the
  `KevEntry` table by `ingestion_service.ingest_kev_catalog`. After vuln
  ingestion, `apply_kev_enrichment` recomputes `Vulnerability.kev_listed`
  from the catalog (the catalog, not the scanner, is the source of truth —
  skipped when the catalog is empty, e.g. fully offline). The Vulnerability
  Management Agent surfaces `kev_due_date`/`kev_ransomware_use` per finding;
  `knownRansomwareCampaignUse` is a ready signal for the ransomware
  precursor heuristic.
- **MITRE ATT&CK** (`app/connectors/mitre_attack.py`, 7-day cache) parses
  the official Enterprise STIX bundle: ~700 techniques (sub-techniques
  included, deprecated/revoked skipped, first kill-chain phase = tactic)
  feed `seed_attack_techniques` (curated seed remains the offline
  fallback), and ~160 intrusion sets with ≥3 "uses" relationships feed
  `ThreatActorProfile` rows alongside the mock TIP profiles.

**Actor matching is incident-coverage, not Jaccard**
(`threat_intel_agent.py`): real groups know hundreds of techniques, which
makes Jaccard vanish for small incidents. A match needs the actor to cover
≥50% of the incident's techniques with ≥2 in common; top 3 reported.

VirusTotal is a defined seam only: `IocEnrichmentConnector` in
`connectors/base.py`, `NullIocEnrichmentConnector` wired by default,
`IocMatch.enrichment` carries the result once a real provider is added.

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
5. For each new `Incident`: `agents.incident_commander_agent.gate()`
   delegates to `agents.threat_analyzer_agent.analyze()` for a risk
   assessment. If `.recommended`, `agents.incident_response_agent.triage()`
   then `agents.incident_commander_agent.decide()` run; otherwise
   `agents.incident_commander_agent.skip()` records a direct `MONITOR`
   decision with no triage at all (see "Agent pipeline" below)
6. The batch of `ThreatAnalysis` rows just created is re-queried and ranked
   by `risk_score` descending, writing `risk_rank` (1 = highest risk) onto
   each — this is what a "highest risk first" analyst view sorts by

### Agent pipeline

Six agents in `app/agents/`, each wrapping existing services behind a typed
contract (`app/agents/context.py` dataclasses — `AssetFinding`,
`VulnFinding`, `IocMatch`, `ActorMatch`, `EvidenceFinding`, `RiskAssessment`,
`TriageReport`, etc.) rather than raw ORM rows:

- **Inventory Agent** (`inventory_agent.py`) — asset criticality/exposure/
  business-unit context for a set of asset IDs
- **Vulnerability Management Agent** (`vulnerability_agent.py`) — open
  findings on those assets, KEV-listed first
- **Threat Intel Agent** (`threat_intel_agent.py`) — two independent
  signals, evaluated per-alert (so each match is attributed to the specific
  asset it was found on, via `IocMatch.matched_hostname`): direct IOC
  substring match against alert text, and ATT&CK technique-set Jaccard
  overlap against tracked actor profiles (`MIN_TECHNIQUE_OVERLAP = 0.3`)
- **Threat Analyzer Agent** (`threat_analyzer_agent.py`) — runs first, right
  after correlation and before the Commander's gate or the IR Agent do
  anything: calls the three agents above, computes a deterministic weighted
  risk score (`_CONFIDENCE_WEIGHT`, `_SEVERITY_WEIGHT`,
  `_ASSET_CRITICALITY_WEIGHT`, `_EXPOSURE_BONUS`, `_KEV_BONUS`,
  `_THREAT_INTEL_BONUS` — sum to 1.0 by construction, tune to change risk
  appetite — this is the *canonical* scoring implementation, not
  duplicated elsewhere), buckets it into a `risk_rating`
  (low/medium/high/critical), and sets `recommended = True` at high/
  critical. Persists a `ThreatAnalysis` row and returns a `RiskAssessment`
  carrying both the score and the already-gathered
  Inventory/Vulnerability/Threat-Intel reports, so nothing downstream has
  to re-query them
- **Incident Response Agent** (`incident_response_agent.py`) — the hub for
  incidents the Analyzer recommends: `triage()` takes the `RiskAssessment`
  (reusing its score/rating/context reports rather than recomputing),
  builds an evidence collection/preservation plan (see below), spawns IRP
  response sub-agents (see "Response sub-agents" below), persists an
  `IncidentTriage` row, hands a `TriageReport` to the Commander. Calling
  `triage()` without a `RiskAssessment` (e.g. directly from a test) still
  works — it calls the Threat Analyzer Agent inline first
- **Incident Commander Agent** (`incident_commander_agent.py`) — bookends
  the pipeline around the two agents above. `gate(db, incident)` delegates
  straight to the Threat Analyzer and returns its `RiskAssessment`; callers
  route to `incident_response_agent.triage()` when `.recommended` is `True`
  or call `skip()` otherwise (records a `MONITOR` `CommanderDecision`
  directly, citing the Analyzer's rationale, with no `IncidentTriage` row).
  `decide(db, incident, triage)` is the final response-tier call, run only
  for triaged incidents: `critical → CONTAIN_PENDING_APPROVAL` (files a
  `ContainmentApproval` previewing which SOAR playbooks would run — nothing
  executes yet), `high → ESCALATE` (notify only), `medium`/`low → MONITOR`
  (no action). Persists a `CommanderDecision` row.

### Commander disagreement — bounded re-analysis, not a loop

`incident_commander_agent.request_reanalysis(db, incident, reason, override_floor=None)`
is how a human commander who disagrees with the Threat Analyzer's assessment
sends it back, exposed as `POST /incidents/{id}/reanalyze` (`reason` required,
`override_floor` an optional `AlertSeverity` value). Two deliberate
constraints keep this from becoming an open-ended agent argument:

- **One retry per incident.** `ThreatAnalysis.revision` starts at 1 and is
  bumped only when an override actually changes the rating; a second
  `request_reanalysis()` call raises `ReanalysisAlreadyRequested` (409 at the
  API) rather than looping — the correct next step is a human decision, not
  another automated pass.
- **A floor can only raise the rating, never lower it**
  (`threat_analyzer_agent._RATING_ORDER`) — escalating a case a human
  believes is under-scored is safe; letting an override silently suppress a
  legitimately high finding is not, so that direction isn't supported at all.

Both the prior and resulting assessment are snapshotted into a
`CommanderReanalysisRequest` row (`GET /reanalysis-requests` lists the audit
trail) — `ThreatAnalysis` itself still holds only the current row. If the
re-analysis flips `recommended` from `False` to `True` (the only direction
possible), `POST /incidents/{id}/reanalyze` deletes the stale `MONITOR`
`CommanderDecision` from `skip()` and immediately runs the incident through
`incident_response_agent.triage()` + `incident_commander_agent.decide()`, the
same routing `bootstrap.py` does on the first pass.

### Human-in-the-loop containment approval

**Remediation is never automatic.** The Commander cannot execute SOAR
playbooks directly — its strongest decision is `CONTAIN_PENDING_APPROVAL`,
which calls `soar_engine.matching_playbooks()` (match-only, no execution)
and persists a `ContainmentApproval` row (status `pending`) previewing
exactly what approval would run. `app/services/approval_service.py` is the
**only** path from that request to actual execution:
`approve_containment(db, approval_id, approver, note)` calls
`soar_engine.evaluate_and_execute()` and marks the incident `contained`;
`reject_containment()` executes nothing. Both record who decided, when, and
why. Exposed via `GET /containment-approvals` (analyst inbox — filter
`?status=pending`) and `POST /containment-approvals/{id}/approve|reject`
(dashboard renders inline Approve/Reject buttons on `CONTAIN_PENDING_APPROVAL`
incidents). **This is the only place SOAR playbooks get triggered** —
nothing executes automated response outside an explicit human approval.

**Containment feedback loop.** Neither HITL outcome is a dead end. Both
`approve_containment()` (when `soar_engine.evaluate_and_execute()` returns no
executions — approved, but nothing actually matched) and
`reject_containment()` call
`incident_commander_agent.handle_containment_outcome(db, incident, approval, outcome, note)`
straight after recording the approval decision. It deletes the stale
`CONTAIN_PENDING_APPROVAL` `CommanderDecision` and replaces it with the next
tier down (`_FALLBACK_DECISION`, today always `ESCALATE`), so the incident
doesn't sit on a containment request that was never going to execute. This
is terminal, not a loop — `ESCALATE` files no approval of its own, so there's
nothing further to reject or fail. Both the rejected/failed outcome and the
resulting decision are recorded in a `CommanderContainmentReview` row
(`GET /containment-reviews`).

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
   only happens through the Commander's HITL approval gate (see above).
2. **Ransomware is behavioral, not technique-triggered.** Its
   `matches()` override exists so precursor combinations (e.g. cred dump +
   lateral movement toward backup-tagged assets) can spawn the runbook
   before T1486 fires — the heuristic body is a deliberate placeholder
   (returns `False` beyond the direct T1486/T1490 triggers), same pattern
   as `compute_risk_score()`.

To add a category: subclass `ResponseSubAgent` in a new
`app/agents/response/<category>.py` and append its instance to
`RESPONSE_SUBAGENTS` in `response/__init__.py`.

### AWS IRP playbook sub-agents (Commander-stage dispatch)

`app/agents/response/aws/` holds a second tier of sub-agents distilled from
the AWS incident response playbook checkout at
`playbooks/aws-incident-response-playbooks/` (gitignored reference clone;
each subclass's `source_playbook` cites its markdown source). One sub-agent
per playbook present in the checkout — credential compromise, STS token
abuse, ransomware, data access, personal data breach, DoS, insider threat,
Identity Center compromise, federated access abuse, satellite operations —
all defined in `aws/catalog.py` (add new ones there, not in separate files).

They differ from the generic category sub-agents in two ways:

1. **Trigger vocabulary** — matched by prefix against `Alert.finding_type`
   (GuardDuty finding types / CloudTrail `eventName:...` values), not
   ATT&CK technique IDs. On-prem alerts have `finding_type = None` and can
   never spawn them.
2. **Dispatch stage** — activated by the **Commander's decision**, not at
   triage: `incident_commander_agent.decide()` calls
   `dispatch_aws_playbooks(incident, decision)` and only
   ESCALATE/CONTAIN_PENDING_APPROVAL activate playbooks (MONITOR never
   does), mirroring the AWS triage guide where P1/P2 routes into a full
   playbook. Spawning these is safe pre-approval — they're recommendations,
   and their output is the material a human reads before approving.

Both tiers persist `ResponseTask` rows; `dispatched_by` ("ir_agent" vs
"commander") is what separates them — the API surfaces triage-stage tasks
under `triage.response_tasks` and Commander-stage tasks under
`commander_decision.response_tasks`. For AWS-tier tasks the
`triggered_by_technique_ids` column holds the matched *finding types*
(the column name is historical).

The mock scenario includes a second, cloud-native attack chain on the
`aws-prod-account` asset (stolen instance credentials → S3 versioning
suspension + bulk deletion → attacker KMS key + ransom notes). With live
threat intel it lands CRITICAL → CONTAIN_PENDING_APPROVAL (real ransomware
groups fully cover its technique set); offline it lands HIGH → ESCALATE.
Either way it activates the AWS Ransomware and STS Token Abuse playbooks in
the demo (as recommendations awaiting human sign-off in the CRITICAL case).

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
`ThreatAnalysis`, `IncidentTriage`, and `CommanderDecision` are all
one-per-incident (`unique=True` on `incident_id`). `ThreatAnalysis.risk_rank`
is the odd one out — it's not set at creation, only after bootstrap ranks
the whole batch of incidents processed in that run.

### Frontend

`app/static/index.html` is a single self-contained file (inline CSS/JS, no
build step) served at `GET /` by `app/main.py`. It calls the JSON API
directly via `fetch()` — `/assets`, `/vulnerabilities`, `/alerts`,
`/incidents` (embeds `threat_analysis` + `triage`, including
`triage.evidence_items`, + `commander_decision` per incident),
`/attack-coverage`, `/threat-actor-profiles`, `/threat-indicators`,
`/evidence-items`, `/playbooks`, `/playbook-executions` — and a "Run
Ingestion + Refresh" button that POSTs `/bootstrap` then reloads.
Dark-theme only, no light-mode handling. `GET /threat-analyses` (highest
`risk_score` first, `?recommended_only=true` filter) is exposed but not
yet rendered anywhere in the dashboard.
