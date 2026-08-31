# VBG Defense Orchestrator

A defense orchestrator combining SIEM alert correlation, MITRE ATT&CK-mapped
detection coverage, asset-weighted vulnerability prioritization, and a
multi-agent SOAR triage/response pipeline with human-in-the-loop containment
approval. Backend is FastAPI + SQLAlchemy (SQLite or Postgres), frontend is a
single static HTML/vanilla-JS dashboard with no build step, served by FastAPI
itself.

SIEM, vulnerability scanner, asset inventory, and IOC/TIP feeds are mocked
with a deliberately coherent synthetic attack scenario. The CISA KEV catalog
and MITRE ATT&CK Enterprise dataset are ingested live from their public
sources, with graceful offline fallback.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Seed reference data, ingest sources, correlate incidents, run the agent pipeline
.venv/bin/python -m app.bootstrap

# Run the dev server
.venv/bin/uvicorn app.main:app --reload
```

Open **http://127.0.0.1:8000/** for the dashboard. The "Run Ingestion + Refresh"
button re-runs bootstrap (idempotent) and reloads.

Run the tests:

```bash
.venv/bin/python -m pytest tests/ -v
```

The SQLite DB file is `orchestrator.db` at the repo root, created on first
bootstrap. Delete it to reset all state.

## What it does

- **Ingests** alerts, vulnerabilities, and assets from pluggable connectors
  (mocked today; see [Connectors](#connectors-mock-to-real)).
- **Correlates** related alerts into incidents — per-asset clustering by time
  window, then chained across assets when a lateral-movement technique
  bridges them.
- **Analyzes risk before triaging.** A dedicated Threat Analyzer Agent
  correlates asset, vulnerability, and threat-intel data for every correlated
  incident into a deterministic weighted risk score, ranks the whole batch by
  that score, and recommends only the highest-risk cases for full triage. The
  Incident Commander's gate acts on that recommendation — incidents it
  doesn't clear get a direct MONITOR decision with no triage, evidence
  planning, or sub-agent dispatch spent on them.
- **Triages** each recommended incident through a pipeline that gathers asset
  context, open vulnerabilities (KEV-prioritized), and threat intel matches
  (IOC hits + ATT&CK TTP overlap against tracked actor profiles) — reusing
  the Threat Analyzer's already-computed risk score rather than rescoring —
  then builds the evidence and response plan around it.
- **Plans evidence collection** — every recommended artifact is traceable to
  either the ATT&CK technique observed or a confirmed IOC match.
- **Spawns response runbooks** — IRP-category sub-agents (malware,
  ransomware, phishing, credential compromise, lateral movement, data
  exfiltration) at triage time, and a second tier of AWS IRP playbook
  sub-agents (credential compromise, ransomware, data access, DoS, insider
  threat, and more) once the Commander escalates or queues containment.
- **Lets a human commander send a risk assessment back for re-analysis.** A
  disagreement with the Threat Analyzer's rating (`POST
  /incidents/{id}/reanalyze`, with a required reason and an optional rating
  floor that can only raise the rating, never lower it) is capped at one
  retry per incident and logged to a `CommanderReanalysisRequest` audit
  trail (`GET /reanalysis-requests`) — a bounded escalation, not a loop.
- **Falls back, rather than dead-ending, when containment doesn't go
  through.** A rejected containment request, or an approval that matches no
  SOAR playbook, is fed back to the Commander to fall back to `ESCALATE`
  (`GET /containment-reviews` for the audit trail) — see
  [Human-in-the-loop containment approval](#human-in-the-loop-containment-approval).
- **Lets a human commander override the response tier outright.** The
  break-glass path (`POST /incidents/{id}/override`, requiring a reason and
  a named approver) bypasses the Threat Analyzer and `decide()` entirely —
  for once the one re-analysis retry above is exhausted and a human still
  disagrees (`GET /manual-overrides` for the audit trail).
- **Gates all remediation behind human approval.** The Incident Commander
  never executes containment automatically — a critical incident files a
  containment request previewing exactly which SOAR playbooks would run;
  nothing executes until an analyst approves it via the dashboard or API.
- **Maps detection coverage** against MITRE ATT&CK and prioritizes
  vulnerabilities by an asset exposure/criticality/EPSS/KEV-weighted risk
  score (`compute_risk_score()` — internet-facing findings are weighted far
  above internal/isolated ones, since attacker access cost matters more than
  raw CVSS).

## Architecture

A full pipeline diagram — every stage from raw feed to the human-approval
gate, with every arrow labeled, including the Threat Analyzer Agent, the
Commander's pre-triage `gate()` step, and the three bounded human feedback
loops (re-analysis, the containment-outcome fallback to `ESCALATE`, and the
break-glass manual override) — is below (or as a vector PDF at
[`docs/architecture-diagram.pdf`](docs/architecture-diagram.pdf)).

![Pipeline architecture diagram](docs/architecture-diagram.png)

### Connector abstraction (mock-to-real seam)

`app/connectors/base.py` defines abstract interfaces for every external data
source: SIEM, vulnerability scanner, asset inventory, threat intel, KEV
catalog, ATT&CK catalog, and IOC enrichment. Every service in the app talks
only to these interfaces, never to a concrete product. `app/connectors/mock.py`
implements the still-mocked ones against synthetic data; `app/connectors/__init__.py`
is the single wiring point deciding which concrete connector backs each
interface. To add a real integration (Splunk, Qualys, CrowdStrike, a TIP),
implement the matching base class in a new `app/connectors/<product>.py` and
change the import — nothing else in the app changes.

Two connectors are **live** rather than mocked:

- **CISA KEV** (`cisa_kev.py`) — the public Known Exploited Vulnerabilities
  feed, cached 24h locally. Corrects `Vulnerability.kev_listed` after
  ingestion (the catalog, not the scanner, is the source of truth) and
  surfaces remediation due dates + ransomware-campaign attribution.
- **MITRE ATT&CK** (`mitre_attack.py`) — the official Enterprise STIX bundle,
  cached 7 days. Feeds ~700 techniques (sub-techniques included) and ~160
  real intrusion-set actor groups, alongside the mock TIP profiles.

Both degrade gracefully offline: serve a stale cache on fetch failure, or
fall back to the curated seed / scanner-provided flags with no cache at all.

VirusTotal has a defined seam (`IocEnrichmentConnector`) but no
implementation yet — see [Known incomplete pieces](#known-incomplete-pieces).

### Agent pipeline

Six agents in `app/agents/`, each wrapping services behind a typed contract
(`app/agents/context.py`) rather than raw ORM rows:

| Agent | Role |
|---|---|
| Inventory | Asset criticality/exposure/business-unit context |
| Vulnerability Management | Open findings on affected assets, KEV-first |
| Threat Intel | IOC matches + ATT&CK technique-overlap actor matching |
| **Threat Analyzer** | Runs first: correlates the three above into a weighted risk score per incident, ranks the whole batch by risk, and recommends the highest-risk cases for full triage |
| **Incident Response** | Hub for recommended incidents — reuses the Threat Analyzer's score/context (no rescoring), builds the evidence plan, spawns IRP response sub-agents |
| **Incident Commander** | Bookends the pipeline: `gate()` delegates to the Threat Analyzer and acts on its recommendation *before* triage runs; `decide()` sets the response tier after triage. The only place SOAR playbooks get triggered — and only after human approval |

The **Threat Analyzer Agent** is what keeps the expensive evidence-planning/
response-dispatch/LLM work from running on obvious background noise: it
computes one deterministic weighted risk score per incident (correlation
confidence, severity, asset criticality/exposure, KEV-listed vulnerabilities,
threat-intel IOC/TTP overlap), buckets it into a risk rating, and recommends
anything rated high or critical. The Commander's `gate()` just acts on that
recommendation — anything not recommended gets a direct `MONITOR`
`CommanderDecision` via `skip()`, with no `IncidentTriage` row, no evidence
plan, and no response sub-agents spawned for it. Every incident's assessment
is ranked against the rest of its batch (`risk_rank`, 1 = highest) via
`GET /threat-analyses`, so an analyst can see which cases to look at first
independent of the recommend/skip split.

Actor matching uses **incident coverage**, not Jaccard similarity — a real
intrusion set with hundreds of known techniques would otherwise never
register against a small incident. A match requires the actor to cover at
least half the incident's observed techniques, with at least two in common.

**Disagreeing with the Analyzer:** `incident_commander_agent.request_reanalysis()`
(`POST /incidents/{id}/reanalyze`) recomputes a `ThreatAnalysis` with a
required reason and an optional rating floor that can only raise the rating,
never lower it. Capped at one retry per incident (a second attempt is a
409) — the intent is a bounded escalation path a human uses when they
believe a case is under-scored, not an automated back-and-forth. Both the
prior and resulting assessment are recorded in a `CommanderReanalysisRequest`
(`GET /reanalysis-requests`) for audit.

### Response sub-agents (IRP annexes)

Two dispatch tiers, both persisting `ResponseTask` rows (recommendations —
never auto-executed):

1. **Triage-stage** (`app/agents/response/`) — six category sub-agents
   (malware, ransomware, phishing, credential compromise, lateral movement,
   data exfiltration), spawned by the IR Agent based on observed ATT&CK
   technique IDs.
2. **Commander-stage** (`app/agents/response/aws/`) — ten sub-agents
   distilled from the AWS incident response playbook set (credential
   compromise, STS token abuse, ransomware, data access, personal data
   breach, DoS, insider threat, Identity Center compromise, federated access
   abuse, satellite operations), triggered by GuardDuty finding types /
   CloudTrail event names and activated only once the Commander escalates or
   queues containment.

### Human-in-the-loop containment approval

Remediation is never automatic. A critical incident produces a
`ContainmentApproval` (status `pending`) previewing which SOAR playbooks
would run. `app/services/approval_service.py` is the only code path that can
trigger execution:

- `POST /containment-approvals/{id}/approve` — runs the matched playbooks,
  marks the incident contained, records who approved it and why.
- `POST /containment-approvals/{id}/reject` — executes nothing, records the
  rejection.

The dashboard renders inline Approve/Reject buttons on incidents awaiting a
decision. `GET /containment-approvals?status=pending` is the analyst inbox.

**Neither outcome is a dead end.** A rejection, or an approval that turns out
to match no SOAR playbook (containment wasn't actually possible), is fed back
to `incident_commander_agent.handle_containment_outcome()`, which replaces
the stale decision with the next response tier down (today, always
`ESCALATE` — terminal, since escalation files no approval of its own to
reject or fail). Both the outcome and the fallback decision are recorded in
a `CommanderContainmentReview` (`GET /containment-reviews`).

### Evidence collection & preservation

`app/agents/evidence_planner.py` produces evidence recommendations traceable
to either the ATT&CK technique observed (`TECHNIQUE_EVIDENCE_MAP`) or a
direct threat-intel IOC match — never deduped against each other, since a
confirmed IOC hit is independently justified for chain-of-custody purposes.

### Hybrid LLM reasoning (optional)

`app/agents/llm_reasoning.py` generates rationale/summary text on top of the
already-computed deterministic decisions. If `ANTHROPIC_API_KEY` is unset or
the API call fails, it falls back to a deterministic templated string — the
pipeline's decisions are never gated on LLM availability.

### Database

SQLite by default (`orchestrator.db`, zero setup). For the full stack, point
at Postgres:

```bash
docker compose up -d   # postgres:16 on localhost:5433
                        # (offset from the default 5432 in case a native
                        # Postgres install is already using it)
DATABASE_URL=postgresql+psycopg2://orchestrator:orchestrator@localhost:5433/orchestrator \
  .venv/bin/python -m app.bootstrap
```

`.mcp.json` configures a read-only Postgres MCP server
(`postgres-mcp --access-mode=restricted`) against the same database, so an
MCP-aware assistant can query the intel warehouse directly. Tests always use
in-memory SQLite regardless of `DATABASE_URL`.

### Frontend

`app/static/index.html` is a single self-contained file (inline CSS/JS, no
build step) served at `GET /`. It calls the JSON API directly via `fetch()`.
Each incident card renders its Threat Analyzer Agent assessment (score,
rating, `risk_rank`, recommended badge) with a **Request Re-Analysis**
button when not recommended, and every Commander decision carries a
**Manual Override…** button; a **Commander Feedback Log** section merges
the re-analysis, containment-review, and manual-override audit trails into
one table. `GET /threat-analyses` (highest risk first,
`?recommended_only=true` filter) is exposed but not rendered as its own
view — each incident's own `threat_analysis` is what's shown today.

`app/static/admin.html`, served at `GET /admin`, is a separate console for
an operator persona: a prioritized **Pending HITL Approvals** queue (same
approve/reject actions as the incident cards) and a filterable **System
Activity Feed** merging every Commander decision (`GET /commander-decisions`)
with the three feedback-loop audit trails and playbook executions into one
chronological table. Auto-refreshes every 15s. Linked from the incident
dashboard's header and back.

## Known incomplete pieces

- **VirusTotal enrichment** — `IocEnrichmentConnector` seam is defined and
  wired to a no-op by default; no implementation yet.
- **Re-requesting containment after a decided approval** — `manual_override()`
  to `CONTAIN_PENDING_APPROVAL` only files a new `ContainmentApproval` if the
  incident doesn't already have one; `ContainmentApproval` is one-per-incident,
  so there's no way yet to re-request containment after a prior approval was
  already approved or rejected.

## The mock scenario

`app/seed/mock_scenario.py` and `app/seed/mock_threat_intel.py` model one
coherent attack chain rather than random fixtures: a public-facing web
server gets exploited via a KEV-listed CVE, credentials are dumped, the
attacker pivots to the domain controller via SMB, then exfiltrates data — plus
a second, cloud-native chain (stolen instance credentials → S3 destruction →
attacker KMS key) modeled on the AWS ransomware playbook's own game-day
scenario. A couple of unrelated low-severity alerts are mixed in as noise.
This exercises the full pipeline: correlation, ATT&CK coverage, threat-intel
matching, and both response-dispatch tiers.

## Commands reference

```bash
# Run a single test
.venv/bin/python -m pytest tests/test_correlation_service.py::test_lateral_movement_chains_two_assets_into_one_incident -v

# Re-bootstrap (idempotent for reference data; see DEPLOYMENT.md for a note
# on alert/incident dedup across process restarts in the mock scenario)
.venv/bin/python -m app.bootstrap
```

There is no linter/formatter configured in this repo yet.

## Deploying this

See [`DEPLOYMENT.md`](DEPLOYMENT.md) for the container image, environment
variables, Postgres setup, and production considerations (auth is not
included — put this behind something that handles it).

## For contributors using Claude Code

See [`CLAUDE.md`](CLAUDE.md) for the full architectural deep-dive this README
summarizes, plus conventions for the codebase.
