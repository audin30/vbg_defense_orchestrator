# Deployment

This covers running the orchestrator outside a local dev checkout: container
image, environment configuration, database options, and the operational
details that differ between a laptop demo and something reachable by other
people.

For architecture and how the app is put together, see
[`CLAUDE.md`](CLAUDE.md). For a general project overview, see
[`README.md`](README.md).

## Contents

- [Runtime requirements](#runtime-requirements)
- [Configuration (environment variables)](#configuration-environment-variables)
- [Local dev (no containers)](#local-dev-no-containers)
- [Container image](#container-image)
- [Database](#database)
- [Running the full stack with Docker Compose](#running-the-full-stack-with-docker-compose)
- [Bootstrap and data lifecycle](#bootstrap-and-data-lifecycle)
- [Health checks](#health-checks)
- [Persistent volumes](#persistent-volumes)
- [Networking and reverse proxy](#networking-and-reverse-proxy)
- [Secrets](#secrets)
- [Logging and observability](#logging-and-observability)
- [Scaling notes](#scaling-notes)
- [Upgrading](#upgrading)
- [Troubleshooting](#troubleshooting)

## Runtime requirements

- Python 3.12 (the container image pins `python:3.12-slim`; anything 3.11+
  should work locally)
- SQLite (bundled) or PostgreSQL 14+ — see [Database](#database)
- Outbound HTTPS access to `www.cisa.gov` and `raw.githubusercontent.com`
  for live threat-intel ingestion (optional — see below)
- No message queue, cache, or search service. No build step for the
  frontend — `app/static/index.html` is served as-is.

## Configuration (environment variables)

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DATABASE_URL` | No | `sqlite:///./orchestrator.db` | SQLAlchemy connection string. Set to a `postgresql+psycopg2://` URL for Postgres. |
| `ANTHROPIC_API_KEY` | No | unset | Enables LLM-generated triage/commander rationale text (`app/agents/llm_reasoning.py`). Every decision the pipeline makes is deterministic and unaffected by this key's presence — only the explanatory prose changes. Unset or an API failure falls back to a templated string automatically. |

No other environment variables are read by the app today. `VIRUSTOTAL_API_KEY`
is referenced in code comments as the variable a future VirusTotal connector
will read, but nothing consumes it yet (`IocEnrichmentConnector` is wired to
a no-op — see `README.md`).

## Local dev (no containers)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m app.bootstrap
.venv/bin/uvicorn app.main:app --reload
```

Dashboard at `http://127.0.0.1:8000/`. This is the fastest path for
iterating on the app itself; skip straight to it unless you specifically
need to test the containerized build or Postgres.

## Container image

A `Dockerfile` at the repo root builds a single-stage image:

```bash
docker build -t vbg-orchestrator .
docker run -p 8000:8000 vbg-orchestrator
```

That alone runs against an ephemeral in-container SQLite file — fine for a
quick check, gone on the next `docker run`. For anything persistent, pair it
with a real database (below) and a mounted volume (see
[Persistent volumes](#persistent-volumes)).

The image does **not** run `app.bootstrap` on startup — bootstrap is a
separate, explicit step (see [Bootstrap and data lifecycle](#bootstrap-and-data-lifecycle)).
`CMD` only starts `uvicorn`.

### Build details worth knowing

- Base image is `python:3.12-slim`. `psycopg2-binary` ships its own `libpq`,
  so no `libpq-dev`/`build-essential` layer is needed.
- `.dockerignore` excludes `tests/`, `playbooks/` (the large AWS IRP
  reference checkout, gitignored anyway), `.git/`, and local caches — the
  build context stays small.
- `/srv/app/data` is declared as a `VOLUME` — that's where the CISA KEV and
  MITRE ATT&CK HTTP caches live (`app/connectors/_http_cache.py`). Losing it
  just means the next ingestion re-fetches from source; it's a performance
  cache, not state.
- A `HEALTHCHECK` polls `GET /health` every 30s.

## Database

**SQLite** (default) needs no setup and is fine for a single-instance demo
or low-traffic internal tool. The file lives wherever the process's working
directory is — inside a container, that's ephemeral unless you mount a
volume over it.

**PostgreSQL** is the better choice once more than one person or process
touches the same data, or you want the `orchestrator-postgres` MCP server
to work. Point `DATABASE_URL` at it:

```
postgresql+psycopg2://<user>:<password>@<host>:<port>/<database>
```

The engine choice is purely a connection-string concern —
`app/db.py::DATABASE_URL` is read once at import time; nothing else in the
app branches on which database is in use. There is no migration tool
(Alembic or similar) in this repo: schema is created via
`Base.metadata.create_all()` on first bootstrap. If you change ORM models in
`app/models/orm.py` after a database already has data, you're responsible
for schema evolution yourself (add columns manually, or drop and
re-bootstrap in a non-production environment).

## Running the full stack with Docker Compose

`docker-compose.yml` currently defines only the `postgres` service — it's
meant to be run alongside the app, not to replace it. Bring Postgres up
first:

```bash
docker compose up -d --wait
```

This starts `postgres:16` on **host port 5433** (not 5432 — offset in case
this machine already runs a native Postgres install; see the comment in
`docker-compose.yml`). Credentials are `orchestrator`/`orchestrator`,
database `orchestrator` — fine for local/dev; change them for anything
shared (see [Secrets](#secrets)).

Then run the app against it, either directly:

```bash
DATABASE_URL=postgresql+psycopg2://orchestrator:orchestrator@localhost:5433/orchestrator \
  .venv/bin/python -m app.bootstrap
DATABASE_URL=postgresql+psycopg2://orchestrator:orchestrator@localhost:5433/orchestrator \
  .venv/bin/uvicorn app.main:app --reload
```

or containerized, on the same Docker network Compose created
(`<project>_default` — check the exact name with `docker network ls` after
`up`):

```bash
docker build -t vbg-orchestrator .
docker run -d --name vbg-orchestrator \
  --network vbg_defense_orchestrator_default \
  -e DATABASE_URL="postgresql+psycopg2://orchestrator:orchestrator@orchestrator-postgres:5432/orchestrator" \
  -p 8000:8000 \
  vbg-orchestrator
docker exec vbg-orchestrator python -m app.bootstrap
```

Note the container-to-container URL uses the **service's internal port
5432** and hostname `orchestrator-postgres` (the container name), not the
host-mapped `localhost:5433` — that mapping only matters from outside
Docker's network.

If you want a single `docker compose up` to bring up both services, add an
`app` service to `docker-compose.yml` yourself, e.g.:

```yaml
  app:
    build: .
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql+psycopg2://orchestrator:orchestrator@postgres:5432/orchestrator
    ports:
      - "8000:8000"
```

This isn't checked in by default so that running just `docker compose up`
doesn't surprise anyone who only wanted the database (e.g. for MCP access
against SQLite-free local dev).

## Bootstrap and data lifecycle

`python -m app.bootstrap` (or `POST /bootstrap`) does five things: create
tables if missing, seed ATT&CK/detection-rule/playbook reference data,
ingest all connectors (mock + live KEV/MITRE), correlate alerts into
incidents, and run the two-tier response pipeline. It's meant to be
re-run — most of it is idempotent by natural key (hostnames, CVE+asset,
indicator value, ATT&CK technique ID).

**One known exception:** the mock SIEM data
(`app/seed/mock_scenario.py::MOCK_ALERTS`) computes alert timestamps
relative to `datetime.now()` at **process import time**, not a fixed point.
Re-running bootstrap within the same long-lived process is idempotent;
re-running it from a **new process** (a fresh `python -m app.bootstrap`, a
container restart) produces alerts with slightly different timestamps, which
don't match the existing rows' natural key — so you get duplicate mock
alerts and incidents piling up. This only affects the synthetic demo data;
KEV entries, ATT&CK techniques, actor profiles, and detection rules/playbooks
stay correctly deduplicated across any number of runs.

In practice: bootstrap once per environment lifetime (or after clearing the
database), not on every container restart. If you need a guaranteed-clean
state, reset the database first:

```bash
# SQLite
rm -f orchestrator.db

# Postgres
docker compose down -v && docker compose up -d --wait
```

## Health checks

`GET /health` returns `{"status": "ok"}` unconditionally once the process is
up — it does not check database connectivity. Use it for liveness (is the
process alive), not readiness against a specific dependency. If you need a
DB-aware readiness probe, add one; it doesn't exist today.

## Persistent volumes

Two things need to survive a restart if you want them to:

1. **Database state** — trivial for Postgres (`docker-compose.yml` already
   declares the `orchestrator_pgdata` volume); for SQLite, mount a host path
   or named volume over wherever `orchestrator.db` resolves inside the
   container (its working directory, `/srv/app`).
2. **Intel caches** (`/srv/app/data` in the container) — not required for
   correctness (see [Container image](#container-image) above), but
   preserving it avoids a ~40MB re-download of the MITRE ATT&CK STIX bundle
   on every container recreate.

## Networking and reverse proxy

The app listens on `0.0.0.0:8000` inside the container with no TLS, auth, or
CORS configuration of its own — it expects to sit behind something that
handles those (nginx, Caddy, a cloud load balancer, Cloudflare Tunnel,
etc.). There is currently **no authentication on any endpoint**, including
the containment-approval actions that execute SOAR playbooks
(`POST /containment-approvals/{id}/approve`). Before exposing this beyond a
trusted local network, put an auth layer in front of it — this app does not
provide one.

## Secrets

- `ANTHROPIC_API_KEY` — pass as a runtime environment variable
  (`docker run -e`, your orchestrator's secret store, etc.), never bake it
  into the image.
- Postgres credentials in `docker-compose.yml` (`orchestrator`/`orchestrator`)
  are placeholder values meant for local development. Change
  `POSTGRES_PASSWORD` and the corresponding `DATABASE_URL` before running
  this anywhere other people or processes can reach it.
- `.mcp.json` embeds the same local Postgres connection string for the MCP
  server — it's development tooling (lets an MCP-aware assistant query the
  database directly) and is not part of the deployed application; don't
  ship it inside the container image (`.dockerignore` doesn't need to
  exclude it explicitly since it isn't copied by the `Dockerfile` in the
  first place — only `app/` is).

## Logging and observability

Plain stdout/stderr from `uvicorn` — no structured logging, metrics
endpoint, or tracing wired up. Container orchestrators that expect
`stdout` (Docker, Kubernetes, most PaaS platforms) work without extra
configuration; anything expecting a specific log format or a `/metrics`
endpoint will need that added.

## Scaling notes

The app is stateless request-to-request — all state lives in the database —
so multiple `uvicorn` replicas behind a load balancer work as long as they
share one database. Two things to know before doing that:

- **Bootstrap is not safe to run concurrently** from multiple replicas
  against a fresh database — table creation and seeding aren't guarded
  against a race. Run it once (a single job/init container/manual step),
  then start replicas against the already-seeded database.
- **SQLite does not support concurrent writers** well — if you're running
  more than one instance, use Postgres.

## Upgrading

There's no versioned release process yet — deploy from a specific commit.
After pulling a new commit:

1. Rebuild the image (`docker build`) if `requirements.txt` or `app/`
   changed.
2. If `app/models/orm.py` changed, see the migration caveat in
   [Database](#database) — there's no automatic schema migration.
3. Re-run bootstrap only if new reference data (detection rules, playbooks,
   ATT&CK seed) needs seeding; it's safe to skip for a pure code change.

## Troubleshooting

**`bind: address already in use` on Postgres startup** — something else on
the host already listens on the port `docker-compose.yml` maps to (this repo
already hit this with a native Postgres install on 5432, which is why the
default is remapped to 5433). Change the host-side port in
`docker-compose.yml` and any `DATABASE_URL`/`.mcp.json` references to match.

**KEV/ATT&CK counts are 0 after bootstrap** — the live connectors
(`app/connectors/cisa_kev.py`, `app/connectors/mitre_attack.py`) need
outbound HTTPS to `www.cisa.gov` and `raw.githubusercontent.com`. With no
network and no warm cache in `data/`, they return empty and the app falls
back to the curated seed / scanner-provided flags automatically — this is
expected degraded behavior, not a crash. Check egress rules if you expected
live data.

**`risk_score` is `0.0` everywhere** — expected. See
`app/services/vuln_prioritization.py::compute_risk_score()`; it's an
intentionally unimplemented placeholder, not a deployment issue.

**Duplicate incidents after a restart** — see the idempotency caveat in
[Bootstrap and data lifecycle](#bootstrap-and-data-lifecycle).
