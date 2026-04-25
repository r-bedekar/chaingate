# ChainGate — Seed and Collector Architecture

_Snapshot: 2026-04-13. Describes the upstream pipeline that produces
seed bundles consumed by the chaingate runtime. The collector and
seed production code live on private infrastructure (chaingate-ops);
this document is preserved here for reader context. See
[SECURITY.md](../SECURITY.md) for the current trust model._

_Covers the data-collection foundation (Phases P1–P4)._

---

## 1. System Purpose

ChainGate is a supply-chain witness + gate layer for npm and PyPI. It sits
between the developer and the upstream registries, observes every
metadata/version change, cross-references independent security sources,
and (eventually) blocks installs when package-level invariants diverge
from what's been historically observed.

The project is deliberately staged in two halves:

1. **Witness store** (P1–P4, now landed) — a passive, append-only record
   of every version of every seed package, with hashes, dependencies,
   publishers, attestations, and advisories attached.
2. **Proxy + gates** (P5, next) — an HTTP shim in front of `registry.npmjs.org`
   that reads the witness store on install and fires BLOCK/WARN gates
   when the incoming artifact contradicts history.

The order matters: gates only mean something if they have a trustworthy
baseline to compare against. P1–P4 is that baseline.

---

## 2. High-Level Design

### 2.1 Components

```
                 ┌───────────────────┐
                 │  npm registry     │         ┌────────────────┐
                 │  pypi.org JSON    │◄────────│  collector     │
                 │  pypi /integrity/ │         │  (systemd      │
                 │  osv.dev          │         │   timer x2)    │
                 └───────────────────┘         └──────┬─────────┘
                                                      │
                                                      ▼
┌────────────┐     ┌──────────────────────────────────────────┐
│  seeds/    │────▶│         PostgreSQL witness store         │
│  *.txt     │     │  packages · versions · version_files     │
└────────────┘     │  version_events · attack_labels          │
                   │  collector_runs                          │
                   └──────────────────────────────────────────┘
                                      │
                                      │ (P5 — not built yet)
                                      ▼
                               ┌─────────────┐
                               │ npm proxy + │
                               │ gate runner │
                               └─────────────┘
```

### 2.2 Data-flow summary

- Every 15 minutes, the collector walks both seed lists (≈100 npm, ≈100
  PyPI packages), fetches registry metadata, and normalizes it into
  `versions` + `version_files` rows.
- A single `sources/*.py` module per registry handles the fetch and
  parse; `collector.py` is a generic dispatcher that knows nothing about
  ecosystem specifics beyond calling `source.fetch_package()`,
  `source.parse_versions()`, and (optionally) `source.enrich_version()`.
- Each versioned artifact gets children: one `version_files` row per
  wheel/sdist/tarball, keyed `UNIQUE (version_id, filename)`.
- Out-of-band enrichment workers (the `backfill_*.py` scripts) walk the
  same tables by id-cursor and fill late-arriving columns (install-script
  detection, PEP 740 attestations, OSV advisories) without retouching
  any row that's already populated.
- Every mutation respects the **append-only invariant** (see §4.2): new
  facts are INSERTed, existing facts are never overwritten. The only
  UPDATEs allowed are fill-NULL (via COALESCE) and monotonic lifecycle
  transitions (`last_seen_at`, `deprecated_at`, `yanked_at`, `vanished_at`).

### 2.3 External dependencies

| Source                       | Purpose                                       | Auth  | Rate policy          |
|------------------------------|-----------------------------------------------|-------|----------------------|
| `registry.npmjs.org`         | npm package docs (packument)                  | none  | 20 rps, 8 concurrent |
| `pypi.org/pypi/*/json`       | PyPI per-package + per-version metadata       | none  | 20 rps, 8 concurrent |
| `pypi.org/integrity/.../provenance` | PEP 740 sigstore attestation bundles  | none  | 10 rps, 10 concurrent |
| PyPI sdist tarball URLs      | AST-walk of `setup.py` for dangerous imports  | none  | 5 concurrent, 150 MB cap |
| `api.osv.dev/v1/querybatch`  | Cheap bulk vuln lookup (sparse result)        | none  | single batch / run   |
| `api.osv.dev/v1/vulns/{id}`  | Full advisory record (cached by id)           | none  | 10 rps, 10 concurrent |

All are retry-wrapped (`tenacity`, 3 attempts, exponential 1→16 s) and
distinguish 5xx (retryable) from 4xx (terminal). The collector never
falls back to fake data on failure — it logs the error, increments the
run's error counter, and moves on.

### 2.4 Runtime topology

| Process                                   | Cadence            | Scope                                |
|-------------------------------------------|--------------------|--------------------------------------|
| `chaingate-collector-npm.timer`           | `*:00,15,30,45`    | npm seed walk                        |
| `chaingate-collector-pypi.timer`          | `*:07,22,37,52`    | pypi seed walk (7-min stagger)       |
| `collector.backfill_*` one-shot scripts   | manual / tmux      | historical backfill over existing rows |

The 7-minute stagger is intentional — npm and pypi share the same
Postgres instance and the same `collector_runs` table, so serializing
their writes makes failure attribution obvious (you never have to
disambiguate which collector owned a failing row).

---

## 3. Low-Level Design

### 3.1 Database schema (relevant tables)

```
packages
    id            SERIAL PK
    ecosystem     VARCHAR(16)   -- 'npm' | 'pypi'
    package_name  TEXT
    UNIQUE (ecosystem, package_name)

versions
    id                            SERIAL PK
    package_id                    FK packages(id)
    version                       TEXT
    published_at                  TIMESTAMPTZ
    content_hash, content_hash_algo           -- sha256 (wheels/tarballs)
    integrity_hash                            -- npm SRI "sha512-..."
    git_head                                  -- npm gitHead when present
    dependency_count + dependencies JSONB
    dev/peer/optional/bundled_dependencies JSONB + *_count
    publisher_name, publisher_email
    publisher_tool                            -- npm _npmVersion
    publisher_maintainer, publisher_maintainer_email
    maintainers JSONB                         -- full maintainers[] array
    publish_method                            -- 'oidc' | 'token' | 'unknown'
    provenance_present BOOL, provenance_details JSONB
    has_install_scripts                       -- pypi AST walk result
    package_size_bytes
    source_repo_url
    license_text, license_expression
    raw_metadata JSONB                        -- full upstream record
    -- lifecycle (write-once, monotonic)
    first_observed_at DEFAULT NOW()
    last_seen_at
    deprecated_at, deprecated_reason
    yanked_at, yanked_reason
    vanished_at
    UNIQUE (package_id, version)

version_files                                 -- per-artifact child of versions
    id              SERIAL PK
    version_id      FK versions(id) CASCADE
    filename        TEXT
    packagetype     VARCHAR(32)               -- wheel | sdist | tarball
    python_version  VARCHAR(32)
    content_hash, content_hash_algo           -- per-file sha256
    size_bytes, uploaded_at, url
    yanked BOOL, yanked_reason
    -- PEP 740 tri-state
    attestation_present   BOOL NULL           -- NULL=unchecked
    attestation_publisher JSONB               -- {kind,repository,workflow,env}
    attestation_bundles   JSONB               -- raw sigstore bundles
    attestation_fetched_at TIMESTAMPTZ
    raw_metadata JSONB
    first_observed_at DEFAULT NOW()
    last_seen_at, vanished_at
    UNIQUE (version_id, filename)

version_events                                -- append-only lifecycle log
    id, version_id, event_type, run_id, detail, occurred_at
    -- event_type ∈ {deprecated, yanked, vanished}

attack_labels                                 -- advisory / malware hits
    id, package_id, version_id                -- version_id NULL = package-level
    is_malicious BOOL
    attack_name                               -- 'malware' | 'advisory'
    source                                    -- 'osv'
    advisory_id                               -- e.g. GHSA-… / MAL-…
    aliases JSONB                             -- CVE aliases
    severity VARCHAR(16)                      -- CRITICAL | HIGH | MODERATE | LOW
    summary TEXT
    affected_range TEXT                       -- collapsed semver e.g. ">=1.0.0 <1.13.5"
    url, raw_advisory JSONB
    modified_at, first_seen_at, labeled_at
    UNIQUE (advisory_id, package_id)          -- partial, WHERE advisory_id IS NOT NULL

collector_runs
    id, source, started_at, finished_at, status
    packages_attempted, versions_inserted, errors, notes
```

### 3.2 Module layout

```
collector/
    __init__.py
    collector.py                 # generic orchestrator (source-agnostic)
    db.py                        # psycopg2 helpers, ONLY UPDATE paths live here
    sources/
        npm.py                   # npm registry fetch + parse
        pypi.py                  # pypi /pypi/*/json fetch + parse
        pypi_tarball.py          # streams sdist, AST-walks setup.py
        pypi_attestations.py     # /integrity/*/provenance fetch
        osv.py                   # /v1/querybatch + /v1/vulns/{id}
    backfill_pypi.py             # enrichment pass for publisher/deps
    backfill_pypi_p21.py         # P2.1: license/maintainer history fill
    backfill_pypi_tarballs.py    # install-script history fill
    backfill_version_files.py    # P2.2: reconstruct files[] from raw_metadata
    backfill_attestations.py     # P2.2: PEP 740 history fill (tri-state)
    backfill_advisories.py       # P3:   OSV advisory ingest
    seeds/
        npm_top.txt              # 100 npm packages (attack-relevant + foundational)
        pypi_top.txt             # 100 pypi packages (same criteria)
    deploy/
        systemd/
            chaingate-collector-npm.{service,timer}
            chaingate-collector-pypi.{service,timer}
            README.md
```

### 3.3 Source module contract

Every source module exposes a small, duck-typed interface that
`collector.py` calls generically:

```python
# required
def fetch_package(client, name) -> dict | None
def parse_versions(package_name, raw) -> list[VersionDict]

# optional per-version enrichment (pypi only today)
async def enrich_version(client, name, version_str) -> dict | None

# optional install-script / binary inspection (pypi only today)
async def inspect_tarball(client, file_url) -> dict | None

# lifecycle
def detect_vanished(existing, observed) -> list[str]   # pure, lives in db.py
```

`VersionDict` is a plain dict. Keys that map to `versions` columns are
copied verbatim; everything else lands in `raw_metadata` JSONB.

### 3.4 The append-only invariant and the two escape hatches

The `versions` and `version_files` tables are **append-only** by design.
Gates only work if what we wrote yesterday is still what we read today.
There are exactly two sanctioned ways to change an existing row:

1. **Fill-NULL enrichment** — `db.update_version_fill_nulls` and
   `db.update_file_fill_nulls`. Both use `SET col = COALESCE(col, %s)`
   so a non-NULL value can never be overwritten. A second enrichment
   pass with different data is a no-op on any already-populated column.
   The fillable-column set is explicit in `_FILLABLE_COLUMNS` / 
   `_FILE_FILLABLE_COLUMNS` — adding a new enrichable field is a
   deliberate code change, not an accident.

2. **Write-once lifecycle transitions** — `bulk_mark_seen`,
   `mark_vanished`, `apply_lifecycle`, `apply_file_yank`. These bump
   monotonic timestamps (`last_seen_at`, `deprecated_at`, `yanked_at`,
   `vanished_at`). Each first transition additionally appends a
   `version_events` row so the history is preserved even if the
   package later reappears.

Everything else (mutating a hash, a dependency list, a publisher email)
is forbidden at the DB layer. If a mutation like that ever needs to
happen, it must first become a new row — never an in-place edit.

### 3.5 Resumable id-cursor backfill pattern

Every `backfill_*.py` script uses the same shape:

```python
while True:
    batch = fetch_batch(cursor_id, BATCH_SIZE)
    if not batch:
        break
    for row in batch:
        process(row)
    cursor_id = batch[-1][0]
```

The `WHERE` clause is:

```sql
WHERE <target_col> IS NULL
  AND id > %s
ORDER BY id
LIMIT %s
```

Because enrichment is COALESCE-protected, a process crash leaves the
row it was working on still NULL, so the next run resumes transparently.
No external state file, no lock table, no cursor snapshot — Postgres
is the cursor.

### 3.6 PEP 740 attestation tri-state

`version_files.attestation_present` is deliberately `NULL`-able:

- `NULL`  — not yet checked
- `FALSE` — checked, file has no Trusted Publishing attestation
- `TRUE`  — checked, attestation present; publisher + bundles populated

The backfill's `WHERE attestation_present IS NULL` clause self-cursors
against this: once a file is checked, it drops out of future batches
regardless of outcome. `attestation_fetched_at` is the second idempotency
guard. Pre-existing NOT NULL DEFAULT FALSE had to be removed before
the backfill could run; see the P2.2 progress log entry.

### 3.7 Two-stage OSV fetch

The OSV source exists because GHSA, PyPA, RustSec, and the Malicious
Packages project are all federated behind one API. Fetch is two stages
so we don't pay the per-advisory cost for packages that have no hits:

1. `POST /v1/querybatch` with one query per seed package
   (209 queries / single POST — well under the 1000 limit). The response
   is sparse: `{vulns: [{id, modified}, ...]}` per package. Most
   packages return zero vulns.
2. `GET /v1/vulns/{id}` per *unique* advisory id. Multi-package
   advisories (typosquat + original) are cached so they're fetched once.

Malware heuristic (`is_malicious`) triggers on any of:

- `id` starts with `MAL-` (OSV Malicious Packages ecosystem), OR
- `summary` contains `malware`, `malicious code`, `typosquat`, or
  `embedded malicious` (case-insensitive), OR
- `database_specific.cwe_ids` contains `CWE-506` (Embedded Malicious
  Code).

Ranges are flattened by `_format_ranges` into npm-style semver:
`>=1.0.0 <1.13.5 || <0.18.1`. We do not try to resolve ranges to
concrete `version_id`s at ingest — `attack_labels.version_id` stays
NULL and consumers interpret `affected_range` against their own
version of interest.

### 3.8 Rate-limiting and concurrency

All HTTP fan-out uses the same two-primitive pattern:

```python
semaphore = asyncio.Semaphore(CONCURRENCY)   # cap in-flight requests
limiter   = AsyncLimiter(RPS, 1)             # cap requests per second

async with semaphore:
    async with limiter:
        await client.get(url)
```

`CONCURRENCY` and `RPS` are tuned per source (npm: 8/20, pypi: 8/20,
attestations: 10/10, OSV vulns: 10/10). No source has ever tripped a
429 — registries are indulgent, but the collector is polite anyway.

### 3.9 Observability

Every run opens a `collector_runs` row with `status='running'` at start
and closes it with `success|partial|failed` + counts + notes at end.
The systemd unit binds the service so a process crash leaves the row in
`running` — a separate sweeper (or a `started_at < now - interval '1h'
AND status='running'` query) can flag orphans.

Structured JSON logs go to stdout (captured by systemd-journald):

```json
{"ts":"...","level":"INFO","msg":{"event":"progress","visited":22500,"has_attestation":706,"no_attestation":21794,"errors":0}}
```

The `event` key is always present. Grep-friendly.

---

## 4. What's in the store today (2026-04-13)

| Table            | Rows     | Notes                                           |
|------------------|----------|-------------------------------------------------|
| `packages`       | 209      | 104 npm + 105 pypi seeds                        |
| `versions`       | 69,964   | 50,423 npm + 19,541 pypi                        |
| `version_files`  | 181,240  | 50,423 npm (1 file/ver) + 130,817 pypi (~6.7/ver) |
| `version_events` | 3,430    | deprecated/yanked/vanished transitions          |
| `attack_labels`  | 922      | 206 npm (11 malware) + 716 pypi (0 malware)     |
| `collector_runs` | 81       | mix of hourly/15m + backfills                   |

### 4.1 Column coverage (primary signals)

npm (50,423 rows):
- `integrity_hash` 99.99%
- `maintainers` 99%
- `publisher_tool` 92%
- `git_head` 70%
- `dev_dependencies` 66%
- `peer_dependencies` 37%

PyPI (19,541 rows):
- `has_install_scripts` 100%  (AST walk of every sdist)
- `license_text OR license_expression` 91%
- `publisher_email` 59%  (data-source limit — many authors omit email)
- `publisher_maintainer` 6%  (same)

All residual NULLs are data-source limits (upstream didn't publish the
field), not collection gaps.

### 4.2 Known-attack validation

The OSV backfill correctly labels every canonical supply-chain incident
in the seed set:

| Package              | Advisory               | Type              | Range               |
|----------------------|------------------------|-------------------|---------------------|
| axios                | GHSA-3p68-rc4w-qgx5    | NO_PROXY SSRF     | `<1.15.0` CRITICAL  |
| axios                | MAL-2026-2307          | Malware           | —                   |
| ua-parser-js         | GHSA-pjwm-rvh2-c87w    | Embedded malware  | `>=0.7.29 <0.7.30`  |
| event-stream         | GHSA-mh6f-8j2x-4483    | Embedded malware  | CRITICAL            |
| node-ipc             | GHSA-97m3-w2cp-4xx6    | Protestware       | CRITICAL            |
| rc                   | GHSA-g2q5-5433-rhrf    | Takeover malware  | CRITICAL            |
| coa                  | GHSA-73qr-pfmq-6rp8    | Takeover malware  | CRITICAL            |
| debug                | GHSA-4x49-vf9v-38px    | Account-TO malware| HIGH                |
| chalk                | MAL-2025-46969         | Malware           | —                   |
| eslint-config-prettier | GHSA-f29h-pxvx-f335 | Publisher compromise | HIGH           |

Axios also carries 10 non-malicious advisories (SSRF, ReDoS, DoS) with
correct range slicing — this is the data that drives future gates.

---

## 5. Phase status

| Phase | Scope                                                | Status | Landed     |
|-------|------------------------------------------------------|--------|------------|
| P1    | Yank / deprecation / vanish detection                | done   | 2026-04-13 |
| P2.1  | versions-table extensions (16 columns)               | done   | 2026-04-13 |
| P2.2  | version_files + PEP 740 attestations                 | done   | 2026-04-13 |
| P3    | Advisories / attack_labels (OSV federated)           | done   | 2026-04-13 |
| P4    | Collector cadence 1h → 15m                           | done   | 2026-04-13 |
| P5    | Week 2-3: npm proxy + gates                          | pending | —         |

---

## 6. Phase 5 preview (not built)

The witness store is now rich enough to drive gates. Planned scope:

```
npm install
     │
     ▼
.npmrc registry=http://localhost:PORT
     │
     ▼
proxy/server.js  ──▶  gates/index.js  ──▶  reads versions + version_files
     │                     │                              │
     ▼                     ▼                              ▼
forward to upstream  ┌──────────────────┐        writes gate_decisions row
                     │ content-hash     │
                     │ dep-structure    │
                     │ publisher-id     │
                     │ provenance-cont  │
                     │ release-age      │
                     │ scope-boundary   │
                     └──────────────────┘
```

Each gate is a pure function of the incoming packument + the witness
store's prior observations. Gate decisions are logged to a new
`gate_decisions` table (not yet created) and the proxy rewrites the
response body only when the disposition is BLOCK.

The validation target is the real Axios 1.14.0 → 1.14.1 delta (the
2025 incident): 4 gates should fire (content-hash, dep-structure,
publisher-identity, provenance-continuity).

---

## 7. Operational notes

- **Secrets**: `DATABASE_URL` is in `.env` (git-ignored). No registry
  auth tokens needed — everything uses public endpoints.
- **Postgres**: single local instance, no replication. The collector
  assumes it's the only writer. If that changes, the fill-NULL path
  would need SERIALIZABLE isolation or a row-lock — today it doesn't.
- **Tmux for backfills**: long-running history passes (attestations,
  tarballs, pypi P2.1) always run inside tmux so an SSH disconnect
  doesn't kill them. See `tracker/tasks.md` Progress Log for run
  elapsed times.
- **systemd-journald** holds collector logs. `journalctl -u
  chaingate-collector-npm.service -f` tails them live.
- **Idempotency**: every collector run and every backfill script is
  safe to re-run. ON CONFLICT DO NOTHING on inserts; COALESCE on
  fill-NULL; write-once on lifecycle. No run cleanup is ever required.
