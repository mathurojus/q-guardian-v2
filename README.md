# Q-Guardian v2: Post-Quantum Cryptographic Risk and Migration Platform

Q-Guardian is an enterprise platform that inventories an organisation's real
cryptographic footprint, scores each asset against quantum-era threats, maps
the risk to a migration timeline, and produces a standards-aligned
Cryptographic Bill of Materials (CBOM). It is built for regulated sectors,
banking first, where cryptography must be proven, not assumed.

The platform answers four questions:

1. What cryptography actually exists across our network, source code,
   container images, and compiled binaries?
2. Which assets will break first when a cryptographically relevant quantum
   computer (CRQC) arrives?
3. When must each migration happen, and what does a compliant path look like?
4. Does what we declare about our crypto match what is really deployed?

Unlike manifest-only inventory tools, Q-Guardian scans four independent
evidence vectors, live TLS endpoints, source code, container images, and raw
binaries, then reconciles them into one logical asset inventory. A package
manager may declare a modern OpenSSL, while a compiled binary still embeds a
legacy MD5 table. Q-Guardian surfaces that "declared vs actual" divergence
instead of trusting the SBOM at face value, and every heuristic estimate
(for example, an unpulled container image or an unmatched identity across
sources) is labeled with its detection method and confidence, so an estimate
is never presented as a measurement.

---

## Feature Overview

### Multi-source cryptographic discovery

| Source vector | Engine | What it detects |
|---|---|---|
| Network (live TLS) | `discovery.py`, `port_scanner.py`, `active_discovery.py` | Subdomains from certificate-transparency logs (crt.sh), real TLS handshake metadata (protocol, cipher suite, key size, forward secrecy, certificate validity, negotiated hybrid PQC group where the runtime exposes it), open TCP ports, and discovered API surface (OpenAPI/Swagger specs, JS-crawled routes, banking-path fuzzing). Private, loopback, and link-local targets (including cloud metadata addresses) are refused unless `ALLOW_PRIVATE_SCAN_TARGETS` is set. |
| Static source | `static_analysis.py`, `source_scanner.py`, `rules/crypto.yml` | Cryptographic API calls in source trees with file, line, and enclosing-function evidence. A real Python AST visitor plus a Semgrep ruleset derived from the OWASP community crypto rules, extended with algorithm names, key sizes, AES-ECB, and hardcoded-key patterns. Falls back to a pruned line-regex scan only if Semgrep is unavailable. |
| Container image | `container_scanner.py` | OS/package manifests via Trivy (`trivy fs` / `trivy image`, DB-free offline mode) with Syft and a tag-inference heuristic as fallbacks. Every finding is tagged with `detection_method` and `confidence`, so a Trivy/Syft result (`high` confidence, real SBOM) is never confused with a heuristic estimate (`low` confidence, inferred from the image tag string, image not pulled). Package versions are checked against a quantum-readiness table (OpenSSL/libcrypto/libssl are PQC-capable only from 3.5.0, the release that shipped native ML-KEM/ML-DSA). |
| Binary | `binary_scanner.py` | Compiled artifacts (ELF / PE / Mach-O) via LIEF plus byte-level constant matching: ML-KEM-768 NTT zeta constants (FIPS 203, using the real signed reference encoding so genuine liboqs/OpenSSL 3.5+ binaries match, not only the bundled demo fixture), AES S-box tables, MD5/SHA-1 IV constants (with cross-suppression so a SHA-1 table cannot register as a false MD5 hit), and liboqs PQC interface strings, including in stripped binaries, with evidence offsets and section labels. |

### Declared-vs-actual reconciliation

Every scan job writes findings into a unified asset schema tagged with its
source (`network_live`, `static-source`, `container`, `binary`, `cloud_kms`,
`hardware_module`). `reconciler.py` correlates assets across sources by
normalised hostname identity where one exists, and flags divergence,for
example a container that ships modern OpenSSL while the bundled binary still
executes legacy MD5 (`DIV_CONTAINER_MODERN_VS_BINARY_MD5`). Each divergence
carries a `correlation` field: `identity-matched` (the two findings were
proven to describe the same logical asset, high confidence) or
`environment-level` (the environment contains both a modern and a legacy
artifact, but a shared identity was not established, medium confidence and
capped severity). Reconciliation clears stale flags on every run, so a
remediated asset can actually drop out of the divergence count on rescan.

### Risk scoring and timelines

- **Q-TRI (Quantum Transition Resilience Index)**: a 0-100 score per asset,
  weighted by RBI sensitivity tier (S1-S5). Non-network assets (source code,
  binaries, container libraries, KMS/HSM keys) are scored on their crypto
  primitive and PQC status instead of on absent TLS/cipher fields, so a
  PQC-clean binary is not structurally penalised for lacking a TLS session.
  Legacy algorithm families (MD5, SHA-1, DES/3DES/RC4, AES-ECB) cap the score
  via a quantum-signal guard so a modern-looking wrapper cannot mask a weak
  primitive.
- **Mosca countdown engine**: implements the Mosca inequality `X + Y > Z`
  (migration complexity plus data shelf life versus time to CRQC), with
  inputs derived from the real scanned surface. An asset that is already
  post-quantum short-circuits to `SAFE` instead of being flagged by a model
  that assumes vulnerable crypto. Outputs CRITICAL / WARNING / MONITOR / SAFE
  risk states plus a CRQC arrival-probability curve, explicitly labeled as an
  illustrative planning estimate rather than a specific cited figure.
- **Enterprise cyber rating**: a roll-up 0-1000 rating with letter bands
  (A / B-C / D / F), blended with the share of assets sitting inside the
  Mosca risk window so the headline number reflects the quantum-timeline
  math, not only TLS hygiene.
- **HNDL exposure model**: Harvest-Now-Decrypt-Later exposure estimates for
  endpoints without perfect forward secrecy. Only the CRQC arrival-probability
  term is model-derived; the traffic-volume baseline is an explicitly labeled,
  configurable planning assumption, not measured telemetry or a cited
  external source.

### Cryptographic Bill of Materials (CBOM)

- Native **CycloneDX 1.6 JSON** export generated with `cyclonedx-python-lib`,
  using the ECMA-424 crypto extension (`cryptoProperties`: asset type,
  algorithm properties, OID, classical and NIST quantum security levels,
  parameter-set identifiers) per component. `primitive` and `assetType` are
  derived from the asset's own classification (a hash finding is `hash`, a
  TLS finding is `protocol`), not guessed from the algorithm name string.
- Every component is source-tagged and carries its evidence (file, line, or
  binary offset), Q-TRI score, PQC flag, and divergence flag as properties.
- The hand-rolled fallback path (used only when `cyclonedx-python-lib` is
  unavailable) emits the same schema-valid structure as the primary path,
  independently validated against the official CycloneDX 1.6 JSON schema.
- PDF export and a run-history diff (added/removed components per source
  vector) for showing improvement between audit runs.

### Compliance mapping

| Framework | Coverage |
|---|---|
| RBI baseline cyber security controls | Mapped against the actual published circular (`DBS.CO/CSITE/BC.11/33.01.001/2015-16`, Annex-1 Baseline Cyber Security and Resilience Requirements) and the Master Direction on Digital Payment Security Controls (2021), only against assets that genuinely carry the relevant primitive. |
| NIST IR 8547 | The real published transition dates: deprecate 112-bit quantum-vulnerable algorithms (RSA-2048, ECDSA P-256, ECDH, finite-field DH) after 2030, disallow after 2035. NSA CNSA 2.0's 2033 exclusive-use date is tracked separately and not conflated with IR 8547. |
| India DST National Quantum Mission / TEC | NQM 2023-2031 horizon and TEC quantum-safe cryptography guidance flags. |

### Migration playbooks

`migration.py` maps every surfaced algorithm family to a concrete,
standards-aligned PQC transition path (FIPS 203 ML-KEM, FIPS 204 ML-DSA,
FIPS 205 SLH-DSA), branched by cryptographic usage: RSA used for key
exchange targets ML-KEM-768, while RSA used for signatures or certificates
targets ML-DSA-65 (a KEM cannot produce a signature, so the two are never
conflated). TLS server-config guidance is kept in its own field, separate
from source-code remediation snippets, so a nginx directive is never spliced
onto a Python hashing line. Benchmark figures are labeled by parameter set
with an explicit "order of magnitude, platform-dependent" caveat rather than
false-precision numbers with no reproducible source.

### Analyst and reporting tools

- **Live threat intelligence feed**: RSS aggregation from quantum-computing
  and cybersecurity sources (IBM, NIST, Google, CSO), tagged with a
  relevance category (quantum-related, vulnerability disclosure, standards
  update). Ships a small set of clearly labeled sample items so the panel is
  never blank in an air-gapped deployment, and never asserts an action (such
  as recalculating a risk clock) that the platform did not actually perform.
- **Board brief PDF**: ReportLab-generated executive report with the rating,
  risk distribution, and recommendation summaries.
- **Chatbot with local RAG**: a rule-based security advisor that falls back
  to a fully offline retrieval-augmented engine (LangChain + FAISS with a
  deterministic hashing embedder) grounded on the knowledge base and the live
  asset inventory. No external LLM, no API keys, no network. Safe for
  air-gapped deployments, and the UI is explicit that this is extractive
  lexical retrieval, not generative synthesis.
- **Cloud KMS / HSM intake**: maps caller-supplied key export records (from
  AWS KMS, Azure Key Vault, GCP KMS, Vault, or an HSM audit export) into the
  unified asset schema. There is no live cloud SDK and no network call; this
  is a bring-your-own-inventory intake. Sample fixtures are only loaded when
  explicitly requested and are tagged `data_source: sample_fixture` so they
  are never mistaken for a real inventory pull.

---

## Architecture

```
q-guardian-v2/
├── run.ps1                          Launch backend + frontend (checks backend/venv, then backend/.venv)
│
├── backend/                         FastAPI application
│   ├── app/
│   │   ├── main.py                  API routes and scan orchestration
│   │   ├── auth.py                  JWT auth, SECRET_KEY startup validation
│   │   ├── database.py              SQLModel ORM (DBAsset, DBScanJob, DBCBOMHistory, DBAuditLog)
│   │   ├── settings.py              Environment config, CORS, scan limits, safety flags
│   │   ├── net_guard.py             SSRF guard and local-path confinement shared by every scanner
│   │   └── engines/
│   │       ├── discovery.py            Network discovery + TLS handshake scanning
│   │       ├── active_discovery.py     API surface mapping (specs, JS crawl, fuzzing)
│   │       ├── port_scanner.py         Async TCP port scanner
│   │       ├── api_scanner.py          OWASP API Top 10 scan (read-only by default)
│   │       ├── static_analysis.py      Real AST + regex static source scanning
│   │       ├── source_scanner.py       Semgrep crypto rule execution
│   │       ├── container_scanner.py    Trivy / Syft / labeled-heuristic container scanning
│   │       ├── binary_scanner.py       LIEF + constant-signature binary scanning
│   │       ├── sample_binary.py        Synthetic positive-control demo binary generator
│   │       ├── managed_crypto.py       Cloud KMS / HSM bring-your-own-inventory intake
│   │       ├── reconciler.py           Cross-source divergence detection
│   │       ├── mosca.py                Mosca X + Y > Z timeline engine
│   │       ├── scoring.py              Q-TRI scoring + enterprise rating
│   │       ├── hndl.py                 Harvest-Now-Decrypt-Later model
│   │       ├── cbom.py                 CycloneDX 1.6 CBOM generation + PDF export
│   │       ├── migration.py            PQC migration playbooks
│   │       ├── compliance.py           RBI / NIST IR 8547 / India DST-TEC mapping
│   │       ├── reporting.py            Board brief PDF
│   │       ├── chatbot.py              Rule-based security advisor
│   │       ├── rag_advisor.py          Offline RAG (LangChain + FAISS) grounded answers
│   │       └── threat_intel.py         Quantum/cyber RSS aggregation
│   ├── rules/crypto.yml            Semgrep crypto ruleset
│   ├── .env.example                Configuration template
│   └── requirements.txt
│
├── frontend/                        React + Vite SPA, routed with react-router-dom
│   └── src/
│       ├── App.jsx                 Route definitions
│       ├── layouts/AppShell.jsx     Sidebar + top bar shell shared by every authenticated page
│       ├── routes/                 ProtectedRoute (auth gate) and LoginRoute
│       ├── context/                 AuthContext, AppDataContext (assets, rating, scan state), ToastContext
│       ├── components/             Sidebar, TopBar, ScannerPanel, AssetTable, Dashboard,
│       │                           HNDLSimulator, DependencyGraph, ComplianceMapper,
│       │                           CBOMViewer, ApiScanner, Chatbot, PlaybookModal
│       ├── pages/                  One page per sidebar destination (see Platform Walkthrough)
│       └── index.css               Tailwind design system
│
└── demo/                           Offline demo seeding and legacy runbook
    ├── seed_demo.py                Deterministic canonical-state seeder (real engines)
    ├── DEMO.md                     Original scripted demo walkthrough (tab-based UI, superseded by WALKTHROUGH.md)
    └── fallback/                   Recorded artifacts of the canonical demo state
```

See `WALKTHROUGH.md` for a live-demo script and `USERFLOW.md` for a page-by-page
tour of the current sidebar UI.

---

## Technology Stack

**Backend**

| Component | Technology |
|---|---|
| API framework | FastAPI, Uvicorn |
| ORM / database | SQLModel (SQLAlchemy + Pydantic), SQLite by default, PostgreSQL via `DATABASE_URL` |
| Auth | python-jose (JWT), passlib/bcrypt |
| Scanners | Semgrep (bundled ruleset), Trivy (portable, DB-free mode), Syft, LIEF |
| Standards | cyclonedx-python-lib (CycloneDX 1.6 / ECMA-424 crypto), ReportLab |
| RAG (optional) | langchain-core, FAISS (`faiss-cpu`), degrades gracefully when absent |

**Frontend**

| Component | Technology |
|---|---|
| Framework | React 18, Vite 5, react-router-dom 6 |
| Styling | TailwindCSS 3 with a navy/cobalt enterprise design system |
| Visualisation | Recharts, react-force-graph-2d, d3 |
| UX | Framer Motion, Lucide icons |

---

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- Git

External scanners: Semgrep is installed via `requirements.txt`. Trivy runs in
DB-free SBOM mode; without it installed, the container scanner falls back to
a clearly-labeled tag-inference estimate rather than failing. Network scans
require outbound internet (crt.sh, live TLS); everything else runs locally.

### 1. Install

```bash
git clone <repo-url>
cd q-guardian-v2

# Backend
cd backend
python -m venv venv
# Windows: .\venv\Scripts\activate     macOS/Linux: source venv/bin/activate
pip install -r requirements.txt

# Frontend
cd ../frontend
npm install
```

### 2. Configure the backend

```bash
cd backend
cp .env.example .env
```

Set a strong `SECRET_KEY` (32+ random characters) and replace
`ADMIN_PASSWORD_HASH` with a real bcrypt hash of your admin password:

```bash
python -c "import bcrypt; print(bcrypt.hashpw(b'YourPasswordHere', bcrypt.gensalt()).decode())"
```

On startup the API validates this configuration and refuses to boot with a
missing or placeholder secret.

### 3. Run

From the repository root:

```powershell
.\run.ps1
```

Or manually:

```bash
# Terminal 1, backend (http://localhost:8000)
cd backend && uvicorn app.main:app --reload --port 8000

# Terminal 2, frontend (http://localhost:5173)
cd frontend && npm run dev
```

- Frontend UI: http://localhost:5173
- API: http://localhost:8000
- OpenAPI docs (dev only): http://localhost:8000/docs

The demo credentials shipped in `.env.example` are placeholders meant to be
replaced; set your own `ADMIN_USERNAME` / `ADMIN_PASSWORD_HASH` before any
real use.

### 4. Seed the canonical demo state (optional)

`demo/seed_demo.py` drives the real Semgrep, Trivy, container, and LIEF
engines against bundled fixtures to produce a deterministic inventory. Stop
the backend first, then run it and restart:

```bash
cd backend
./venv/Scripts/python.exe ../demo/seed_demo.py --wipe
```

---

## Platform Walkthrough

The UI is a sidebar console with real routes, one page per destination.

| Sidebar section | Page | Purpose |
|---|---|---|
| Overview | `/` | Enterprise cyber rating, risk-state chart, metric cards, threat-intelligence feed. Empty state links directly into Scan Center. |
| Scan Center | `/scan` | Hub linking to each scanner, plus a reconciliation shortcut. |
| Scan Center | `/scan/source` | Source-code scan: AST or Semgrep against a local file or directory. |
| Scan Center | `/scan/container` | Container image or Dockerfile scan (Trivy/Syft, or a labeled estimate). |
| Scan Center | `/scan/binary` | Compiled binary scan (LIEF plus byte-signature matching). |
| Scan Center | `/scan/api` | OWASP API Top 10 scan of a live endpoint URL. |
| Scan Center | `/scan/network` | Domain scan: subdomain discovery plus live TLS inspection, with progress visible from any page. |
| Inventory | `/inventory` | Unified asset table across every source vector, with evidence, Q-TRI, source badges, and the divergence filter. |
| Risk & Compliance | `/risk/hndl` | Harvest-Now-Decrypt-Later exposure view with its grounding advisory. |
| Risk & Compliance | `/risk/compliance` | Cross-framework compliance viewer (RBI, NIST IR 8547, India DST/TEC). |
| Topology | `/topology` | Force-directed graph of assets and primitives, coloured by discovery vector, with a divergence hub. |
| Reports | `/reports/cbom` | CycloneDX 1.6 JSON / PDF export, run-history diff. |
| Reports | `/reconcile` | Cross-source divergence detection. |

A floating assistant answers questions about findings, frameworks, and
migration guidance from the offline knowledge base and your live inventory.
See `USERFLOW.md` for a narrated walk through each page as a first-time
analyst would encounter it.

---

## API Reference

All routes except `/api/v1/auth/login` require `Authorization: Bearer <token>`.

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/auth/login` | Authenticate and receive a JWT |
| POST | `/api/v1/scan/trigger` | Full network scan (discovery, ports, TLS, analytics) for a domain |
| GET | `/api/v1/scan/{job_id}/status` | Poll scan progress |
| POST | `/api/v1/scan/api` | OWASP API Top 10 scan of an endpoint URL |
| POST | `/api/v1/scan/source` | AST static scan of a local file/directory |
| POST | `/api/v1/scan/semgrep` | Semgrep crypto-ruleset scan of a local path |
| POST | `/api/v1/scan/container` | Container/image scan (image tag, tarball, or path) |
| POST | `/api/v1/scan/binary` | Binary scan of an ELF/PE/Mach-O file (`SAMPLE` generates a demo binary) |
| POST | `/api/v1/intake/kms` | Ingest caller-supplied Cloud KMS export records |
| POST | `/api/v1/intake/hsm` | Ingest caller-supplied HSM fleet export records |
| GET | `/api/v1/intake/samples` | Retrieve the labeled sample KMS/HSM fixtures |
| POST | `/api/v1/cbom/reconcile` | Cross-source divergence detection |
| GET | `/api/v1/assets` | Unified asset inventory |
| GET | `/api/v1/enterprise/rating` | Roll-up cyber rating |
| GET | `/api/v1/migration/{asset_id}/playbook` | PQC migration playbook for an asset |
| GET | `/api/v1/migration/{asset_id}/codegen` | Downloadable crypto-agility strategy stub |
| GET | `/api/v1/cbom/export/cyclonedx` | Native CycloneDX 1.6 CBOM JSON |
| GET | `/api/v1/cbom/export/pdf` | CBOM PDF export |
| GET | `/api/v1/cbom/history` | Recent CBOM scan snapshots |
| GET | `/api/v1/cbom/diff` | Before/after diff of the two latest snapshots |
| GET | `/api/v1/cbom/divergence` | Assets flagged with declared-vs-actual drift |
| GET | `/api/v1/compliance/rbi` | RBI baseline control mapping |
| GET | `/api/v1/compliance/frameworks` | RBI + NIST IR 8547 + India DST/TEC mapping |
| GET | `/api/v1/reports/board-brief` | Executive board-brief PDF |
| GET | `/api/v1/threat-intel` | Aggregated quantum/cyber intelligence feed |
| POST | `/api/v1/chat` | Advisor chat (rule-based + offline RAG) |

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | `production` hardens defaults (docs off) |
| `SECRET_KEY` | (required) | JWT signing secret, startup fails if missing or weak |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD_HASH` | (required) | Admin credentials (bcrypt) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | Token lifetime |
| `DATABASE_URL` | `sqlite:///./qguardian.db` | SQLModel connection string (PostgreSQL supported) |
| `FRONTEND_ORIGINS` | localhost:5173/8000 | CORS allow-list |
| `FRONTEND_ORIGIN_REGEX` | (empty) | Optional CORS origin regex (for preview deployments) |
| `DISCOVERY_MAX_ASSETS` | unlimited | Cap on discovered subdomains per scan |
| `SCAN_ROOT` | (unset) | Confines local-path scans (source/semgrep/container/binary) to this directory; a sensitive-path denylist applies even when unset |
| `ALLOW_PRIVATE_SCAN_TARGETS` | `false` | Permit scanning private/internal/loopback ranges |
| `ALLOW_MUTATING_API_PROBES` | `false` | Enable the API scanner's state-changing DELETE/POST probes (off by default) |
| `ENABLE_API_DOCS` | `true` (dev) | Expose `/docs` |

---

## Standards Alignment

- **CycloneDX 1.6 (ECMA-424)**: CBOM serialisation with per-component crypto
  properties, independently validated against the official JSON schema.
- **NIST FIPS 203 / 204 / 205**: ML-KEM, ML-DSA, SLH-DSA reference targets in
  scoring and migration playbooks, branched by cryptographic usage rather
  than treating every RSA finding as a KEM candidate.
- **NIST IR 8547**: the published transition dates (deprecate quantum-vulnerable
  112-bit algorithms after 2030, disallow after 2035), not an invented
  milestone schedule.
- **NIST SP 800-38D / FIPS 180-4 / FIPS 202**: algorithm guidance referenced
  by rule recommendations.
- **RBI baseline cyber security controls**: mapped against the real
  published circular and the Digital Payment Security Controls direction.
- **India DST National Quantum Mission / TEC**: national quantum-safe
  horizon flags.

---

## Security and Ethical Use

- All scanning endpoints are JWT-protected. Login is the only public route.
- The API refuses to start with a missing or placeholder `SECRET_KEY`, and
  OpenAPI docs are disabled in production by default.
- Local-path scans (source/semgrep/container/binary) are confined to
  `SCAN_ROOT` when configured, and a sensitive-path denylist applies even
  when it is not, closing the path-traversal exposure that an unconfined
  scanner would otherwise have.
- Network and API scanners refuse private, loopback, and link-local targets
  (including cloud metadata addresses) unless `ALLOW_PRIVATE_SCAN_TARGETS` is
  explicitly set. The API scanner's destructive probes (mass-assignment POST,
  method-switching DELETE) stay off unless `ALLOW_MUTATING_API_PROBES` is set.
  Use every active scanner only against domains and services you own or are
  explicitly authorised to test.
- Threat-intel and certificate-transparency lookups require outbound network
  access; the local scan paths work fully offline.

## Known Limitations

- HNDL figures are model-based ceilings derived from an illustrative,
  configurable traffic baseline, not telemetry-verified measurements. Only
  the CRQC arrival-probability term is model-derived.
- Binary constant detection is signature-based: custom or obfuscated
  implementations that hide known constants may be missed.
- Container scanning without Trivy/Syft installed falls back to a
  tag-inference estimate; it is labeled `confidence: low` but is not a
  substitute for a real image inspection.
- The default SQLite store suits single-node or demo use; switch
  `DATABASE_URL` to PostgreSQL for multi-analyst deployments.
- There is no automated test suite or CI pipeline yet, and
  `backend/requirements.txt` is currently unpinned. Treat both as open work
  before relying on this as a production system rather than a reference
  implementation.
