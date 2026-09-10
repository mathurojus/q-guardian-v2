# Q-Guardian v2, Project Explanation

## 1. What this project is

Q-Guardian is a full-stack Post-Quantum Cryptographic Risk and Migration
Platform built for regulated banking. Its job is to answer four questions
for an organisation:

1. What cryptography actually exists across our network, source code,
   containers, and compiled binaries?
2. Which assets will break first when a Cryptographically Relevant Quantum
   Computer (CRQC) arrives?
3. When must each asset migrate, and what does a compliant migration path
   look like?
4. Does what we declare about our crypto (manifests, configs) match what
   is actually deployed (compiled binaries, container layers)?

It is not a generic vulnerability scanner, it is purpose-built around the
quantum-computing threat: RSA/ECC/DH break under Shor's algorithm, AES
weakens under Grover's algorithm, and adversaries are already recording
today's encrypted traffic to decrypt once a CRQC exists ("Harvest Now,
Decrypt Later" / HNDL).

The system is a two-tier app: a FastAPI/Python backend with a collection of
independent scanning and scoring "engines", and a React/Vite SPA frontend
that drives scans and visualises results. Everything runs locally, no
external AI, no cloud dependency for the offline scan paths, which matters
for a bank that cannot leak internal data to third parties.

### A note on this document's history

This platform went through a full hardening pass after an initial build.
That first build looked complete but had a real problem: several of its
flagship features were fabricating or mislabeling data rather than
measuring it, for example the binary scanner's post-quantum detection used
the wrong byte encoding and could only ever match its own synthetic test
file, the container scanner invented package versions from an image tag
string when it could not actually inspect an image, and a compliance page
cited NIST milestone dates that do not exist in the real document. The
sections below describe the platform as it stands after that pass: what is
genuinely measured, what is a clearly labeled estimate, and what remains a
known limitation. Where a claim in this document could not be made honestly,
it was removed or reworded rather than kept for appearances.

## 2. High-level architecture

```
Frontend (React 18 + Vite + react-router-dom, :5173)  <-- axios/HTTP -->  Backend (FastAPI, :8000)  -->  SQLite/Postgres (SQLModel ORM)
```

- `run.ps1` launches both dev servers at once. It checks for a virtualenv
  at `backend/venv` first, then `backend/.venv`, so it works regardless of
  which convention was used to create it.
- All backend routes except `/api/v1/auth/login` require a JWT
  (`Authorization: Bearer <token>`); `auth.py` refuses to boot the server if
  `SECRET_KEY` is missing or a placeholder.
- Long-running scans are dispatched as FastAPI `BackgroundTasks`; the
  frontend polls `GET /api/v1/scan/{job_id}/status` for live progress, and
  a persistent indicator in the top bar keeps that progress visible even
  while you navigate to a different page.
- Each discovered asset is committed to the DB individually during a scan
  (not just at the end), so partial results survive a mid-scan failure and
  the DB never holds a half-written row.
- Local-path scan endpoints (source, semgrep, container, binary) resolve
  and confine every target path through `net_guard.py` before touching the
  filesystem, and active network/API scanners refuse private, loopback, and
  link-local targets (including cloud metadata addresses) through the same
  module, unless explicitly overridden for authorised internal testing.

## 3. The core idea: four independent discovery vectors

Most "crypto inventory" tools just read a manifest (package.json,
requirements.txt) and trust it. Q-Guardian instead scans four independent
evidence sources and then reconciles them, so a lie in one source can be
caught by another:

| Vector | Engine(s) | What it finds |
|---|---|---|
| Network (live TLS) | `discovery.py`, `port_scanner.py`, `active_discovery.py`, `api_scanner.py` | Subdomains via Certificate Transparency logs (crt.sh), real TLS handshakes (protocol/cipher/key size/forward secrecy/cert validity/negotiated hybrid PQC group where the runtime exposes it), open TCP ports, discovered API routes (Swagger/JS-crawl/banking-path fuzzing), and OWASP API Top 10 findings |
| Static source code | `static_analysis.py`, `source_scanner.py`, `rules/crypto.yml` | Crypto API calls with file, line, and enclosing-function evidence, via a real Python AST visitor and a real Semgrep ruleset (OWASP-derived crypto rules); falls back to a pruned line-regex scan only if Semgrep is genuinely unavailable |
| Container images | `container_scanner.py` | OS/package manifests via Trivy (offline DB-free mode) / Syft / a tag-inference heuristic, cross-checked against a PQC-readiness version table. Every finding carries `detection_method` and `confidence` so a real SBOM result and a heuristic estimate are never presented the same way |
| Compiled binaries | `binary_scanner.py` | ELF/PE/Mach-O parsing via LIEF plus byte-level constant matching in the raw file, ML-KEM-768 NTT zeta constants (FIPS 203, real signed reference encoding), AES S-boxes, MD5/SHA-1 IV constants, liboqs strings, works even on stripped binaries |

There is also a fifth intake path: `managed_crypto.py`, which maps
caller-supplied inventories from cloud KMS (AWS/Azure/GCP/Vault) and HSM
fleets (Thales Luna, Utimaco, AWS CloudHSM, YubiHSM) into the unified
schema. This is a bring-your-own-inventory intake: there is no cloud SDK
and no live connection to any provider. Sample fixtures exist for demos but
are only loaded when explicitly requested and are tagged
`data_source: sample_fixture`, so a fixture can never be mistaken for a
real key inventory.

Every finding, regardless of source, is normalised into one unified asset
schema, tagged with its source (`network_live`, `static-source`,
`container`, `binary`, `cloud_kms`/`hardware_module`), so the rest of the
pipeline (scoring, CBOM export, reconciliation) does not care where an
asset came from.

### Declared-vs-actual reconciliation

`reconciler.py` correlates assets across the four vectors and raises a
divergence flag when sources disagree, the canonical example is
`DIV_CONTAINER_MODERN_VS_BINARY_MD5`: a container manifest claims a modern
OpenSSL, but the compiled binary inside it still executes legacy MD5. Each
divergence is labeled with a `correlation` field: `identity-matched` means
the two findings were actually tied to the same normalised hostname
identity (high confidence), `environment-level` means the environment
contains both a modern and a legacy artifact without a proven shared
identity (medium confidence, capped severity). Stale flags are cleared at
the start of every reconciliation run, so a remediated and rescanned asset
can genuinely drop out of the divergence count instead of being stuck
flagged forever.

## 4. Risk scoring and timelines

- **Q-TRI (Quantum Transition Resilience Index)**, a 0-100 score per asset
  (`scoring.py`), weighted by the asset's RBI sensitivity tier (S1
  payment-critical down to S5 public). Non-network assets (source code,
  binaries, container libraries, KMS/HSM keys) are scored on their crypto
  primitive and PQC status rather than on TLS/cipher fields that do not
  apply to them, and legacy algorithms (MD5/SHA-1/DES/3DES/RC4/AES-ECB) cap
  the score outright so a modern TLS wrapper cannot hide a weak primitive
  underneath.
- **Mosca countdown engine** (`mosca.py`), implements Dr. Michele Mosca's
  inequality X + Y > Z: if (migration time + data shelf life) exceeds
  (time until CRQC arrives), the asset is already in the risk window. An
  asset that is already post-quantum short-circuits to SAFE rather than
  being run through a model that assumes vulnerable crypto. Outputs
  CRITICAL / WARNING / MONITOR / SAFE and a "days remaining" countdown.
- **HNDL exposure model** (`hndl.py`), for assets lacking Perfect Forward
  Secrecy, estimates GB of historical traffic already harvestable and at
  risk. Only the CRQC arrival-probability weighting is model-derived; the
  per-tier traffic-volume baseline is an explicitly labeled, configurable
  planning assumption, not measured traffic or a cited external figure.
  Both the API response and the UI now say this plainly.
- **Enterprise cyber rating**, average Q-TRI across all assets, scaled to
  a 0-1000 board-level number with letter bands (A/B-C/D/F), discounted by
  the share of assets sitting inside the Mosca risk window so the headline
  number reflects the quantum-timeline math rather than TLS hygiene alone.

## 5. Outputs: CBOM, compliance, migration, reporting

- **CBOM (Cryptographic Bill of Materials)**, `cbom.py` generates a native
  CycloneDX 1.6 JSON export (via `cyclonedx-python-lib`) using the
  ECMA-424 crypto extension: every component carries algorithm, OID,
  classical/NIST-quantum security levels, parameter-set identifiers,
  source tag, evidence location, Q-TRI score, and divergence flag.
  `primitive` and `assetType` are derived from the asset's own
  classification (a hash finding is genuinely tagged `hash`, a TLS finding
  is tagged `protocol`) instead of being guessed from the algorithm name
  string, and the hand-rolled fallback path used when the CycloneDX
  library is unavailable produces the same schema-valid shape, verified
  independently against the official schema. Also supports PDF export and
  run-history diffing (added/removed components between the two latest
  scans).
- **Compliance mapping** (`compliance.py`), maps findings to the real RBI
  baseline cyber security circular (`DBS.CO/CSITE/BC.11/33.01.001/2015-16`)
  and the Digital Payment Security Controls direction, the actual NIST IR
  8547 transition dates (deprecate 112-bit quantum-vulnerable algorithms
  after 2030, disallow after 2035, rather than an invented milestone
  schedule), and India DST National Quantum Mission / TEC guidance.
- **Migration playbooks** (`migration.py`), for each vulnerable algorithm
  family generates a concrete hybrid-PQC target, branched by cryptographic
  usage: RSA used for key exchange maps to ML-KEM-768, RSA used for
  signatures or certificates maps to ML-DSA-65, a KEM cannot produce a
  signature so the two are never conflated. TLS server-config guidance is
  kept separate from source-code remediation snippets so a nginx directive
  is never spliced onto a Python hashing line, and benchmark figures are
  labeled by parameter set with an explicit platform-dependent caveat.
  There is also a code-gen endpoint that renders a Jinja2 migration-strategy
  stub for download.
- **Board brief** (`reporting.py`), a ReportLab-generated executive PDF:
  rating, risk distribution, top-5 riskiest assets, regulatory references.
- **Chatbot** (`chatbot.py` + `rag_advisor.py`), a rule-based
  intent-classification advisor (regex to topic to canned/dynamic answer)
  that falls back to a fully offline RAG engine (LangChain + FAISS with a
  deterministic hashing embedder, no external LLM/API key) grounded on a
  local knowledge base plus the live asset inventory. This is genuinely
  extractive lexical retrieval, and is presented as such rather than as
  generative synthesis.
- **Threat intel** (`threat_intel.py`), aggregates RSS from
  IBM/NIST/Google/CSO quantum-computing and security news, tagged with a
  relevance category (not an asserted action the platform did not
  actually perform), with a small set of clearly labeled sample entries so
  the panel is never blank in an air-gapped deployment.

## 6. Backend structure

```
backend/
├── app/
│   ├── main.py         API routes, JWT auth wiring, background-task scan orchestration
│   ├── auth.py          JWT issuing/validation, startup SECRET_KEY hardening
│   ├── database.py      SQLModel schema + engine/session setup + auto-migration
│   ├── settings.py      Env config (CORS, scan limits, DB URL, safety flags, prod hardening)
│   ├── net_guard.py     SSRF guard and local-path confinement shared by every scanner
│   └── engines/          One module per capability (see tables above), plus:
│       ├── sample_binary.py     synthetic positive-control binary generator (for the "SAMPLE" binary scan option)
│       ├── sample_target.py     deliberately-vulnerable fixture file (MD5/SHA-1/1024-bit RSA/SSLv23) used to prove scanners catch weak crypto
│       └── verify_phase3.py     standalone smoke-test script exercising container/binary/semgrep scanners end-to-end + CBOM export
├── rules/crypto.yml     Semgrep crypto ruleset
├── validate_cbom_schema.py   Offline CycloneDX 1.6 schema validation check
└── requirements.txt
```

### Database schema (`database.py`, SQLModel/SQLAlchemy)

- **DBScanJob**, one row per scan run: `job_uuid`, `domain`, `status`
  (PENDING/SCANNING/COMPLETED/FAILED), `progress` (0-100), `current_step`,
  timestamps.
- **DBAsset**, one row per discovered cryptographic asset: TLS/algorithm
  fields (`tls_version`, `algorithm`, `key_size`, `cipher_suite`,
  `forward_secrecy`, `cert_valid/expiry`), classification (`sensitivity_tier`,
  `is_pqc`, `policy_compliant`, `qtri_score`), multi-source evidence
  (`source_type`, `asset_type`, `evidence_file/line/offset/function`),
  CycloneDX crypto properties (`primitive`, `mode`,
  `parameter_set_identifier`, `classical_security_level`,
  `nist_quantum_security_level`, `oid`), reconciliation fields
  (`divergence_flag`, `maturity_level`), and JSON blobs for
  `mosca_data`/`hndl_data`/`open_ports_data`/`discovered_endpoints_data`.
- **DBAuditLog**, `timestamp`, `username`, `action`, `target`, `details`,
  now written on login and on every scan trigger.
- **DBCBOMHistory**, a CBOM snapshot per scan job (`total_assets`,
  `pqc_assets`, `critical_risks`, `cbom_json_data`) used for before/after
  diffing.
- `create_db_and_tables()` also auto-ALTERs in missing columns on startup,
  so upgrading the schema across versions does not require a manual
  migration.

### API surface (all JWT-protected except login/health)

Auth: `POST /api/v1/auth/login`.
Scanning: `POST /api/v1/scan/trigger` (full network scan),
`POST /api/v1/scan/api` (OWASP API Top 10, read-only by default),
`POST /api/v1/scan/source` (AST), `POST /api/v1/scan/semgrep`,
`POST /api/v1/scan/container`, `POST /api/v1/scan/binary`,
`GET /api/v1/scan/{job_id}/status`.
Intake: `GET /api/v1/intake/samples`, `POST /api/v1/intake/kms`,
`POST /api/v1/intake/hsm` (fixtures only load on explicit request, never
as a silent fallback for an empty request body).
Inventory/risk: `GET /api/v1/assets`, `GET /api/v1/enterprise/rating`,
`GET /api/v1/migration/{asset_id}/playbook`,
`GET /api/v1/migration/{asset_id}/codegen`.
CBOM: `POST /api/v1/cbom/reconcile`, `GET /api/v1/cbom/export/cyclonedx`,
`GET /api/v1/cbom/export/pdf`, `GET /api/v1/cbom/history`,
`GET /api/v1/cbom/diff`, `GET /api/v1/cbom/divergence`.
Compliance/reporting: `GET /api/v1/compliance/rbi`,
`GET /api/v1/compliance/frameworks`, `GET /api/v1/reports/board-brief`.
Advisor/intel: `POST /api/v1/chat`, `GET /api/v1/threat-intel`.

## 7. Frontend structure

React 18 + Vite 5 SPA, routed with `react-router-dom`, TailwindCSS 3 design
system, Recharts for charts, `react-force-graph-2d`/d3 for the topology
graph, Framer Motion for animation.

The app is a real multi-page console rather than a single view with tabs
that swap content in place. Every sidebar destination is its own route, so
refreshing the page, using browser back/forward, and sharing a link all
work as expected:

```
frontend/src/
├── App.jsx                 Route definitions only
├── layouts/AppShell.jsx     Sidebar + top bar shell, shared by every authenticated page
├── routes/
│   ├── ProtectedRoute.jsx  Auth gate; also mounts AppDataProvider once per session
│   └── LoginRoute.jsx      Redirects to "/" if already authenticated
├── context/
│   ├── AuthContext.jsx     Token/user state, login/logout
│   ├── AppDataContext.jsx  Shared assets/rating, background scan progress, playbook modal state
│   └── ToastContext.jsx    Toast notifications
├── components/
│   ├── Sidebar.jsx, TopBar.jsx           Persistent shell chrome
│   ├── ScannerPanel.jsx                  Shared scan form + results panel, locked to one or a few modes per page
│   ├── Dashboard.jsx, AssetTable.jsx, HNDLSimulator.jsx, DependencyGraph.jsx,
│   │   ComplianceMapper.jsx, CBOMViewer.jsx, ApiScanner.jsx
│   └── Chatbot.jsx, PlaybookModal.jsx, Toast.jsx, ErrorBoundary.jsx, LoginPage.jsx
└── pages/
    ├── OverviewPage.jsx
    ├── scan/ScanCenterPage.jsx, SourceScanPage.jsx, ContainerScanPage.jsx,
    │        BinaryScanPage.jsx, ApiScanPage.jsx, NetworkScanPage.jsx
    ├── InventoryPage.jsx
    ├── risk/HndlPage.jsx, CompliancePage.jsx
    ├── TopologyPage.jsx
    ├── reports/CbomPage.jsx
    └── ReconcilePage.jsx
```

`AppDataContext` is mounted once per authenticated session (inside
`ProtectedRoute`), so the asset inventory, enterprise rating, and an
in-progress network scan's status all stay in sync no matter which page is
currently open, a background scan started from the Network page keeps
reporting progress in the top bar even after you navigate away from it.

## 8. Demo/offline path

`demo/seed_demo.py` drives the real engines (Semgrep, Trivy, container,
LIEF) against bundled fixtures to deterministically produce a canonical
demo state without needing network access. `demo/DEMO.md` is the original
scripted walkthrough written for the old tab-based UI; `WALKTHROUGH.md` and
`USERFLOW.md` at the repository root describe the current sidebar UI and
supersede it for anything UI-related. `demo/fallback/` holds pre-recorded
artifacts in case a live demo scan fails.

## 9. Security posture and known limitations

- JWT-protected everywhere except login; startup refuses to boot with a
  weak/missing `SECRET_KEY`; API docs disabled in production.
- Local-path scan endpoints (source/semgrep/container/binary) resolve and
  confine every target through `net_guard.py`, either strictly under
  `SCAN_ROOT` when configured, or against a sensitive-path denylist when it
  is not.
- Network and API scanners refuse private, loopback, and link-local targets
  (including cloud metadata addresses) unless `ALLOW_PRIVATE_SCAN_TARGETS`
  is explicitly set, and the API scanner's destructive probes stay off
  unless `ALLOW_MUTATING_API_PROBES` is set. They are still real active
  probes, intended only for domains and services you own or are authorised
  to test.
- HNDL numbers are explicitly labeled model ceilings, not
  telemetry-verified measurements.
- Binary detection is signature-based, obfuscated or custom crypto
  implementations that avoid known constants can be missed.
- Container scanning without Trivy or Syft installed falls back to a
  tag-inference estimate, labeled `confidence: low`, not a substitute for a
  real image inspection.
- SQLite is the default store (fine for single-node/demo use); switch
  `DATABASE_URL` to Postgres for multi-analyst deployments.
- There is no automated test suite or CI pipeline yet, and
  `backend/requirements.txt` is currently unpinned. Both are open work.
- The codebase evolved from an earlier PNB-specific single-vector-scan tool
  (documented in `docsx.txt`, an older internal write-up) into the current
  four-vector reconciliation platform, then went through the hardening pass
  described at the top of this document. `docsx.txt` and `demo/DEMO.md`
  describe earlier states of the project and should be read as history, not
  as current documentation.
