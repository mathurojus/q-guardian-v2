# Q-Guardian v2, Live Demo Walkthrough

This is a scripted path through the sidebar UI built to show off what
changed in the recent hardening pass: real scanning (not fabricated data),
honest labeling where a number is a model or an estimate, and correct
crypto risk math. Follow it top to bottom for a live demo, each step says
what to click and what you should see. Sidebar order is followed exactly,
top to bottom, so the demo also doubles as a tour of the navigation.

**Before you start:** backend running on `http://localhost:8000`, frontend
on `http://localhost:5173`. Log in with the admin credentials from
`backend/.env` (`ADMIN_USERNAME` / the password you set).

---

## 1. Overview (`/`)

Sidebar: **Overview**

- With an empty inventory this shows a "Platform ready" empty state with a
  **Go to Scan Center** button, not a blank chart. Click it, or continue
  reading and use the sidebar.
- Once assets exist (after Step 2 below), come back here and note the
  **Enterprise Rating** (0-1000) and its letter grade. This number now
  factors in Mosca risk state, not just TLS hygiene, point this out:
  "the headline score reflects the quantum-timeline math, not just cipher
  strength."

## 2. Scan Center (`/scan`)

Sidebar: **Scan Center**

- This hub lists five scanner cards (Source Code, Container Image,
  Compiled Binary, API Endpoint, Network/Domain) plus a **Reconcile
  Sources** card. Point out that each card is a real, separate page with
  its own URL, not a sub-tab hidden inside one screen.

### a) Source Code (`/scan/source`)

- Target path: `backend/app/engines/sample_target.py`
- Click **Scan**
- **Expect:** 4 findings, MD5 (line 7), SHA-1 (line 11), RSA-1024 (line 15),
  TLS-1.0/1.1 (line 19). Open one finding and check the evidence, file+line
  is exact, and this is now genuinely coming from Semgrep, not a silently
  swallowed error falling back to a weaker regex engine. That specific bug
  (a Windows encoding crash that used to degrade the engine with no
  warning) is fixed, so what you are looking at now is the real Semgrep
  CLI result. You can also switch the internal AST/Semgrep toggle at the
  top of the panel to see the native AST engine reach the same result on
  its own.

### b) Container Image (`/scan/container`)

- Target: `nginx:1.24-alpine` (or any image tag)
- Click **Scan**
- **Expect:** OpenSSL/ca-certificates findings. Open a finding, if a
  small amber **ESTIMATE** badge appears on a finding card, that means
  Trivy/Syft are not installed on this machine and the result is a
  tag-inference estimate, not an inspected image, and the UI says so
  explicitly instead of pretending otherwise. That disclosure is new,
  previously this fabricated a "high-fidelity" inventory with no way to
  tell it apart from a real SBOM scan.
- Talking point: the PQC-readiness table is now correct, OpenSSL only
  shows `is_pqc: true` from version 3.5.0 and above (native ML-KEM/ML-DSA),
  not 3.2 like before, because 3.2 through 3.4 have no native PQC support
  at all.

### c) Compiled Binary (`/scan/binary`), the flagship result

- Click **DEMO FIXTURE** (generates a synthetic positive-control binary),
  then **Scan**
- **Expect:** `ML-KEM-768` detected, `is_pqc: true`, QTRI around 98, at a
  byte offset with a `PQC` badge on the finding.
- Talking point (this is the headline fix): the NTT-constant signature
  used to be encoded wrong, it stored unsigned residues where a real
  compiled Kyber/ML-KEM binary stores signed int16 values, so the detector
  would never fire on anything except its own synthetic sample. It now
  uses the real, signed FIPS-203 encoding, so it would also match a
  genuine liboqs/OpenSSL 3.5+ Kyber binary. Also point out AES is no
  longer mislabeled `is_pqc: true` (AES is classical, not post-quantum).

### d) API Endpoint (`/scan/api`)

- Enter a URL you are authorised to test and scan it.
- Talking point: destructive checks (mass-assignment POST, method-switching
  DELETE) are off by default and require an explicit opt-in on the backend,
  the scanner only runs read-only probes unless that flag is set.

### e) Network / Domain (`/scan/network`)

- Enter a domain you own or are authorised to test (or `example.com`,
  which exists for exactly this purpose).
- Click **Trigger network scan**, then immediately click over to another
  page in the sidebar, for example **Overview**.
- **Expect:** a small pill in the top bar keeps showing scan progress from
  any page, click it to jump straight back to the Network Scan page. Once
  the scan completes it links you directly to **Inventory**.

### f) Reconcile Sources (`/reconcile`)

- Click **Run Reconciliation**.
- **Expect:** if a divergence appears, it now carries a **correlation**
  tag: `identity-matched` (same logical asset across two sources, high
  confidence) or `environment-level` (the environment contains both a
  modern and a legacy artifact, but they were not proven to be the same
  service, medium confidence, and severity is capped accordingly).
- Talking point: previously every co-presence of "any modern container
  lib" plus "any legacy binary" was reported as a specific, confident
  "declared vs actual" narrative about a single asset, even when the two
  came from completely unrelated scans. Now the engine only makes an
  identity claim when it can actually justify one.

## 3. Inventory (`/inventory`)

Sidebar: **Inventory**

- Show the combined asset table across all scans.
- Point out evidence columns are now honest: static/binary findings show
  `tls_version: N/A`, `cipher_suite: N/A` instead of fabricated TLS/cert
  fields that made no sense for a hash constant or a source-code line.
- Filter or sort by QTRI score, a PQC binary asset should now score high
  (90+), not be dragged down to around 28 by a TLS penalty that did not
  apply to it (that structural bug, non-network assets being scored on
  absent TLS fields, is fixed).

## 4. Risk & Compliance

### HNDL Exposure (`/risk/hndl`)

- Talking point: the headline number is labeled **EST. EXPOSURE (TIER
  BASELINE)**, not "TOTAL DATA AT RISK". Only the CRQC arrival-probability
  term is model-derived; the traffic-volume baseline is a configurable
  assumption, not measured or externally published data, and the
  grounding advisory at the bottom says this plainly.

### Cert-IN Mapper (`/risk/compliance`)

- Open the NIST IR 8547 section.
- Talking point: the milestone dates are now the real published dates,
  "deprecate after 2030, disallow after 2035", instead of an invented
  "T1 through T4, 2027 through 2033" schedule that does not exist in the
  actual document. RBI citations now point to the real circular
  (`DBS.CO/CSITE/BC.11/33.01.001/2015-16`) instead of a fabricated
  "CSF 2.0" reference.

## 5. Topology (`/topology`)

- Show the force-directed graph; point out the divergence hub edge if one
  exists after Step 2f.

## 6. Reports

### CBOM Export (`/reports/cbom`)

- Click **Export CycloneDX** (or view the JSON in-app).
- Talking point: open the MD5 finding's
  `cryptoProperties.algorithmProperties.primitive`, it now correctly says
  `hash`, not `key-agree`. Same for a TLS finding: `assetType` is now
  `protocol`, not `algorithm`. This is schema-valid and semantically
  correct now (previously it validated against the schema but mislabeled
  almost everything).
- If you have `jsonschema` installed, you can run
  `backend/validate_cbom_schema.py` in a terminal to show it validating
  live against the official CycloneDX 1.6 schema.

## 7. Migration playbook (from Inventory)

- Click into any RSA finding's migration playbook.
- Talking point: RSA guidance is now split by usage, key exchange goes to
  ML-KEM-768, but signatures and certificates correctly go to ML-DSA-65 (a
  signature scheme), instead of the old, cryptographically wrong advice to
  replace a signature key with a KEM. Config snippets are also no longer
  mashed together (no more nginx directives glued onto a Python hashing
  line).

---

## If something looks empty

- **Rating shows 0, Inventory is empty:** you have not run a scan yet, do
  Step 2 first.
- **Container scan shows an ESTIMATE badge:** expected if Trivy/Syft are
  not installed locally, this is the honest-disclosure behavior working as
  designed, not a failure.
- **KMS/HSM intake returns a 400 on an empty submit:** expected, it no
  longer silently substitutes fake fixture data. Explicitly pass
  `use_sample_fixtures: true` to see the (clearly labeled) sample fleet.

## One-line pitch if asked "what changed?"

> "Every number in this tool now either comes from a real, evidence-backed
> scan, or is clearly labeled as an estimate, nothing is silently faked or
> mislabeled as measured. Where the code was fabricating data (container
> versions, KMS keys) or getting the crypto wrong (RSA to KEM, AES marked
> post-quantum, invented compliance dates), we fixed the substance, not
> just the copy. And the UI is now a real multi-page console with its own
> URLs, not one screen with tabs swapping content in place."
