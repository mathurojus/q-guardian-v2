# Q-Guardian — End-to-End Scan Record (Real Targets)

Date: 2026-09-04
Run via the live API (`http://localhost:8000/api/v1`), authenticated as the
platform admin, using the platform's own scan endpoints end to end
(scan -> persist -> reconcile -> CBOM -> rating). No fixtures were fabricated
for this pass.

## Targets (both authorized for testing)

1. Real public repo (owned): this repository's own backend source tree
   `C:/Users/Ojus/Desktop/sih/backend/app` (the q-guardian-v2 clone).
2. Real public container image: `alpine:3.20`, pulled live from the Docker Hub
   registry by the bundled portable Trivy (0.74.0). No local Docker daemon was
   used; Trivy fetched the image directly from the registry.

## What ran, in order

| Step | Endpoint | Result |
|---|---|---|
| 1 | `POST /api/v1/scan/semgrep` (rules/crypto.yml over backend/app) | 6 findings, CycloneDX 1.6 CBOM, 2s |
| 2 | `POST /api/v1/scan/container` (`alpine:3.20`) | 3 assets via real Trivy SBOM, 8s |
| 3 | `POST /api/v1/cbom/reconcile` | evaluated=21, divergences=1 |
| 4 | Captures (see artifact files below) | assets=21, rating=436 B/C |

## Real repo findings (Semgrep, backend/app)

| Rule | File:line | QTRI | Note |
|---|---|---|---|
| python-crypto-ecb-mode-cipher | `engines/migration.py:76` | 25 | ECB mode referenced in the migration mapping table |
| python-crypto-weak-hash-md5 | `engines/rag_advisor.py:68` | 15 | The offline RAG embedder genuinely uses `hashlib.md5` for its deterministic index hash |
| python-crypto-weak-hash-md5 | `engines/sample_target.py:7` | 15 | Bundled demo fixture (intentional) |
| python-crypto-weak-hash-sha1 | `engines/sample_target.py:11` | 30 | Bundled demo fixture (intentional) |
| python-crypto-weak-rsa-keysize | `engines/sample_target.py:15` | 10 | Bundled demo fixture (intentional) |
| python-crypto-weak-tls-protocol | `engines/sample_target.py:19` | 20 | Bundled demo fixture (intentional) |

Headline: scanning our own real source surfaced a genuine production use of
MD5 (`rag_advisor.py:68`) that no manifest/SBOM view would ever report —
exactly the static-source value proposition.

## Real container image findings (Trivy image, alpine:3.20)

| Algorithm (package@version) | QTRI | Assessment |
|---|---|---|
| LIBCRYPTO3-3.3.7-r0 (`libcrypto3@3.3.7-r0`) | 90 | OpenSSL 3.3 core — modern, quantum-agile-capable (oqs-provider floor met) |
| LIBSSL3-3.3.7-r0 (`libssl3@3.3.7-r0`) | 50 | OpenSSL 3.3 TLS library |
| CA-CERTIFICATES-BUNDLE-20260413-r0 | 50 | Current CA bundle (2026) |

Versions were parsed from the real pulled image SBOM, not guessed: the engine
cross-checked every package/version against its quantum-readiness floors
(e.g. OpenSSL >= 3.2.0 is treated as PQC-capable-class).

## Environment facts / limitations

- Backend: FastAPI on Python venv; frontend untouched.
- Trivy: portable 0.74.0 at `backend/.tools/trivy`, DB-free CycloneDX mode
  (`TRIVY_SKIP_DB_UPDATE=1`), image pulled from registry (network required).
- Docker daemon not available on this host; registry pull worked without it.
- The seeded canonical state (12 assets) had to be restored after this pass —
  artifacts below reflect the transient E2E state (21 assets) only.
- `python:3.9-slim` / `nginx:1.24-alpine` paths in `demo/DEMO.md` use the
  engine's offline declared-image heuristic; this pass instead used a real
  registry pull to keep the record 100% factual.

## Artifacts (this directory)

- `scan_semgrep_real_repo.json` — Semgrep scan response with per-finding evidence
- `scan_container_alpine320.json` — Trivy container scan response
- `reconcile_result.json` — divergence report after both scans
- `assets_after_e2e.json` — full inventory at E2E state
- `cbom_export_cyclonedx.json` — CycloneDX 1.6 CBOM of the E2E state
- `cbom_history.json` / `cbom_diff.json` — scan snapshots + before/after delta
- `enterprise_rating.json` — rating at E2E state (436, B/C)
- `compliance_frameworks.json` — RBI / NIST IR 8547 / India DST-TEC mapping

Reproduce: start the backend, log in, then run the two scan requests above
against any repo/image you own or are authorized to test.
