# Q-Guardian v2 — Live Demo Runbook

Deterministic, offline-capable demo. Canonical data is produced by
`demo/seed_demo.py` — it runs the **real** Semgrep, Trivy, container and
binary (LIEF / ML-KEM NTT) engines, so the fallback path and the live path
produce identical numbers.

---

## 1. Launch

```powershell
# from repo root — one-time setup was already done (backend/.venv, npm install)
.\run.ps1
```

Or manually:

```bash
# Terminal 1 — backend (venv python, NOT system python)
cd backend
./.venv/Scripts/python.exe -m uvicorn app.main:app --port 8000

# Terminal 2 — frontend
cd frontend
npm run dev
```

- Backend: http://localhost:8000  ·  Docs: http://localhost:8000/docs
- Frontend: http://localhost:5173
- Login: `qguardian_admin` / `QGuardian@2026`

### Reset to canonical state (before each demo run)

```bash
# stop backend first, then:
cd backend
./.venv/Scripts/python.exe ../demo/seed_demo.py --wipe
# expected output: 12 assets, 1 divergence, Level 3 maturity — deterministic
```

> ⚠️ DB is wiped → run the seed AFTER starting is NOT needed; seed writes the
> DB, then start the backend. Fallback artifacts for the exact state live in
> `demo/fallback/` (assets, cyclonedx CBOM, compliance, history/diff, rating).

---

## 2. Scripted flow (~4 minutes, all offline)

| # | Step | Expect |
|---|------|--------|
| 1 | Log in with demo credentials | Analyst workspace (loading panel → Posture Dashboard) |
| 2 | **Posture Dashboard** | Rating **509 / B–C Good**, **12 total assets**, **12 critical** (seeded fixtures are deliberately vulnerable demo targets), ML-KEM binary rows at QTRI 98 |
| 3 | **ASSET INVENTORY** | 12 rows; source badges (SEMGREP / DOCKER / BINARY), evidence file+line / binary offset; **⚠ DIVERGENT (1)** pill |
| 4 | **TOPOLOGY GRAPH** | Nodes colored by source vector; amber **DIVERGENCE** hub edge; legend |
| 5 | **CERT-IN MAPPER** | Three sections — RBI (4), **NIST IR 8547 (4)** w/ T1→T4 deadline chips, **India DST/TEC (4)** w/ NQM-2031 chips |
| 6 | **MULTI-SOURCE SCAN → SEMGREP** → target `app/engines/sample_target.py` → SCAN | 4 findings (MD5, SHA-1, RSA-1024, TLS-1.0/1.1), CBOM 1.6 badge |
| 7 | **MULTI-SOURCE SCAN → CONTAINER** → target `python:3.9-slim` → SCAN | Container heuristic findings (OpenSSL/cryptography rows) |
| 8 | **MULTI-SOURCE SCAN → BINARY** → click **DEMO FIXTURE** → SCAN | **ML-KEM-768 NTT detected** (PQC LVL 3, offset `0x123`) — strongest scanner result |
| 9 | **RECONCILE CBOM** | Divergence report: container-modern vs binary-legacy MD5 |
| 10 | **CBOM EXPORT** | Before/after diff panel (additions vs previous scan), JSON + PDF export |

### Highlight moments (scripted)

1. **Declared-vs-actual divergence** (Step 9 → Step 3 filter `DIVERGENT`):
   container layer ships OpenSSL 3.1.4 (modern) but the compiled binary still
   embeds a legacy **MD5 IV table** → `DIV_CONTAINER_MODERN_VS_BINARY_MD5`,
   proving supply-chain SBOM claims ≠ what the binary actually does.
2. **Strongest scanner result** (Step 8): LIEF-based detection of the
   **ML-KEM-768 NTT zeta constants** in `.rodata` at byte offset `0x123` —
   PQC presence confirmed at the binary level, not from a manifest.

---

## 3. Fallback plan (if live scanning fails)

Live scanning is not required at all — the canonical DB is **pre-seeded**
(`seed_demo.py --wipe` above) and the full state is snapshotted in
`demo/fallback/`:

| File | Contents |
|------|----------|
| `assets.json` | The 12 canonical assets (identical to Step 2/3) |
| `cbom_export_cyclonedx.json` | Schema-valid CycloneDX 1.6 export with source-tagged components |
| `compliance_frameworks.json` | RBI + NIST IR 8547 + India DST/TEC mappings |
| `cbom_history.json` / `cbom_diff.json` | CBOM history + before/after delta |
| `enterprise_rating.json` | Rating snapshot (509, B/C) |
| `seed_report_run2.txt` / `seed_report_final.txt` | Determinism proof (identical outputs) |

If a live scan fails mid-demo: say *"switching to the pre-audited snapshot"*,
re-run `seed_demo.py --wipe`, refresh the browser. Numbers will match the
runbook exactly. All scans in the seed are offline-safe
(`TRIVY_SKIP_DB_UPDATE=1`, no network, no Docker daemon required).

---

## 4. Notes

- **NIST IR 8547 dates** (T1 2027 → T4 2033) and **DST NQM 2031** horizon are
  the platform's planning-alignment flags — refine milestone dates to your
  institution's compliance calendar before production use.
- Trivy runs in DB-free CycloneDX/SBOM mode by default (see
  `container_scanner.py`). Run `trivy --download-db-only` once to also get
  the CVE-rich JSON path.
- `run.ps1` prefers `backend/.venv` when present — no global pip installs needed.
