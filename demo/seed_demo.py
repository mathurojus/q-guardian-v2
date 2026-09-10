"""
Demo seed script — Q-Guardian v2
================================
Builds a CANONICAL, reproducible demo database from the three scanner
families (no network scans, so it works fully offline and deterministically):

    1. Semgrep (rules/crypto.yml)  -> backend/app/engines/sample_target.py
    2. Trivy  (trivy fs)           -> demo/container-fixture (manifest scan)
    3. Container heuristics        -> nginx:1.24-alpine (base-image assessment)
    4. Binary (LIEF + ML-KEM NTT)  -> generated sample binary ("SAMPLE")

Then reconciles across sources to surface declared-vs-actual divergence and
records CBOM history snapshots so the before/after diff tab has data.

Usage:
    cd backend
    .venv/Scripts/python.exe ../demo/seed_demo.py [--wipe]

--wipe deletes qguardian.db first (run with the backend server STOPPED).
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
DB_PATH = os.path.join(BACKEND, "qguardian.db")


def wipe_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"[seed] wiped {DB_PATH}")
    # Also drop lingering sample binaries produced by scans
    for f in os.listdir(BACKEND):
        if f.endswith(".bin"):
            os.remove(os.path.join(BACKEND, f))


def main():
    if "--wipe" in sys.argv:
        wipe_db()

    from app.database import create_db_and_tables, engine as db_engine
    from app.main import _save_discovered_assets_to_db
    from app.engines.source_scanner import scan_semgrep
    from app.engines.container_scanner import scan_container, scan_container_heuristic
    from app.engines.sample_binary import generate_sample_crypto_binary
    from app.engines.binary_scanner import scan_binary
    from app.engines.reconciler import reconcile_assets
    from sqlmodel import Session

    create_db_and_tables()

    batches = []

    # 1. Semgrep static-source scan (repo's own crypto fixtures)
    target = os.path.join(BACKEND, "app", "engines", "sample_target.py")
    assets = scan_semgrep(target)
    job = str(uuid.uuid4())
    _save_discovered_assets_to_db(assets, job)
    batches.append(("semgrep (static-source)", len(assets)))
    print(f"[seed] semgrep  : {len(assets)} assets")

    # 2. Trivy fs on the demo container manifest (real scanner, offline)
    fixture = os.path.join(os.path.dirname(__file__), "container-fixture")
    assets = scan_container(fixture)
    job = str(uuid.uuid4())
    _save_discovered_assets_to_db(assets, job)
    batches.append(("trivy fs (container)", len(assets)))
    print(f"[seed] trivy    : {len(assets)} assets")

    # 3. Container base-image heuristic assessment (offline & deterministic —
    #    bypasses `trivy image` so the demo never depends on registry pulls)
    assets = scan_container_heuristic("nginx:1.24-alpine")
    job = str(uuid.uuid4())
    _save_discovered_assets_to_db(assets, job)
    batches.append(("nginx image (container)", len(assets)))
    print(f"[seed] container: {len(assets)} assets")

    # 4. Binary scan — synthesized ELF with ML-KEM-768 NTT constants
    bin_path = generate_sample_crypto_binary("demo_pqc_target.bin")
    assets = scan_binary(bin_path)
    job = str(uuid.uuid4())
    _save_discovered_assets_to_db(assets, job)
    batches.append(("binary (LIEF/ML-KEM)", len(assets)))
    print(f"[seed] binary   : {len(assets)} assets (ML-KEM NTT detection)")

    # Reconcile: declared-vs-actual divergence across sources
    with Session(db_engine) as session:
        recon = reconcile_assets(session)
        print("[seed] reconcile: evaluated=%d divergences=%d maturity=%s" % (
            recon["total_evaluated"], recon["divergence_count"], recon["maturity_label"]))
        total = recon["total_evaluated"]

    # Clean up the synthesized binary artifact (evidence text remains intact)
    if os.path.exists(bin_path):
        os.remove(bin_path)

    print(f"[seed] DONE — {total} assets, {sum(b[1] for b in batches)} findings in "
          f"{len(batches)} scanner batches. DB ready for demo.")
    return total


if __name__ == "__main__":
    main()
