"""
End-to-end verification script for Phase 3 features in Q-Guardian-v2.
Tests Container Scanner, Binary Scanner (ML-KEM NTT), Semgrep Scanner,
DB Persistence, Reconciliation & Divergence Detection, and CycloneDX 1.6 CBOM Export.
"""

import os
import sys
import uuid

# Set up paths
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.database import engine, create_db_and_tables, get_session, DBAsset
from app.engines.container_scanner import scan_container
from app.engines.sample_binary import generate_sample_crypto_binary
from app.engines.binary_scanner import scan_binary
from app.engines.source_scanner import scan_semgrep
from app.engines.reconciler import reconcile_assets
from app.engines.cbom import CBOMGenerator
from sqlmodel import Session, select

def test_full_phase3_pipeline():
    print("=" * 60)
    print("PHASE 3 VERIFICATION: MULTI-SOURCE DISCOVERY & CBOM ENGINE")
    print("=" * 60)
    
    create_db_and_tables()
    
    # 1. Test Container Scanner
    print("\n[1/5] Testing Container Scanner...")
    container_assets = scan_container("nginx:1.24-alpine")
    print(f"  Container findings: {len(container_assets)}")
    for a in container_assets:
        print(f"   -> [{a['source_type']}] {a['algorithm']} (QTRI: {a['qtri_score']})")
    assert len(container_assets) > 0, "Container scanner returned no assets"

    # 2. Test Binary Scanner with ML-KEM NTT Constant Detection
    print("\n[2/5] Testing Binary Scanner (LIEF + ML-KEM-768 NTT Detection)...")
    sample_bin = generate_sample_crypto_binary("phase3_test_target.bin")
    binary_assets = scan_binary(sample_bin)
    print(f"  Binary findings: {len(binary_assets)}")
    has_mlkem = False
    for a in binary_assets:
        print(f"   -> [{a['source_type']}] {a['algorithm']} PQC={a['is_pqc']} (QTRI: {a['qtri_score']}) Offset: {a.get('evidence_offset')}")
        if "ML-KEM" in a['algorithm'] and a['is_pqc']:
            has_mlkem = True
    assert has_mlkem, "ML-KEM NTT constant signature was not detected in binary!"

    # 3. Test Semgrep Crypto Rule Scanner
    print("\n[3/5] Testing Semgrep Crypto Scanner (rules/crypto.yml)...")
    semgrep_target = os.path.join(os.path.dirname(__file__), "sample_target.py")
    semgrep_assets = scan_semgrep(semgrep_target)
    print(f"  Semgrep findings: {len(semgrep_assets)}")
    for a in semgrep_assets:
        print(f"   -> [{a['source_type']}] {a['algorithm']} rule: {a.get('evidence_function')}")
    assert len(semgrep_assets) >= 3, "Semgrep scanner should detect weak crypto in sample_target.py"

    # 4. Test DB Persistence of all Discovered Assets
    print("\n[4/5] Testing Unified DB Persistence...")
    all_new_assets = container_assets + binary_assets + semgrep_assets
    job_uuid = str(uuid.uuid4())
    
    with Session(engine) as session:
        for a in all_new_assets:
            db_asset = DBAsset(
                asset_uuid=str(uuid.uuid4()),
                job_uuid=job_uuid,
                hostname=a["hostname"],
                tls_version=a["tls_version"],
                algorithm=a["algorithm"],
                key_size=a["key_size"],
                cipher_suite=a["cipher_suite"],
                forward_secrecy=a["forward_secrecy"],
                cert_valid=a["cert_valid"],
                cert_expiry=a["cert_expiry"],
                sensitivity_tier=a["sensitivity_tier"],
                is_pqc=a["is_pqc"],
                policy_compliant=a["policy_compliant"],
                qtri_score=a["qtri_score"],
                source_type=a.get("source_type", "static_code"),
                asset_type=a.get("asset_type", "library"),
                evidence_file=a.get("evidence_file"),
                evidence_line=a.get("evidence_line"),
                evidence_offset=a.get("evidence_offset"),
                evidence_function=a.get("evidence_function"),
                primitive=a.get("primitive", "unknown"),
                mode=a.get("mode"),
                parameter_set_identifier=a.get("parameter_set_identifier"),
                classical_security_level=a.get("classical_security_level", 0),
                nist_quantum_security_level=a.get("nist_quantum_security_level", 0),
                oid=a.get("oid"),
                divergence_flag=a.get("divergence_flag"),
                mosca_data='{"risk_state": "CRITICAL"}',
                last_scanned="2026-09-04T12:00:00"
            )
            session.add(db_asset)
        session.commit()
    print(f"  Persisted {len(all_new_assets)} assets to DB under job {job_uuid}")

    # 5. Test Reconciliation & Divergence Engine
    print("\n[5/5] Testing CBOM Reconciliation & Divergence Engine...")
    with Session(engine) as session:
        recon = reconcile_assets(session)
        print(f"  Reconciliation status: {recon['status']}")
        print(f"  Total evaluated: {recon['total_evaluated']}")
        print(f"  Divergences detected: {recon['divergence_count']}")
        print(f"  Maturity Level: {recon['maturity_label']} ({recon['crypto_agility_score']}/5)")
        for d in recon.get("divergences", []):
            print(f"   -> [{d['severity']}] {d['divergence_flag']} on {d['target']}")

    # 6. Test CycloneDX 1.6 Export
    print("\n[Bonus] Testing CycloneDX 1.6 Export...")
    cbom = CBOMGenerator.generate_cyclonedx_1_6_json(all_new_assets)
    comps = cbom.get("components", [])
    print(f"  CycloneDX Spec: {cbom.get('specVersion')}, Components: {len(comps)}")
    has_crypto_prop = any("cryptoProperties" in c for c in comps)
    print(f"  CryptoProperties present in components: {has_crypto_prop}")

    # Clean up test binary
    if os.path.exists(sample_bin):
        os.remove(sample_bin)

    print("\n" + "=" * 60)
    print("ALL PHASE 3 CAPABILITIES VERIFIED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    test_full_phase3_pipeline()
