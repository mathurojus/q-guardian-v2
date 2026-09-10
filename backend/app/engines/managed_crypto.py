"""
Managed Cryptography & HSM Intake Engine for Q-Guardian-v2.

BRING-YOUR-OWN-INVENTORY: this engine does NOT connect to any cloud provider or
HSM. It has no boto3/azure/google-cloud/hvac SDK and makes no network calls. It
maps caller-supplied KMS/HSM export records (e.g. a CSV/JSON you export from
`aws kms list-keys`, Azure/GCP, Vault, or an HSM audit) into the unified DBAsset
schema (source_type='cloud_kms' or 'hardware_module') and scores CRQC exposure
via Mosca and Q-TRI. Bundled sample fixtures are clearly tagged data_source=
'sample_fixture' so demo data is never mistaken for a live inventory pull.
"""

import re
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from app.engines.mosca import calculate_mosca_clocks, derive_migration_complexity
from app.engines.scoring import calculate_qtri_score
from app.engines.hndl import calculate_hndl_exposure


# ── Cloud KMS Intake ──────────────────────────────────────────────────────────

def _classify_kms_algorithm(raw_algo: str, raw_size: Optional[int] = None) -> tuple[str, int, str, bool, int, int]:
    """
    Classify KMS algorithm into (algorithm, key_size, primitive, is_pqc, classical_sec, nist_level).
    """
    algo_upper = (raw_algo or "").upper().strip()
    size = raw_size or 0

    if "RSA" in algo_upper:
        if size == 0:
            match = re.search(r"(\d{4})", algo_upper)
            size = int(match.group(1)) if match else 2048
        classical_sec = 80 if size < 2048 else (112 if size == 2048 else (128 if size == 3072 else 192))
        primitive = "signature" if ("SIGN" in algo_upper or "PSS" in algo_upper) else "public-key-encryption"
        return f"RSA-{size}", size, primitive, False, classical_sec, 0

    elif any(k in algo_upper for k in ("ECC", "ECDSA", "P256", "P-256", "SECP256", "PRIME256")):
        return "ECC-P256", 256, "signature", False, 128, 0

    elif any(k in algo_upper for k in ("P384", "P-384", "SECP384")):
        return "ECC-P384", 384, "signature", False, 192, 0

    elif "ML-KEM" in algo_upper or "KYBER" in algo_upper:
        return "ML-KEM-768", 768, "key-agreement", True, 192, 3

    elif "ML-DSA" in algo_upper or "DILITHIUM" in algo_upper:
        return "ML-DSA-65", 65, "signature", True, 192, 3

    elif "AES" in algo_upper:
        size = 256 if (size == 0 or size == 256 or "256" in algo_upper) else 128
        return f"AES-{size}-GCM", size, "symmetric-cipher", False, size, 1

    # Default fallback
    return raw_algo or "RSA-2048", size or 2048, "public-key-encryption", False, 112, 0


def ingest_kms_inventory(records: List[Dict[str, Any]], data_source: str = "user_import") -> List[Dict[str, Any]]:
    """
    Ingest a batch of caller-supplied Cloud KMS key records into unified assets.
    data_source is stamped onto every asset ('user_import' or 'sample_fixture').
    """
    assets = []
    for rec in records:
        provider = str(rec.get("provider") or "AWS KMS").strip()
        key_name = str(rec.get("key_name") or rec.get("id") or "unnamed-kms-key").strip()
        region = str(rec.get("region") or "global").strip()
        raw_algo = str(rec.get("algorithm") or "RSA-2048")
        raw_size = rec.get("key_size")
        rotation_days = int(rec.get("rotation_days") or rec.get("rotation_age") or 180)
        tier = str(rec.get("sensitivity_tier") or "S2").upper()

        algo, key_size, primitive, is_pqc, classical_sec, nist_level = _classify_kms_algorithm(raw_algo, raw_size)

        # In KMS, keys unrotated for >365 days violate crypto-hygiene policies
        unrotated_violation = rotation_days > 365
        policy_compliant = (not unrotated_violation) and (is_pqc or classical_sec >= 128)

        hostname = f"kms:{provider.lower().replace(' ', '-')}:{region}:{key_name}"

        raw_asset = {
            "hostname": hostname,
            "tls_version": "N/A",
            "algorithm": algo,
            "key_size": key_size,
            "cipher_suite": "N/A",
            "forward_secrecy": None,
            "cert_valid": None,
            "cert_expiry": None,
            "sensitivity_tier": tier,
            "is_pqc": is_pqc,
            "policy_compliant": policy_compliant,
            "source_type": "cloud_kms",
            "asset_type": "kms_key",
            "data_source": data_source,
            "rotation_days": rotation_days,
            "evidence_file": f"{provider} [{region}]",
            "evidence_function": rec.get("key_arn") or rec.get("key_id") or key_name,
            "evidence_offset": rotation_days,
            "primitive": primitive,
            "classical_security_level": classical_sec,
            "nist_quantum_security_level": nist_level,
        }

        # Calculate scores
        qtri = calculate_qtri_score(raw_asset)
        if unrotated_violation:
            qtri = max(10, qtri - 20)
        raw_asset["qtri_score"] = qtri

        complexity = derive_migration_complexity(raw_asset)
        mosca = calculate_mosca_clocks(complexity, tier, is_pqc=is_pqc)
        hndl = calculate_hndl_exposure(raw_asset)

        raw_asset["mosca"] = mosca
        raw_asset["hndl"] = hndl

        if is_pqc:
            recom = f"KMS Key is quantum-resilient ({algo}). Maintain automated rotation policy."
        elif "RSA" in algo or "ECC" in algo:
            recom = f"Migrate KMS key from {algo} to hybrid ML-KEM-768 or ML-DSA-65 envelope encryption."
        else:
            recom = f"Ensure regular annual KMS key rotation (current age: {rotation_days} days)."

        raw_asset["recommendation"] = recom
        assets.append(raw_asset)

    return assets


# ── Hardware Security Module (HSM) Intake ────────────────────────────────────

def ingest_hsm_inventory(records: List[Dict[str, Any]], data_source: str = "user_import") -> List[Dict[str, Any]]:
    """
    Ingest caller-supplied Hardware Security Module (HSM) inventory records.
    Scored for CRQC exposure: an HSM with RSA/ECC long-lived keys and no PQC
    firmware upgrade path is classified as critical risk. data_source is stamped
    onto every asset ('user_import' or 'sample_fixture').
    """
    assets = []
    for rec in records:
        make_model = str(rec.get("make_model") or rec.get("model") or "Thales Luna 7 HSM").strip()
        serial_or_id = str(rec.get("serial_number") or rec.get("id") or "HSM-SLOT-01").strip()
        location = str(rec.get("datacenter") or rec.get("location") or "DC-Primary").strip()
        fips_cert = str(rec.get("fips_certification") or "FIPS 140-2 Level 3").strip()
        firmware_age_years = float(rec.get("firmware_age_years") or rec.get("firmware_age") or 3.0)
        key_lifetime_years = float(rec.get("key_lifetime_years") or 5.0)
        tier = str(rec.get("sensitivity_tier") or "S1").upper()
        pqc_firmware_support = bool(rec.get("pqc_firmware_support", False))

        raw_algos = rec.get("algorithms_loaded") or ["RSA-2048", "ECC-P256", "AES-256"]
        if isinstance(raw_algos, str):
            raw_algos = [a.strip() for a in raw_algos.split(",") if a.strip()]

        for algo_entry in raw_algos:
            algo, key_size, primitive, is_pqc, classical_sec, nist_level = _classify_kms_algorithm(algo_entry)

            if is_pqc or pqc_firmware_support:
                is_pqc = True
                nist_level = max(1, nist_level)

            # HSM keys with multi-year lifetime without PQC firmware upgrade = CRITICAL CRQC risk
            has_long_lived_classical_risk = (not is_pqc) and (key_lifetime_years >= 3.0) and ("RSA" in algo or "ECC" in algo)
            policy_compliant = (not has_long_lived_classical_risk) and ("140-3" in fips_cert or "140-2" in fips_cert)

            hostname = f"hsm:{make_model.lower().replace(' ', '-')}:{serial_or_id}:{algo.lower()}"

            raw_asset = {
                "hostname": hostname,
                "tls_version": "N/A",
                "algorithm": algo,
                "key_size": key_size,
                "cipher_suite": "N/A",
                "forward_secrecy": None,
                "cert_valid": None,
                "cert_expiry": None,
                "sensitivity_tier": tier,
                "is_pqc": is_pqc,
                "policy_compliant": policy_compliant,
                "source_type": "hardware_module",
                "asset_type": "hsm",
                "data_source": data_source,
                "fips_certification": fips_cert,
                "key_lifetime_years": key_lifetime_years,
                "evidence_file": f"{make_model} [{fips_cert}]",
                "evidence_function": f"Slot/{serial_or_id} ({location})",
                "evidence_offset": int(firmware_age_years * 365),
                "primitive": primitive,
                "classical_security_level": classical_sec,
                "nist_quantum_security_level": nist_level,
            }

            # Hardware modules without PQC firmware get penalized heavily on QTRI
            qtri = calculate_qtri_score(raw_asset)
            if has_long_lived_classical_risk:
                qtri = min(qtri, 25) # Cap at 25 for long-lived classical HSM root keys
            raw_asset["qtri_score"] = qtri

            complexity = derive_migration_complexity(raw_asset)
            # Physical HSM replacement / firmware ceremony adds to complexity
            mosca = calculate_mosca_clocks(complexity, tier, is_pqc=is_pqc)
            hndl = calculate_hndl_exposure(raw_asset)

            if has_long_lived_classical_risk:
                mosca["risk_state"] = "CRITICAL"

            raw_asset["mosca"] = mosca
            raw_asset["hndl"] = hndl

            if is_pqc:
                recom = f"HSM possesses PQC-capable firmware ({algo}). Schedule dual-signature key ceremony."
            elif has_long_lived_classical_risk:
                recom = (
                    f"CRITICAL: HSM root key ({algo}) has {key_lifetime_years}-year lifetime. "
                    f"Firmware age {firmware_age_years}yr lacks FIPS 203/204 support. "
                    "Initiate HSM hardware refresh / PQC firmware upgrade ceremony."
                )
            else:
                recom = f"Plan HSM firmware upgrade to support FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)."

            raw_asset["recommendation"] = recom
            assets.append(raw_asset)

    return assets


# ── Pre-Packaged Demo Fixtures ───────────────────────────────────────────────

def get_sample_kms_fixtures() -> List[Dict[str, Any]]:
    """SAMPLE (synthetic) Cloud KMS inventory fixtures for demo/testing only.
    These ARNs/URLs are fabricated and are NOT read from any live cloud account."""
    return [
        {
            "provider": "AWS KMS",
            "key_name": "prod-cardholder-pii-envelope-key",
            "key_arn": "arn:aws:kms:ap-south-1:123456789012:key/3b5f8a92-74c1-4b8a",
            "region": "ap-south-1",
            "algorithm": "RSA-2048",
            "key_size": 2048,
            "rotation_days": 420,
            "sensitivity_tier": "S1"
        },
        {
            "provider": "Azure Key Vault",
            "key_name": "kv-banking-auth-token-signing",
            "key_arn": "https://vault-prod-mumbai.vault.azure.net/keys/auth-signing",
            "region": "centralindia",
            "algorithm": "ECC-P256",
            "key_size": 256,
            "rotation_days": 180,
            "sensitivity_tier": "S2"
        },
        {
            "provider": "Google Cloud KMS",
            "key_name": "gcp-db-storage-encryption-key",
            "key_arn": "projects/fintech-prod/locations/asia-south1/keyRings/ring1/cryptoKeys/db-key",
            "region": "asia-south1",
            "algorithm": "AES-256-GCM",
            "key_size": 256,
            "rotation_days": 90,
            "sensitivity_tier": "S3"
        },
        {
            "provider": "HashiCorp Vault",
            "key_name": "vault-hybrid-pqc-transit-key",
            "key_arn": "transit/keys/pqc-exchange-v1",
            "region": "on-prem-dc1",
            "algorithm": "ML-KEM-768",
            "key_size": 768,
            "rotation_days": 45,
            "sensitivity_tier": "S1"
        }
    ]


def get_sample_hsm_fixtures() -> List[Dict[str, Any]]:
    """SAMPLE (synthetic) HSM fleet fixtures for demo/testing only.
    Serials/models are fabricated and are NOT read from any live HSM."""
    return [
        {
            "make_model": "Thales Luna PCIe HSM 7",
            "serial_number": "LUNA7-PROD-MUM-01",
            "datacenter": "Mumbai DC-Core",
            "fips_certification": "FIPS 140-2 Level 3",
            "firmware_age_years": 4.5,
            "key_lifetime_years": 7.0,
            "sensitivity_tier": "S1",
            "pqc_firmware_support": False,
            "algorithms_loaded": ["RSA-4096", "RSA-2048", "AES-256"]
        },
        {
            "make_model": "AWS CloudHSM v2 Cluster",
            "serial_number": "CLOUDHSM-AP-SOUTH-1-CLUST",
            "datacenter": "AWS ap-south-1",
            "fips_certification": "FIPS 140-3 Level 3",
            "firmware_age_years": 1.5,
            "key_lifetime_years": 3.0,
            "sensitivity_tier": "S2",
            "pqc_firmware_support": True,
            "algorithms_loaded": ["ECC-P256", "ML-KEM-768"]
        },
        {
            "make_model": "Utimaco SecurityServer Se-Series",
            "serial_number": "UTIMACO-PAYMENT-ROOT-02",
            "datacenter": "Chennai Disaster Recovery",
            "fips_certification": "FIPS 140-2 Level 3",
            "firmware_age_years": 5.2,
            "key_lifetime_years": 10.0,
            "sensitivity_tier": "S1",
            "pqc_firmware_support": False,
            "algorithms_loaded": ["RSA-2048", "3DES", "AES-256"]
        }
    ]
