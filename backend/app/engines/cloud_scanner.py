"""
Cloud KMS / HSM Crypto Artefact Scanner Engine
===============================================
Catalogues cryptographic artefacts hosted in cloud key-management services
(AWS KMS, Azure Key Vault, GCP Cloud KMS / Cloud HSM, IBM Cloud KMS) and
on-premise / cloud Hardware Security Modules (Thales Luna, AWS CloudHSM,
nCipher, Safenet) into the unified DBAsset multi-source schema
(source_type: cloud_kms, asset_type: kms_key | hardware_module).

Supports provider-aware heuristics plus free-form manual intake lines:

    PROVIDER::NAME::ALGORITHM::KEYSIZE::REGION::USAGE

e.g.  aws::payment-encryption::RSA::2048::ap-south-1::payment
      hsm::luna-sa::AES::256::MUM-1::general
      azure::signing-cert::ECDSA::P-256::eastus::identity
"""

import re
from typing import Dict, Any, List, Optional
from datetime import datetime


PROVIDERS = {
    "aws":   {"name": "AWS KMS", "hardware": False},
    "azure": {"name": "Azure Key Vault", "hardware": False},
    "gcp":   {"name": "GCP Cloud KMS", "hardware": False},
    "ibm":   {"name": "IBM Cloud KMS", "hardware": False},
    "hsm":   {"name": "Hardware Security Module", "hardware": True},
}

USAGE_TIER = {
    "payment":  "S1",
    "core":     "S1",
    "identity": "S2",
    "auth":     "S2",
    "kyc":      "S2",
    "cert":     "S2",
    "general":  "S3",
    "internal": "S4",
    "public":   "S5",
}

DEFAULT_TIER = "S3"


def _is_pqc(algo: str) -> bool:
    return bool(re.search(r"(ML-KEM|KYBER|ML-DSA|DILITHIUM|SLH-DSA|SPHINCS|FALCON|X25519MLKEM)", algo, re.IGNORECASE))


def _score_kms_asset(algorithm: str, key_size: int) -> dict:
    """Compute Q-TRI / PQC posture for a KMS or HSM artefact based on its
    algorithm family and key size. Mirrors the legacy-family caps used by the
    source / container engines so scores stay consistent across vectors."""
    algo = (algorithm or "RSA").upper()

    if _is_pqc(algo):
        return {"is_pqc": True, "qtri": 95, "nist": 3, "classical": 256,
                "compliant": True, "tls": "1.3",
                "rec": "Post-quantum algorithm already deployed in KMS/HSM."}
    if "MD5" in algo:
        return {"is_pqc": False, "qtri": 18, "nist": 0, "classical": 0,
                "compliant": False, "tls": "1.0",
                "rec": "MD5 is broken for collisions and halved by Grover. Replace with SHA-256/SHA3-256."}
    if "SHA-1" in algo or "SHA1" in algo:
        return {"is_pqc": False, "qtri": 30, "nist": 0, "classical": 80,
                "compliant": False, "tls": "1.1",
                "rec": "SHA-1 is deprecated (SP 800-131A Rev.2). Migrate to SHA-256."}
    if "DES" in algo or "RC4" in algo or "RC2" in algo or "BLOWFISH" in algo or "3DES" in algo:
        return {"is_pqc": False, "qtri": 22, "nist": 0, "classical": 56,
                "compliant": False, "tls": "1.0",
                "rec": "Legacy 56/64-bit symmetric cipher. Replace with AES-256-GCM."}
    if "ECB" in algo:
        return {"is_pqc": False, "qtri": 38, "nist": 0, "classical": 128,
                "compliant": False, "tls": "1.2",
                "rec": "ECB mode leaks patterns. Use authenticated AES-GCM."}

    if "AES" in algo or "GCM" in algo or "CHACHA" in algo:
        if key_size and key_size >= 256:
            return {"is_pqc": False, "qtri": 78, "nist": 1, "classical": 256,
                    "compliant": True, "tls": "1.3",
                    "rec": "AES-256 / ChaCha20 resists Grover with 128-bit quantum security. Maintain; monitor for HNDL."}
        return {"is_pqc": False, "qtri": 58, "nist": 1, "classical": 128,
                "compliant": True, "tls": "1.2",
                "rec": "AES-128 provides only 64-bit quantum security (Grover). Consider AES-256."}

    if "ECDSA" in algo or "ECDH" in algo or "ECC" in algo or "P-256" in algo or "P-384" in algo:
        return {"is_pqc": False, "qtri": 55, "nist": 0, "classical": 128,
                "compliant": False, "tls": "1.2",
                "rec": "ECC is broken by Shor's algorithm. Migrate to hybrid X25519MLKEM768 / ML-DSA."}

    if "RSA" in algo or "DSA" in algo:
        if key_size and 0 < key_size < 2048:
            return {"is_pqc": False, "qtri": 18, "nist": 0, "classical": 80,
                    "compliant": False, "tls": "1.1",
                    "rec": "Sub-2048-bit " + algo + " is classically breakable. URGENT: re-key to RSA-3072+ then ML-KEM/ML-DSA hybrid."}
        if key_size and key_size >= 3072:
            return {"is_pqc": False, "qtri": 58, "nist": 0, "classical": 128,
                    "compliant": False, "tls": "1.2",
                    "rec": algo + "-" + str(key_size) + " is classical-only. Plan ML-KEM-768 / ML-DSA hybrid key ceremony."}
        return {"is_pqc": False, "qtri": 42, "nist": 0, "classical": 112,
                "compliant": False, "tls": "1.2",
                "rec": algo + " is broken by Shor. Migrate to ML-KEM-768 / ML-DSA-65 hybrid."}

    return {"is_pqc": False, "qtri": 50, "nist": 0, "classical": 112,
            "compliant": False, "tls": "1.2",
            "rec": "Review KMS/HSM primitive " + algo + " against NIST IR 8547 transition profile."}


def _parse_keysize(value: str) -> int:
    """Parse an integer key size (bits) or an ECC curve name into a bits value."""
    v = (value or "").strip().upper()
    if not v:
        return 0
    m = re.search(r"\d+", v)
    if m:
        return int(m.group(0))
    if v in ("P-256", "P256", "PRIME256V1", "SECP256R1"):
        return 256
    if v in ("P-384", "P384", "SECP384R1"):
        return 384
    if v in ("P-521", "P521", "SECP521R1"):
        return 521
    if v in ("X25519", "ED25519"):
        return 256
    return 0


def _make_asset(provider: str, name: str, algorithm: str, key_size: int,
                region: str, usage: str) -> dict:
    prov = PROVIDERS.get(provider.lower(), {"name": provider or "KMS", "hardware": False})
    is_hsm = prov["hardware"] or provider.lower() == "hsm"
    score = _score_kms_asset(algorithm, key_size)
    tier = USAGE_TIER.get((usage or "general").lower(), DEFAULT_TIER)

    hostname = ("hsm:" if is_hsm else "kms:") + provider.lower() + ":" + (name or "unnamed")
    asset_type = "hardware_module" if is_hsm else "kms_key"
    up = algorithm.upper()
    if "RSA" in up or "DSA" in up or "DILITHIUM" in up or "SLH" in up:
        primitive = "signature"
    elif "SHA" in up or "MD5" in up:
        primitive = "hash"
    else:
        primitive = "key-agreement"

    evidence = provider.lower() + ":kms:" + (region or "global") + ":" + (usage or "general")

    return {
        "hostname": hostname,
        "tls_version": score["tls"],
        "algorithm": up,
        "key_size": key_size or 0,
        "cipher_suite": prov["name"].upper() + "-" + up,
        "forward_secrecy": True,
        "cert_valid": True,
        "cert_expiry": datetime.now().isoformat(),
        "sensitivity_tier": tier,
        "is_pqc": score["is_pqc"],
        "policy_compliant": score["compliant"],
        "qtri_score": score["qtri"],
        "source_type": "cloud_kms",
        "asset_type": asset_type,
        "evidence_file": evidence,
        "evidence_line": None,
        "evidence_function": prov["name"] + ":" + (name or "unnamed"),
        "primitive": primitive,
        "classical_security_level": score["classical"],
        "nist_quantum_security_level": score["nist"],
        "recommendation": score["rec"],
        "provider": prov["name"],
        "region": region or "global",
        "usage": usage or "general",
    }


def _parse_entry(line: str) -> Optional[dict]:
    """Parse a single free-form intake line:
    PROVIDER::NAME::ALGORITHM::KEYSIZE::REGION::USAGE
    Missing fields are tolerated (defaulted)."""
    parts = [p.strip() for p in (line or "").split("::")]
    if not parts or not parts[0]:
        return None
    provider = parts[0].lower()
    name = parts[1] if len(parts) > 1 and parts[1] else "unnamed"
    algorithm = parts[2] if len(parts) > 2 and parts[2] else "RSA"
    key_size = _parse_keysize(parts[3]) if len(parts) > 3 else 0
    region = parts[4] if len(parts) > 4 and parts[4] else "global"
    usage = parts[5] if len(parts) > 5 and parts[5] else "general"
    return _make_asset(provider, name, algorithm, key_size, region, usage)


def scan_cloud_kms(entries: List[str]) -> List[dict]:
    """Scan free-form KMS / HSM intake entries and return asset dicts."""
    assets = []
    for raw in entries or []:
        asset = _parse_entry(raw)
        if asset:
            assets.append(asset)
    return assets


def scan_cloud_kms_presets() -> List[dict]:
    """Curated, deterministic demonstration set of cloud KMS / HSM artefacts
    spanning multiple providers and usage tiers (used by the demo seed).
    These are FIXTURES describing realistic enterprise deployments."""
    entries = [
        "aws::payment-encryption::RSA::2048::ap-south-1::payment",
        "aws::customer-master::AES::256::ap-south-1::general",
        "azure::signing-cert::ECDSA::P-256::centralindia::identity",
        "gcp::cloud-hsm-root::AES::256::global::core",
        "hsm::luna-sa-legacy::RSA::1024::MUM-1::payment",
        "hsm::cloudhsm-master::AES::256::ap-south-1::core",
    ]
    return scan_cloud_kms(entries)
