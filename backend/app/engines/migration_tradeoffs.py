"""
Cost / latency tradeoff profiles for PQC migration recommendations
(statement iv: recommend alternatives based on risk profile, latency, cost).
Each family lists ranked candidate alternatives from lowest migration cost
to strongest quantum assurance. The first entry is the primary pick.
"""

MIGRATION_TRADEOFFS = {
    "pqc": [],
    "md5": [
        {"target_algorithm": "SHA-256 (FIPS 180-4)", "nist_standard": "NIST FIPS 180-4",
         "effort_estimate": "1 to 2 weeks", "latency_impact": "Low (none)", "migration_cost": "Low",
         "risk_reduction": "High", "best_for": "Fastest to migrate / minimal change"},
        {"target_algorithm": "SHA3-256 (FIPS 202)", "nist_standard": "NIST FIPS 202",
         "effort_estimate": "2 to 4 weeks", "latency_impact": "Low (none)", "migration_cost": "Low",
         "risk_reduction": "High (SPONGE construction)", "best_for": "Long-lived integrity proofs"},
    ],
    "sha1": [
        {"target_algorithm": "SHA-256 (FIPS 180-4)", "nist_standard": "NIST FIPS 180-4",
         "effort_estimate": "2 to 3 weeks", "latency_impact": "Low (none)", "migration_cost": "Low",
         "risk_reduction": "High", "best_for": "Fastest to migrate"},
        {"target_algorithm": "SHA-384 / SHA3-384 (FIPS 180-4 / 202)", "nist_standard": "NIST FIPS 180-4 / 202",
         "effort_estimate": "3 to 4 weeks", "latency_impact": "Low (none)", "migration_cost": "Low",
         "risk_reduction": "High", "best_for": "Stronger digest, 192-bit classical strength"},
    ],
    "symmetric": [
        {"target_algorithm": "AES-256-GCM", "nist_standard": "NIST FIPS 197 / SP 800-38D",
         "effort_estimate": "1 to 2 weeks", "latency_impact": "Low (hardware AES)", "migration_cost": "Low",
         "risk_reduction": "Critical", "best_for": "Lowest latency (AES-NI)"},
        {"target_algorithm": "ChaCha20-Poly1305", "nist_standard": "RFC 8439",
         "effort_estimate": "1 to 3 weeks", "latency_impact": "Low (software, ~0.3x AES-NI)",
         "migration_cost": "Low", "risk_reduction": "Critical", "best_for": "Embedded / no hardware AES"},
    ],
    "ecb": [
        {"target_algorithm": "AES-256-GCM (authenticated)", "nist_standard": "NIST SP 800-38D",
         "effort_estimate": "1 week", "latency_impact": "Low", "migration_cost": "Low",
         "risk_reduction": "High", "best_for": "Fastest to migrate"},
        {"target_algorithm": "AES-256-GCM with key rotation", "nist_standard": "NIST SP 800-38D",
         "effort_estimate": "1 to 2 weeks", "latency_impact": "Low", "migration_cost": "Medium",
         "risk_reduction": "High (+ re-key hygiene)", "best_for": "Long-lived stored ciphertext"},
    ],
    "dsa": [
        {"target_algorithm": "ML-DSA-65 (FIPS 204)", "nist_standard": "NIST FIPS 204",
         "effort_estimate": "2 to 6 weeks", "latency_impact": "Moderate (~0.5ms sign/verify)",
         "migration_cost": "High", "risk_reduction": "Critical", "best_for": "Pure PQC standard"},
        {"target_algorithm": "Hybrid ECDSA P-256 + ML-DSA-65", "nist_standard": "NIST FIPS 186-5 / 204",
         "effort_estimate": "3 to 6 weeks", "latency_impact": "Moderate", "migration_cost": "Medium",
         "risk_reduction": "Critical (defense-in-depth)", "best_for": "Interop with existing PKI"},
    ],
    "ecdsa": [
        {"target_algorithm": "Hybrid ECDSA P-256 + ML-DSA-65", "nist_standard": "NIST FIPS 186-5 / FIPS 204",
         "effort_estimate": "1 to 3 weeks", "latency_impact": "Moderate (~0.4ms dual signature)",
         "migration_cost": "Medium", "risk_reduction": "High", "best_for": "Compatible with existing CAs"},
        {"target_algorithm": "SLH-DSA (FIPS 205, hash-based)", "nist_standard": "NIST FIPS 205",
         "effort_estimate": "2 to 4 weeks", "latency_impact": "Higher (~1.5ms, large signatures)",
         "migration_cost": "Medium", "risk_reduction": "High (conservative margin)",
         "best_for": "Long-term archival signatures"},
    ],
}
    "rsa_strong": [
        {"target_algorithm": "Hybrid X25519MLKEM768 key exchange", "nist_standard": "NIST FIPS 203 / SP 800-52r2",
         "effort_estimate": "2 to 4 weeks", "latency_impact": "Low (~0.2ms handshake overhead)",
         "migration_cost": "Low", "risk_reduction": "High", "best_for": "Lowest latency / TLS 1.3"},
        {"target_algorithm": "Pure ML-KEM-768 (FIPS 203)", "nist_standard": "NIST FIPS 203",
         "effort_estimate": "4 to 8 weeks", "latency_impact": "Low", "migration_cost": "Medium",
         "risk_reduction": "Critical", "best_for": "Maximum quantum assurance"},
    ],
    "rsa_weak": [
        {"target_algorithm": "Interim RSA-3072/4096 (SP 800-52r2)", "nist_standard": "NIST SP 800-52r2",
         "effort_estimate": "1 to 2 weeks", "latency_impact": "Low", "migration_cost": "Low",
         "risk_reduction": "High (classical fix)", "best_for": "Immediate stop-gap re-key"},
        {"target_algorithm": "Hybrid X25519MLKEM768 (FIPS 203)", "nist_standard": "NIST FIPS 203",
         "effort_estimate": "2 to 4 weeks", "latency_impact": "Low (~0.2ms)", "migration_cost": "Medium",
         "risk_reduction": "Critical", "best_for": "Quantum-safe on full roadmap"},
    ],
    "ecc_x": [
        {"target_algorithm": "Hybrid X25519MLKEM768 key exchange", "nist_standard": "NIST FIPS 203 / SP 800-186",
         "effort_estimate": "1 to 3 weeks", "latency_impact": "Low (~0.2ms)", "migration_cost": "Low",
         "risk_reduction": "High", "best_for": "Lowest latency TLS 1.3"},
        {"target_algorithm": "ML-KEM-768 pure (FIPS 203)", "nist_standard": "NIST FIPS 203",
         "effort_estimate": "3 to 6 weeks", "latency_impact": "Low", "migration_cost": "Medium",
         "risk_reduction": "Critical", "best_for": "No legacy ECC dependency"},
    ],
}


def family_from_rule(rule: dict, key_size: int) -> str:
    """Map a matched migration rule to a tradeoff family id."""
    tokens = rule.get("tokens", [])
    joined = " ".join(tokens)
    if any(t in joined for t in ("ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA", "FALCON", "X25519MLKEM")):
        return "pqc"
    if "MD5" in joined:
        return "md5"
    if "SHA-1" in joined or "SHA1" in joined:
        return "sha1"
    if any(t in joined for t in ("3DES", "DES", "RC4", "RC2", "BLOWFISH")):
        return "symmetric"
    if "ECB" in joined:
        return "ecb"
    if "DSA" in joined:
        return "dsa"
    if "ECDSA" in joined:
        return "ecdsa"
    if "RSA" in joined:
        key_max = rule.get("key_max")
        return "rsa_weak" if key_max and key_size <= key_max else "rsa_strong"
    return "ecc_x"


def attach_tradeoffs(recommendation: dict, family: str, tls_version: str) -> dict:
    """Attach latency / cost metadata and ranked alternatives to a playbook."""
    profile = MIGRATION_TRADEOFFS.get(family, [])
    rec = dict(recommendation)
    if profile:
        best = profile[0]
        rec["latency_impact"] = best["latency_impact"]
        rec["migration_cost"] = best["migration_cost"]
        rec["best_for"] = best["best_for"]
        rec["alternatives"] = profile
    else:
        rec["latency_impact"] = "Low"
        rec["migration_cost"] = "Low"
        rec["best_for"] = "Maintain current posture"
        rec["alternatives"] = []
    if tls_version and tls_version != "1.3":
        rec["latency_impact"] += " + TLS 1.3 protocol upgrade"
    return rec
