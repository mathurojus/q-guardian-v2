# Dynamic Q-TRI Weighting Matrix (Weights must sum to 1.0)
# S1/S2: Critical (PQC heavily weighted)
# S3: Balanced
# S4/S5: Operational (PQC is a bonus, not a requirement)

import re

TIER_CONFIG = {
    "S1": {"tls": 0.25, "fs": 0.20, "hygiene": 0.20, "cipher": 0.15, "pqc": 0.20},
    "S2": {"tls": 0.25, "fs": 0.20, "hygiene": 0.20, "cipher": 0.15, "pqc": 0.20},
    "S3": {"tls": 0.30, "fs": 0.20, "hygiene": 0.20, "cipher": 0.20, "pqc": 0.10},
    "S4": {"tls": 0.35, "fs": 0.25, "hygiene": 0.25, "cipher": 0.15, "pqc": 0.00}, # PQC 0 as it's bonus only
    "S5": {"tls": 0.35, "fs": 0.25, "hygiene": 0.25, "cipher": 0.15, "pqc": 0.00},
}

def _quantum_signal_cap(data: dict):
    """
    Q-TRI signal ingestion: cap the score when the real algorithm surface
    (from Semgrep / Trivy / network) is a quantum-vulnerable legacy family.
    Returns None when no cap applies.
    """
    if data.get("is_pqc"):
        return None
    try:
        nist_level = int(data.get("nist_quantum_security_level") or 0)
    except (TypeError, ValueError):
        nist_level = 0
    if nist_level >= 1:
        return None

    algo = str(data.get("algorithm", "")).upper()
    caps = []
    if re.search(r"MD5", algo):
        caps.append(20)          # collision + Grover halving
    if re.search(r"SHA-?1\b", algo):
        caps.append(35)          # deprecated 80-bit digest
    if re.search(r"(3DES|\bDES\b|RC4|RC2|BLOWFISH)", algo):
        caps.append(25)          # 56/64/112-bit symmetric legacy
    if "ECB" in algo:
        caps.append(40)          # unsafe mode (no authentication)
    if re.search(r"RSA-?(512|1024)", algo):
        caps.append(20)          # classically factorable
    try:
        key_size = int(data.get("key_size") or 0)
    except (TypeError, ValueError):
        key_size = 0
    if re.search(r"\bRSA\b", algo) and 0 < key_size < 2048:
        caps.append(25)
    if re.search(r"\bDSA\b", algo) and not re.search(r"ECDSA", algo):
        caps.append(30)          # discrete-log — Shor-vulnerable
    return min(caps) if caps else None


# Source types that are NOT live network endpoints — they have no TLS session,
# cipher suite or certificate, so scoring them on those factors is a category
# error (it structurally punishes a PQC binary/library). These are scored on the
# crypto primitive itself instead.
NON_NETWORK_SOURCES = {
    "static_code", "static-source", "binary", "container",
    "cloud_kms", "hardware_module", "kms", "hsm", "managed",
}


def _score_non_network(data: dict, cap):
    """Q-TRI for assets with no TLS surface: base on PQC status + legacy caps,
    without inventing or penalizing TLS/cipher/cert attributes."""
    if data.get("is_pqc"):
        base = 90
    else:
        try:
            nist_level = int(data.get("nist_quantum_security_level") or 0)
        except (TypeError, ValueError):
            nist_level = 0
        base = 80 if nist_level >= 1 else 60
    if data.get("policy_compliant"):
        base += 5
    if cap is not None:
        base = min(base, cap)
    return max(0, min(100, int(base)))


def calculate_qtri_score(data: dict):
    # Determine Tier (Default to S5 if missing)
    tier = data.get("sensitivity_tier", "S5")
    config = TIER_CONFIG.get(tier, TIER_CONFIG["S5"])

    # Non-network assets (source code, binaries, container libs, KMS/HSM keys)
    # are scored on the crypto primitive, not on absent TLS fields.
    if str(data.get("source_type", "")).lower() in NON_NETWORK_SOURCES:
        return _score_non_network(data, _quantum_signal_cap(data))

    # Check if host was even reachable
    if data.get("tls_version", "Unknown") in ("Unknown", None):
        return 0

    # 1. TLS Score (0.0 to 1.0)
    tls_ver = data.get("tls_version", "1.0")
    tls_val = 1.0 if tls_ver == "1.3" else (0.6 if tls_ver == "1.2" else 0.2)
    
    # 2. Forward Secrecy (0.0 or 1.0)
    fs_val = 1.0 if data.get("forward_secrecy", False) else 0.0
    
    # 3. Cert Hygiene (0.0 to 1.0)
    hygiene_val = 0.0
    if data.get("cert_valid", False):
        keysize = data.get("key_size", 0)
        if keysize >= 4096: hygiene_val = 1.0
        elif keysize >= 2048: hygiene_val = 0.7
        else: hygiene_val = 0.3
        
    # 4. Cipher Strength (0.0 to 1.0)
    cipher = data.get("cipher_suite", "")
    cipher_val = 1.0 if ("GCM" in cipher or "CHACHA20" in cipher) else 0.4
    
    # 5. PQC Adoption (0.0 or 1.0)
    pqc_val = 1.0 if data.get("is_pqc", False) else 0.0
    
    # Calculate Weighted Average
    final_score = (
        (tls_val * config["tls"]) +
        (fs_val * config["fs"]) +
        (hygiene_val * config["hygiene"]) +
        (cipher_val * config["cipher"]) +
        (pqc_val * config["pqc"])
    ) * 100

    # Q-TRI signal ingestion: cap on quantum-vulnerable algorithm families
    cap = _quantum_signal_cap(data)
    if cap is not None:
        final_score = min(final_score, cap)
    
    # 🎁 BONUS: For S4/S5, PQC acts as a raw bonus pts provider since it's not in the baseline
    if tier in ("S4", "S5") and pqc_val == 1.0:
        final_score += 15 # 15 point boost for early adoption on low-priority endpoints
        
    # Compliance modifier
    if data.get("policy_compliant", False):
        final_score += 5
        
    return max(0, min(100, int(final_score)))

def calculate_cyber_rating(qtri_scores: list, mosca_states: list = None):
    """Enterprise 0-1000 rating.

    Base = average Q-TRI (which already weights PQC adoption and caps legacy
    algorithms) scaled to 0-1000. It is then discounted by the share of assets
    that fall inside the Mosca risk window (X+Y > Z), so the headline number
    reflects the quantum-timeline math, not just static TLS hygiene.
    """
    if not qtri_scores:
        return 0
    avg_score = sum(qtri_scores) / len(qtri_scores)
    rating = avg_score * 10  # 0-100 -> 0-1000

    if mosca_states:
        at_risk = sum(1 for s in mosca_states if str(s).upper() in ("CRITICAL", "WARNING"))
        frac = at_risk / len(mosca_states)
        rating *= (1 - 0.25 * frac)  # up to a 25% haircut when the portfolio is in-window

    return int(max(0, min(1000, rating)))
