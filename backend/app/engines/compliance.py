# Regulatory Compliance Mapping Logic
import re

# Frameworks:
#   1. RBI baseline crypto controls — Indian banking (see RBI_* references below)
#   2. NIST IR 8547                  — Post-Quantum Cryptography transition
#   3. India DST/TEC (NQM)           — National Quantum Mission + TEC QSC guidance
#
# NIST IR 8547 "Transition to Post-Quantum Cryptography Standards" (initial public
# draft, 2024) sets the REAL, published transition dates: deprecate the current
# 112-bit-security quantum-vulnerable algorithms (e.g. RSA-2048, ECDSA P-256,
# ECDH, finite-field DH) AFTER 2030, and DISALLOW them AFTER 2035. It defines no
# "T1-T4" schedule. (The 2033 "exclusive use" date belongs to NSA CNSA 2.0 for
# National Security Systems, tracked separately.)
NIST_IR8547_MILESTONES = [
    {"milestone": "Deprecate 112-bit quantum-vulnerable algorithms (RSA-2048, ECDSA P-256, ECDH, FFDH)", "deadline": "after 2030"},
    {"milestone": "Disallow quantum-vulnerable algorithms", "deadline": "after 2035"},
]
CNSA2_NOTE = "NSA CNSA 2.0 requires exclusive PQC use for National Security Systems by 2033 (separate from NIST IR 8547)."

# Real RBI document references (there is no single doc branded "CSF 2.0").
RBI_BASELINE = ("RBI 'Cyber Security Framework in Banks' "
                "(DBS.CO/CSITE/BC.11/33.01.001/2015-16), Annex-1 Baseline Cyber "
                "Security and Resilience Requirements")
RBI_DPSC = "RBI Master Direction on Digital Payment Security Controls (2021)"

INDIA_TIMELINE = {
    "nqm_horizon": "2031",  # DST National Quantum Mission 2023-2031 scale-up window
    "frame": "DST National Quantum Mission (NQM) 2023-2031 / TEC Quantum-Safe Cryptography guidance",
}


def map_to_rbi_controls(assets: list):
    """Map only REAL cryptographic violations to RBI baseline crypto controls.

    TLS findings are restricted to assets that actually carry a TLS protocol
    (network endpoints, TLS libraries, key-agreement primitives) so that
    static/binary rows (hash constants, cipher blocks) are not mislabeled
    as "insecure TLS".
    """
    mapping = []
    for asset in assets:
        findings = []
        tls_ver = str(asset.get("tls_version") or "")
        algo = str(asset.get("algorithm", "")).upper()
        prim = str(asset.get("primitive", "")).lower()
        source = str(asset.get("source_type", "network_live")).lower()
        key_size = asset.get("key_size", 0) or 0

        tls_bearing = (
            tls_ver in ("1.0", "1.1", "1.2", "1.3", "2.0", "3.0", "SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
            or source == "network_live"
            or prim == "key-agreement"
            or "OPENSSL" in algo or "GNUTLS" in algo or "MBEDTLS" in algo or "NSS-" in algo
        )

        # 1. Legacy / insecure TLS protocols (TLS 1.0/1.1/SSLv2/3 only)
        if tls_ver in ("1.0", "1.1", "SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            findings.append({
                "control": f"{RBI_BASELINE} — encryption in transit (secure network configuration)",
                "description": f"Deprecated TLS protocol version {tls_ver} in use.",
                "remediation": "Upgrade to TLS 1.3 with PQC-ready cipher suites."
            })

        # 2. Weak public-key (sub-2048 RSA / legacy DSA)
        if "RSA" in algo and 0 < key_size < 2048:
            findings.append({
                "control": f"{RBI_BASELINE} — cryptographic controls / key management",
                "description": f"Weak RSA key size ({key_size}-bit).",
                "remediation": "Replace with 4096-bit RSA or PQC-equivalent (ML-KEM-768 / ML-DSA)."
            })

        # 3. Broken / legacy hash functions (MD5, SHA-1)
        if re.search(r"MD5", algo) or re.search(r"SHA-?1\b", algo):
            findings.append({
                "control": f"{RBI_BASELINE} — cryptographic controls / key management",
                "description": f"Broken/legacy hash function {algo} used for security-sensitive data.",
                "remediation": "Migrate to SHA-256/SHA-3 (FIPS 180-4 / FIPS 202) with HMAC where required."
            })

        # 4. Legacy symmetric ciphers / unsafe modes
        if re.search(r"(3DES|\bDES\b|RC4|RC2|BLOWFISH)", algo):
            findings.append({
                "control": f"{RBI_BASELINE} — cryptographic controls / key management",
                "description": f"Deprecated symmetric cipher {algo} in use.",
                "remediation": "Replace with AES-256-GCM or ChaCha20-Poly1305 (authenticated)."
            })
        elif "ECB" in algo:
            findings.append({
                "control": f"{RBI_BASELINE} — cryptographic controls / key management",
                "description": "AES-ECB: block cipher in unauthenticated Electronic Codebook mode.",
                "remediation": "Switch to AES-GCM (NIST SP 800-38D) with unique nonces."
            })

        # 5. Missing forward secrecy — only meaningful on TLS-bearing assets
        if tls_bearing and not asset.get("forward_secrecy", False):
            findings.append({
                "control": f"{RBI_DPSC} — protection of data in transit (forward secrecy)",
                "description": "Lack of Perfect Forward Secrecy (PFS) - HNDL Risk.",
                "remediation": "Enable ECDHE or DHE key exchange mechanism."
            })

        if findings:
            mapping.append({
                "hostname": asset["hostname"],
                "findings": findings
            })
    return mapping


def _is_quantum_risk(asset: dict) -> bool:
    """True when the asset carries a quantum-vulnerable primitive."""
    if asset.get("is_pqc"):
        return False
    try:
        nist_level = int(asset.get("nist_quantum_security_level") or 0)
    except (TypeError, ValueError):
        nist_level = 0
    if nist_level >= 1:
        return False
    algo = str(asset.get("algorithm", "")).upper()
    if any(t in algo for t in ("RSA", "DSA", "ECDSA", "ECDH", "MD5", "SHA-1", "SHA1", "DES", "3DES", "RC4")):
        return True
    return False


def _risk_state(asset: dict) -> str:
    mosca = asset.get("mosca") or {}
    if isinstance(mosca, str):
        try:
            import json
            mosca = json.loads(mosca)
        except Exception:
            mosca = {}
    return str(mosca.get("risk_state", "SAFE"))


def map_to_nist_ir8547(assets: list):
    """Per-asset NIST IR 8547 transition flags with milestone deadlines."""
    mapping = []
    for asset in assets:
        if not _is_quantum_risk(asset):
            continue
        risk_state = _risk_state(asset)
        tier = asset.get("sensitivity_tier", "S5")
        critical = risk_state == "CRITICAL" or tier in ("S1", "S2")

        milestone_flags = []
        for idx, m in enumerate(NIST_IR8547_MILESTONES):
            if critical:
                state = "AT-RISK"
            else:
                state = "OPEN" if idx == 0 else "TRACK"  # deprecate(2030)=OPEN, disallow(2035)=TRACK
            milestone_flags.append({"milestone": m["milestone"], "deadline": m["deadline"], "state": state})

        mapping.append({
            "hostname": asset.get("hostname", "unknown"),
            "source_type": asset.get("source_type", "network_live"),
            "algorithm": asset.get("algorithm", "UNKNOWN"),
            "key_size": asset.get("key_size", 0),
            "findings": [{
                "control": "NIST IR 8547 — Post-Quantum Cryptography Transition",
                "description": (
                    f"{asset.get('algorithm', 'UNKNOWN')} ({asset.get('key_size', 0)}-bit, "
                    f"{asset.get('source_type', 'network_live')}) is quantum-vulnerable "
                    f"({asset.get('primitive', 'unknown')} primitive, NIST level 0)."
                ),
                "remediation": asset.get("recommendation") or (
                    "Enroll asset in the NIST IR 8547 inventory and schedule hybrid PQC "
                    "deployment ahead of the priority migration deadline."
                ),
                "risk_state": risk_state,
                "timeline_flags": milestone_flags,
            }]
        })
    return mapping


def map_to_india_dst_tec(assets: list):
    """
    India DST/TEC alignment: National Quantum Mission (NQM) 2023-2031 closes the
    pre-CRQC window for strategic sectors (banking / telecom). Flags map each
    vulnerable asset to NQM/TEC planning horizons.
    """
    mapping = []
    for asset in assets:
        if not _is_quantum_risk(asset):
            continue
        tier = asset.get("sensitivity_tier", "S5")
        risk_state = _risk_state(asset)
        is_financial_core = tier in ("S1", "S2", "S3")

        flags = [{
            "milestone": "NQM Quantum-Safe Readiness",
            "deadline": f"Before {INDIA_TIMELINE['nqm_horizon']}",
            "state": "AT-RISK" if (is_financial_core or risk_state == "CRITICAL") else "OPEN",
        }]
        if asset.get("source_type") in ("container", "binary", "static-source"):
            flags.append({
                "milestone": "Supply-Chain Crypto Dependency Review",
                "deadline": "Rolling (CERT-In / TEC QSC)",
                "state": "OPEN",
            })

        mapping.append({
            "hostname": asset.get("hostname", "unknown"),
            "source_type": asset.get("source_type", "network_live"),
            "algorithm": asset.get("algorithm", "UNKNOWN"),
            "findings": [{
                "control": "India: DST National Quantum Mission + TEC QSC Guidance",
                "description": (
                    f"{asset.get('algorithm', 'UNKNOWN')} on a {tier} asset must transition "
                    f"before the NQM {INDIA_TIMELINE['nqm_horizon']} scale-up window closes the "
                    f"harvest-now-decrypt-later exposure window."
                ),
                "remediation": asset.get("recommendation") or (
                    "Align transition plan to NQM sectoral roadmaps; engage TEC "
                    "quantum-safe cryptography testbeds for telecom-grade validation."
                ),
                "risk_state": risk_state,
                "timeline_flags": flags,
            }]
        })
    return mapping


def map_to_all_frameworks(assets: list) -> dict:
    """Combine RBI CSF 2.0, NIST IR 8547 and India DST/TEC mappings with counts."""
    rbi = map_to_rbi_controls(assets)
    nist = map_to_nist_ir8547(assets)
    india = map_to_india_dst_tec(assets)
    return {
        "frameworks": {
            "rbi_csf_2": rbi,
            "nist_ir_8547": nist,
            "india_dst_tec": india,
        },
        "summary": {
            "rbi_csf_2": len(rbi),
            "nist_ir_8547": len(nist),
            "india_dst_tec": len(india),
            "total_flagged": len({a["hostname"] for fw in (rbi, nist, india) for a in fw}),
        }
    }
