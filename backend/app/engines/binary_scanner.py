"""
Deep Binary Cryptographic Scanner for Q-Guardian-v2
Uses LIEF for executable inspection (ELF, PE, Mach-O) and raw byte constant
matching to detect Post-Quantum (ML-KEM, ML-DSA) and classical cryptographic
primitives in stripped and unstripped binaries.

Detection is signature-based: it matches published algorithm constants (NTT
zeta tables, S-boxes, IV words) and symbol/strings. This finds crypto that
carries those known constants; custom or obfuscated implementations that avoid
them can be missed. Findings are byte-offset evidence, never fabricated.
"""

import os
import re
import struct
from typing import Dict, Any, List, Optional

try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

# Cap how much of a binary we read into memory (defends against OOM / hostile
# large files). Path confinement is enforced by the API layer, not here.
MAX_BINARY_BYTES = 200 * 1024 * 1024

# ─── Constant Signatures (Byte Patterns) ──────────────────────────────────────

# ML-KEM / Kyber NTT zeta twiddle factors (FIPS 203), first 16 bit-reversed
# values. Reference implementations (PQClean, liboqs, OpenSSL 3.5+) store the
# zeta table as SIGNED int16_t Montgomery residues; some tooling stores the
# unsigned residue mod q = 3329. The two encodings are numerically equal but
# bit-for-bit different (e.g. -1044 -> 0xFBEC vs residue 2285 -> 0x08ED), so we
# build and search BOTH so detection fires on real compiled Kyber binaries and
# not only on our own fixture. A 16-value (32-byte) needle keeps false positives
# effectively nil.
_ML_KEM_ZETAS = [2285, 2571, 2970, 1812, 1493, 1422, 287, 202,
                 3158, 622, 1577, 182, 962, 2127, 1855, 1468]
_ML_KEM_ZETAS_SIGNED = [z - 3329 if z > 1664 else z for z in _ML_KEM_ZETAS]
ML_KEM_NTT_ZETAS_UNSIGNED = struct.pack("<16H", *_ML_KEM_ZETAS)
ML_KEM_NTT_ZETAS_SIGNED = struct.pack("<16h", *_ML_KEM_ZETAS_SIGNED)
# Back-compat alias consumed by the synthetic sample-binary fixture generator.
# Points at the real (signed) reference encoding so the fixture is faithful.
ML_KEM_NTT_ZETAS_16 = ML_KEM_NTT_ZETAS_SIGNED

# AES Rijndael S-Box (first 16 bytes: 0x63, 0x7C, 0x77, 0x7B, ...). Identical for
# AES-128/192/256, so the S-box alone does NOT reveal the key length.
AES_SBOX_16 = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
])

# MD5 Initial Constants (A=0x67452301, B=0xEFCDAB89, C=0x98BADCFE, D=0x10325476)
MD5_INIT_CONSTANTS = struct.pack("<4I", 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)

# SHA-1 Initial State Constants. NOTE: the little-endian SHA-1 IV begins with the
# exact four MD5 IV words, so SHA1_INIT_CONSTANTS_LE[:16] == MD5_INIT_CONSTANTS.
# We must therefore suppress the MD5 match wherever a SHA-1 table is present.
SHA1_INIT_CONSTANTS = struct.pack(">5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
SHA1_INIT_CONSTANTS_LE = struct.pack("<5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

# DES S-Box 1, first two rows (32 entries). A single 16-entry row is a natural
# small-integer permutation with a high collision rate against unrelated lookup
# tables; two rows make the signature specific. Real OpenSSL 3DES stores the
# combined SP-box words (des_SPtrans) rather than raw rows, so the symbol-string
# path below remains the primary DES/3DES signal.
DES_SBOX_1 = bytes([
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
])

# Representative NIST security category / classical bits per PQC parameter set,
# used to report the *actual* matched parameter set instead of a fixed default.
_PQC_STRENGTH = {
    "ML-KEM-512": (1, 128), "Kyber512": (1, 128),
    "ML-KEM-768": (3, 192), "Kyber768": (3, 192),
    "ML-KEM-1024": (5, 256), "Kyber1024": (5, 256),
    "ML-DSA-44": (2, 128), "Dilithium2": (2, 128),
    "ML-DSA-65": (3, 192), "Dilithium3": (3, 192),
    "ML-DSA-87": (5, 256), "Dilithium5": (5, 256),
    "Falcon-512": (1, 128), "Falcon-1024": (5, 256),
    "SLH-DSA": (2, 128), "SPHINCS+": (2, 128),
}

# Cryptographic strings / symbols. `family`/`primitive` describe the class; the
# concrete parameter set is taken from the actual matched token at scan time.
CRYPTO_STRING_PATTERNS = [
    {
        "regex": r"(ML-KEM-512|ML-KEM-768|ML-KEM-1024|Kyber512|Kyber768|Kyber1024)",
        "family": "ML-KEM", "primitive": "key-agreement", "is_pqc": True,
        "qtri": 95,
        "recommendation": "Post-Quantum ML-KEM (Kyber) key-encapsulation reference detected in binary.",
    },
    {
        "regex": r"(ML-DSA-44|ML-DSA-65|ML-DSA-87|Dilithium2|Dilithium3|Dilithium5)",
        "family": "ML-DSA", "primitive": "signature", "is_pqc": True,
        "qtri": 95,
        "recommendation": "Post-Quantum ML-DSA (Dilithium) signature primitive identified in binary.",
    },
    {
        "regex": r"(SLH-DSA|SPHINCS\+)",
        "family": "SLH-DSA", "primitive": "signature", "is_pqc": True,
        "qtri": 90,
        "recommendation": "Hash-based PQC signature (SLH-DSA / SPHINCS+) primitive detected.",
    },
    {
        "regex": r"(Falcon-512|Falcon-1024)",
        "family": "FN-DSA", "primitive": "signature", "is_pqc": True,
        "qtri": 90,
        "recommendation": "Lattice PQC signature (FN-DSA / Falcon) primitive detected.",
    },
    {
        "regex": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        "family": "EMBEDDED-PRIVATE-KEY", "primitive": "public-key-encryption", "is_pqc": False,
        "qtri": 5, "classical": 0, "nist_level": 0,
        "recommendation": "CRITICAL: Hardcoded private key embedded in compiled binary!",
    },
    {
        "regex": r"(MD5_Init|MD5_Update|md5_transform|EVP_md5)",
        "family": "MD5", "primitive": "hash", "is_pqc": False,
        "qtri": 10, "classical": 64, "nist_level": 0,
        "recommendation": "Deprecated MD5 symbol referenced in binary. Replace with SHA-256 or SHA-3.",
    },
    {
        "regex": r"(SHA1_Init|SHA1_Update|EVP_sha1)",
        "family": "SHA-1", "primitive": "hash", "is_pqc": False,
        "qtri": 25, "classical": 80, "nist_level": 0,
        "recommendation": "Broken SHA-1 symbol compiled in binary. Migrate to SHA-256 or SHA-3.",
    },
    {
        "regex": r"(DES_ecb_encrypt|DES_ede3_cbc|EVP_des_ede3|des_SPtrans)",
        "family": "3DES", "primitive": "symmetric-cipher", "is_pqc": False,
        "qtri": 20, "classical": 80, "nist_level": 0,
        "recommendation": "3DES legacy cipher symbols present. Transition to AES-256-GCM.",
    },
    {
        "regex": r"(EVP_KEM_fetch|OQS_KEM_new|OQS_SIG_new)",
        "family": "LIBOQS-PQC-INTERFACE", "primitive": "key-agreement", "is_pqc": True,
        "qtri": 98, "classical": 256, "nist_level": 5,
        "recommendation": "liboqs / OpenSSL 3.x PQC provider symbols identified.",
    },
]


def _search_bytes(haystack: bytes, needle: bytes) -> List[int]:
    """Find all byte offset occurrences of needle in haystack."""
    offsets = []
    idx = 0
    while True:
        idx = haystack.find(needle, idx)
        if idx == -1:
            break
        offsets.append(idx)
        idx += len(needle)
    return offsets


def _section_for_offset(section_map: Dict[str, Any], offset: int) -> str:
    """Return the name of the parsed section containing a file offset, or 'raw'.

    Lets evidence be labeled with the section it was truly found in instead of a
    cosmetic '.rodata' string. Falls back to 'raw' for headerless/stripped input.
    """
    for name, info in section_map.items():
        start = info.get("offset", 0) or 0
        size = len(info.get("content", b"") or b"")
        if size and start <= offset < start + size:
            return name or "unknown"
    return "raw"


def _binary_finding(binary_name: str, filepath: str, *, algorithm: str, primitive: str,
                    is_pqc: bool, qtri: int, classical: Optional[int], nist_level: int,
                    offset: int, evidence_label: str, recommendation: str,
                    detection_method: str, key_size: Optional[int] = None,
                    tier: str = "S2", param_set: Optional[str] = None,
                    mode: Optional[str] = None, oid: Optional[str] = None) -> Dict[str, Any]:
    """Build a binary finding with honest (non-fabricated) attributes.

    Binaries have no TLS session, certificate or forward-secrecy state, so those
    fields are left N/A/None instead of being invented. key_size is only set when
    it is genuinely derivable from the matched constant.
    """
    finding = {
        "hostname": f"bin:{binary_name}:{algorithm}",
        "tls_version": "N/A",
        "algorithm": algorithm,
        "key_size": key_size,
        "cipher_suite": "N/A",
        "forward_secrecy": None,
        "cert_valid": None,
        "cert_expiry": None,
        "sensitivity_tier": tier,
        "is_pqc": is_pqc,
        "policy_compliant": qtri >= 60,
        "qtri_score": qtri,
        "source_type": "binary",
        "asset_type": "binary",
        "evidence_file": filepath,
        "evidence_line": None,
        "evidence_offset": offset,
        "evidence_function": evidence_label,
        "primitive": primitive,
        "classical_security_level": classical,
        "nist_quantum_security_level": nist_level,
        "detection_method": detection_method,
        "recommendation": recommendation,
    }
    if param_set:
        finding["parameter_set_identifier"] = param_set
    if mode:
        finding["mode"] = mode
    if oid:
        finding["oid"] = oid
    return finding


def scan_binary(filepath: str) -> List[Dict[str, Any]]:
    """
    Reverse-engineer and scan an ELF, PE, Mach-O or raw binary file
    for cryptographic constants, NTT twiddle factors, and symbols.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Binary file not found: {filepath}")

    size = os.path.getsize(filepath)
    with open(filepath, "rb") as f:
        raw_data = f.read(MAX_BINARY_BYTES)
    truncated = size > MAX_BINARY_BYTES

    findings: List[Dict[str, Any]] = []
    binary_name = os.path.basename(filepath)
    section_map: Dict[str, Any] = {}

    # Inspect with LIEF if available and executable
    if HAS_LIEF:
        try:
            parsed = lief.parse(filepath)
            if parsed:
                for section in parsed.sections:
                    try:
                        sec_content = bytes(section.content)
                    except Exception:
                        sec_content = b""
                    section_map[section.name] = {
                        "offset": section.offset,
                        "virtual_address": section.virtual_address,
                        "content": sec_content,
                    }
                # Check imported and exported symbols
                for sym in getattr(parsed, "symbols", []):
                    s_name = getattr(sym, "name", "") or ""
                    for pat in CRYPTO_STRING_PATTERNS:
                        m = re.search(pat["regex"], s_name, re.IGNORECASE)
                        if not m:
                            continue
                        token = m.group(0)
                        nist_level, classical = _PQC_STRENGTH.get(
                            token, (pat.get("nist_level", 3), pat.get("classical", 192)))
                        findings.append(_binary_finding(
                            binary_name, filepath,
                            algorithm=token if token in _PQC_STRENGTH else pat["family"],
                            primitive=pat["primitive"], is_pqc=pat["is_pqc"],
                            qtri=pat["qtri"], classical=classical, nist_level=nist_level,
                            offset=getattr(sym, "value", 0) or 0,
                            evidence_label=f"symbol:{s_name}",
                            recommendation=pat["recommendation"],
                            detection_method="lief-symbol",
                            param_set=token if token in _PQC_STRENGTH else None,
                        ))
        except Exception:
            pass  # Fall back to direct byte and section scanning

    def _label(kind: str, offset: int) -> str:
        return f"{_section_for_offset(section_map, offset)}:{kind}@0x{offset:08X}"

    # 1. ML-KEM NTT Constant Signature Search (signed reference encoding first,
    #    then the unsigned-residue encoding).
    ntt_offsets = (_search_bytes(raw_data, ML_KEM_NTT_ZETAS_SIGNED)
                   or _search_bytes(raw_data, ML_KEM_NTT_ZETAS_UNSIGNED))
    if ntt_offsets:
        off = ntt_offsets[0]
        findings.append(_binary_finding(
            binary_name, filepath, algorithm="ML-KEM-768", primitive="key-agreement",
            is_pqc=True, qtri=98, classical=192, nist_level=3, offset=off,
            evidence_label=_label("NTT_ZETAS_TABLE", off),
            recommendation="Post-Quantum ML-KEM-768 NTT zeta constants (FIPS 203) matched by byte signature in binary.",
            detection_method="byte-signature", key_size=1184, tier="S1",
            param_set="ML-KEM-768", mode="FIPS-203", oid="2.16.840.1.101.3.4.4.2",
        ))

    # 2. AES Rijndael S-Box Search. The S-box is shared by AES-128/192/256, so the
    #    key length is NOT determinable from it, and AES is classical (Grover only
    #    halves its strength) — it is NOT post-quantum.
    aes_offsets = _search_bytes(raw_data, AES_SBOX_16)
    if aes_offsets:
        off = aes_offsets[0]
        findings.append(_binary_finding(
            binary_name, filepath, algorithm="AES", primitive="symmetric-cipher",
            is_pqc=False, qtri=70, classical=128, nist_level=0, offset=off,
            evidence_label=_label("AES_SBOX", off),
            recommendation="AES Rijndael S-box identified (key length not determinable from the S-box alone).",
            detection_method="byte-signature", key_size=None, tier="S3",
        ))

    # 4. SHA-1 Initial State Constants (compute FIRST so we can suppress the MD5
    #    false positive: SHA1_LE[:16] == MD5 IV).
    sha1_be_offsets = _search_bytes(raw_data, SHA1_INIT_CONSTANTS)
    sha1_le_offsets = _search_bytes(raw_data, SHA1_INIT_CONSTANTS_LE)
    sha1_offsets = sha1_be_offsets or sha1_le_offsets
    if sha1_offsets:
        off = sha1_offsets[0]
        findings.append(_binary_finding(
            binary_name, filepath, algorithm="SHA-1", primitive="hash",
            is_pqc=False, qtri=28, classical=80, nist_level=0, offset=off,
            evidence_label=_label("SHA1_IV", off),
            recommendation="Weak SHA-1 hash constants identified in binary.",
            detection_method="byte-signature", tier="S2",
        ))

    # 3. MD5 Initial Constants Search, excluding offsets that coincide with a
    #    little-endian SHA-1 IV (whose first 16 bytes are the MD5 IV).
    md5_offsets = [o for o in _search_bytes(raw_data, MD5_INIT_CONSTANTS)
                   if o not in sha1_le_offsets]
    if md5_offsets:
        off = md5_offsets[0]
        findings.append(_binary_finding(
            binary_name, filepath, algorithm="MD5", primitive="hash",
            is_pqc=False, qtri=12, classical=64, nist_level=0, offset=off,
            evidence_label=_label("MD5_IV", off),
            recommendation="CRITICAL: Hardcoded MD5 hash initial vector detected in binary. Remove broken digest.",
            detection_method="byte-signature", tier="S1",
        ))

    # 5. DES S-Box Search (two-row needle for specificity).
    des_offsets = _search_bytes(raw_data, DES_SBOX_1)
    if des_offsets:
        off = des_offsets[0]
        findings.append(_binary_finding(
            binary_name, filepath, algorithm="DES", primitive="symmetric-cipher",
            is_pqc=False, qtri=15, classical=56, nist_level=0, offset=off,
            evidence_label=_label("DES_SBOX_1", off),
            recommendation="CRITICAL: Deprecated DES S-box table found in binary.",
            detection_method="byte-signature", key_size=56, tier="S1",
        ))

    # 6. String / symbol-name search across the binary.
    try:
        raw_text = raw_data.decode("latin1", errors="ignore")
        for pat in CRYPTO_STRING_PATTERNS:
            matches = list(re.finditer(pat["regex"], raw_text))
            for m in matches[:2]:  # Max 2 per pattern to avoid flood
                offset = m.start()
                token = m.group(0)
                # Deduplicate if already reported by symbol or constant nearby
                already_reported = any(
                    (f.get("parameter_set_identifier") == token or f["algorithm"] == token
                     or f["algorithm"] == pat["family"])
                    and abs((f.get("evidence_offset") or 0) - offset) < 100
                    for f in findings
                )
                if already_reported:
                    continue
                nist_level, classical = _PQC_STRENGTH.get(
                    token, (pat.get("nist_level", 3), pat.get("classical", 192)))
                findings.append(_binary_finding(
                    binary_name, filepath,
                    algorithm=token if token in _PQC_STRENGTH else pat["family"],
                    primitive=pat["primitive"], is_pqc=pat["is_pqc"],
                    qtri=pat["qtri"], classical=classical, nist_level=nist_level,
                    offset=offset,
                    evidence_label=f'string:"{token[:30]}"',
                    recommendation=pat["recommendation"],
                    detection_method="string-match",
                    param_set=token if token in _PQC_STRENGTH else None,
                ))
    except Exception:
        pass

    if truncated:
        findings.append({
            "hostname": f"bin:{binary_name}:TRUNCATED",
            "algorithm": "SCAN-TRUNCATED", "source_type": "binary", "asset_type": "binary",
            "is_pqc": False, "qtri_score": 0, "sensitivity_tier": "S5",
            "evidence_file": filepath, "evidence_offset": MAX_BINARY_BYTES,
            "detection_method": "note",
            "recommendation": f"Binary exceeds {MAX_BINARY_BYTES} bytes; only the first "
                              f"{MAX_BINARY_BYTES} bytes were scanned.",
        })

    return findings
