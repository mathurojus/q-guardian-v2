"""
Semgrep Source Scanner Engine for Q-Guardian-v2
Executes Semgrep CLI with backend/rules/crypto.yml if available,
or runs a native high-speed AST/regex rule evaluator as a fallback.
Maps results to the unified DBAsset schema with source_type='static-source'.
"""

import ast
import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional

RULES_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "rules", "crypto.yml")

# Built-in specification for crypto rules defined in rules/crypto.yml
INTERNAL_RULES = [
    {
        "id": "python-crypto-weak-hash-md5",
        "lang": "python",
        "regex": r"(hashlib\.md5\s*\(|Crypto\.Hash\.MD5\.new\s*\()",
        "algorithm": "MD5",
        "primitive": "hash",
        "classical_sec": 64,
        "nist_level": 0,
        "qtri": 15,
        "recommendation": "Migrate to SHA-256 or SHA-3 (FIPS 202)."
    },
    {
        "id": "python-crypto-weak-hash-sha1",
        "lang": "python",
        "regex": r"(hashlib\.sha1\s*\(|Crypto\.Hash\.SHA1\.new\s*\()",
        "algorithm": "SHA-1",
        "primitive": "hash",
        "classical_sec": 80,
        "nist_level": 0,
        "qtri": 30,
        "recommendation": "Migrate to SHA-256, SHA-384 or SHA-512."
    },
    {
        "id": "python-crypto-weak-rsa-keysize",
        "lang": "python",
        "regex": r"(RSA\.generate\s*\(\s*(1024|512)\b|key_size\s*=\s*(1024|512)\b)",
        "algorithm": "RSA-1024",
        "primitive": "public-key-encryption",
        "classical_sec": 80,
        "nist_level": 0,
        "qtri": 10,
        "recommendation": "Upgrade to RSA-3072+ minimum for classical compliance or ML-KEM-768 for PQC."
    },
    {
        "id": "python-crypto-ecb-mode-cipher",
        "lang": "python",
        "regex": r"(AES\.MODE_ECB|modes\.ECB\s*\(\s*\))",
        "algorithm": "AES-ECB",
        "primitive": "symmetric-cipher",
        "classical_sec": 64,
        "nist_level": 1,
        "qtri": 25,
        "recommendation": "Switch to authenticated mode like AES-GCM or ChaCha20-Poly1305."
    },
    {
        "id": "python-crypto-weak-tls-protocol",
        "lang": "python",
        "regex": r"ssl\.(PROTOCOL_TLSv1\b|PROTOCOL_TLSv1_1\b|PROTOCOL_SSLv23\b|PROTOCOL_SSLv2\b|PROTOCOL_SSLv3\b)",
        "algorithm": "TLS-1.0/1.1",
        "primitive": "key-agreement",
        "classical_sec": 80,
        "nist_level": 0,
        "qtri": 20,
        "recommendation": "Enforce TLSv1.3 with quantum-safe hybrid key exchange (X25519MLKEM768)."
    },
    {
        "id": "python-crypto-insecure-prng",
        "lang": "python",
        "regex": r"random\.(random|randint|choice|randrange|getrandbits|shuffle|sample)\s*\(",
        # Only a finding when used in a security context — random.choice() for
        # non-crypto purposes (tests, jitter, sampling) is not a weakness. This
        # keeps precision high on ordinary codebases.
        "context_keywords": ["key", "nonce", "salt", "token", "password", "passwd",
                              "secret", "iv", "otp", "seed", "session", "csrf", "apikey"],
        "algorithm": "PRNG-MERSENNE-TWISTER",
        "primitive": "random",
        "classical_sec": 0,
        "nist_level": 0,
        "qtri": 35,
        "recommendation": "Use the secrets module or os.urandom() for keys, nonces, tokens and salts."
    },
    {
        "id": "java-crypto-weak-hash-md5",
        "lang": "java",
        "regex": r'MessageDigest\.getInstance\s*\(\s*"MD5"',
        "algorithm": "MD5",
        "primitive": "hash",
        "classical_sec": 64,
        "nist_level": 0,
        "qtri": 15,
        "recommendation": "Use MessageDigest.getInstance(\"SHA-256\")."
    },
    {
        "id": "java-crypto-weak-hash-sha1",
        "lang": "java",
        "regex": r'MessageDigest\.getInstance\s*\(\s*"SHA-?1"',
        "algorithm": "SHA-1",
        "primitive": "hash",
        "classical_sec": 80,
        "nist_level": 0,
        "qtri": 30,
        "recommendation": "Use MessageDigest.getInstance(\"SHA-384\") or SHA-512."
    },
    {
        "id": "java-crypto-weak-cipher-des",
        "lang": "java",
        "regex": r'Cipher\.getInstance\s*\(\s*"DES(ede)?(/[^"]*)?"',
        "algorithm": "DES/3DES",
        "primitive": "symmetric-cipher",
        "classical_sec": 56,
        "nist_level": 0,
        "qtri": 18,
        "recommendation": "Replace with Cipher.getInstance(\"AES/GCM/NoPadding\")."
    },
    {
        "id": "java-crypto-weak-rsa-keypair",
        "lang": "java",
        "regex": r'KeyPairGenerator\.getInstance\s*\(\s*"RSA"',
        "algorithm": "RSA",
        "primitive": "public-key-encryption",
        "classical_sec": 112,
        "nist_level": 0,
        "qtri": 45,
        "recommendation": "Adopt Bouncy Castle PQC provider with Kyber/Dilithium or RSA-3072+."
    }
]

def scan_file_with_rules(filepath: str) -> List[Dict[str, Any]]:
    """Scan a single source file against ruleset."""
    ext = os.path.splitext(filepath)[1].lower()
    target_lang = "python" if ext in [".py"] else ("java" if ext in [".java"] else None)
    if not target_lang:
        return []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return []

    findings = []
    base_name = os.path.basename(filepath)

    for line_idx, line_content in enumerate(lines, start=1):
        stripped = line_content.strip()
        if stripped.startswith(("#", "//", "*")):
            continue
        for rule in INTERNAL_RULES:
            if rule["lang"] != target_lang:
                continue
            if not re.search(rule["regex"], line_content, re.IGNORECASE):
                continue
            ctx = rule.get("context_keywords")
            if ctx and not any(k in line_content.lower() for k in ctx):
                continue  # PRNG etc. only in a security context
            key_size = 1024 if rule["algorithm"] in ("RSA-1024",) else None
            findings.append({
                "hostname": f"src:{base_name}:{line_idx}",
                "tls_version": "N/A",
                "algorithm": rule["algorithm"],
                "key_size": key_size,
                "cipher_suite": "N/A",
                "forward_secrecy": None,
                "cert_valid": None,
                "cert_expiry": None,
                "sensitivity_tier": "S2",
                "is_pqc": False,
                "policy_compliant": False,
                "qtri_score": rule["qtri"],
                "source_type": "static-source",
                "asset_type": "library",
                "evidence_file": filepath,
                "evidence_line": line_idx,
                "evidence_offset": None,
                "evidence_function": rule["id"],
                "detection_method": "internal-regex",
                "primitive": rule["primitive"],
                "classical_security_level": rule["classical_sec"],
                "nist_quantum_security_level": rule["nist_level"],
                "recommendation": rule["recommendation"]
            })
    return findings

def scan_with_semgrep_cli(target_path: str) -> Optional[List[Dict[str, Any]]]:
    """Execute Semgrep CLI if available."""
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        return None

    rule_path = os.path.abspath(RULES_FILE)
    if not os.path.exists(rule_path):
        return None

    cmd = [semgrep_bin, "--config", rule_path, "--json", "--quiet",
           "--metrics=off", target_path]
    try:
        # CRITICAL: force UTF-8 decoding. On Windows the default (cp1252) raises
        # UnicodeDecodeError on Semgrep's UTF-8 JSON, which used to be swallowed
        # and silently degraded the whole engine to the weaker regex fallback.
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                             encoding="utf-8", errors="replace")
        if res.returncode not in (0, 1) or not res.stdout.strip():
            print(f"[source_scanner] Semgrep CLI unusable (rc={res.returncode}); "
                  f"falling back to internal rules. stderr: {res.stderr[:200]}")
            return None
        data = json.loads(res.stdout)
    except Exception as e:
        print(f"[source_scanner] Semgrep CLI failed ({e!r}); falling back to internal rules.")
        return None

    findings = []
    for r in data.get("results", []):
        check_id = r.get("check_id", "semgrep-rule")
        path = r.get("path", target_path)
        start_line = r.get("start", {}).get("line", 1)
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        msg = extra.get("message", "")

        findings.append({
            "hostname": f"src:{os.path.basename(path)}:{start_line}",
            "tls_version": "N/A",
            "algorithm": meta.get("algorithm", "UNKNOWN"),
            "key_size": meta.get("key_size"),
            "cipher_suite": "N/A",
            "forward_secrecy": None,
            "cert_valid": None,
            "cert_expiry": None,
            "sensitivity_tier": "S2",
            "is_pqc": False,
            "policy_compliant": False,
            "qtri_score": meta.get("qtri_score", 30),
            "source_type": "static-source",
            "asset_type": "library",
            "evidence_file": path,
            "evidence_line": start_line,
            "evidence_function": check_id,
            "detection_method": "semgrep-cli",
            "primitive": meta.get("primitive", "unknown"),
            "classical_security_level": meta.get("classical_security", 80),
            "nist_quantum_security_level": meta.get("quantum_security", 0),
            "recommendation": meta.get("recommendation", msg)
        })
    return findings

def scan_semgrep(target_path: str) -> List[Dict[str, Any]]:
    """
    Main entrypoint for Semgrep static source code scanning.
    Tries external Semgrep binary first; falls back to internal rule scanner.
    """
    cli_findings = scan_with_semgrep_cli(target_path)
    if cli_findings is not None:
        return cli_findings

    # Fallback to direct rules scanner
    if os.path.isfile(target_path):
        return scan_file_with_rules(target_path)
    elif os.path.isdir(target_path):
        all_findings = []
        ignore_dirs = {".git", "node_modules", "__pycache__", "venv", ".venv",
                       "dist", "build", ".tox", "site-packages", "target"}
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for fname in files:
                if fname.endswith((".py", ".java")):
                    full_p = os.path.join(root, fname)
                    all_findings.extend(scan_file_with_rules(full_p))
        return all_findings
    return []
