"""
Container Scanner Engine for Q-Guardian-v2

Scanner priority: Trivy -> Syft -> tag-inference heuristic.

IMPORTANT ON PROVENANCE: Trivy/Syft produce a REAL SBOM by inspecting the image
or filesystem. The heuristic path does NOT pull or unpack any image — it infers a
*likely* base-image crypto baseline from the image tag string. Every finding
therefore carries `detection_method` and `confidence` so heuristic estimates are
never mistaken for observed facts downstream (CBOM, dashboards, reconciliation).
"""

import json
import os
import re
import shutil
import subprocess
from typing import Dict, Any, List, Optional

# Plausible image-reference (name[:tag][@sha256:...]) — used to reject garbage
# input instead of silently synthesizing findings for a nonexistent target.
_IMAGE_REF_RE = re.compile(r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[\w.\-]+)?(?:@sha256:[0-9a-f]{64})?$", re.IGNORECASE)

# Known cryptographic and SSL/TLS packages of interest.
# `pqc_capable_min_version` = first release with NATIVE, standardized PQC support.
# Sources are noted inline; a sentinel of "999" means "no native PQC as of 2026".
CRYPTO_PACKAGES = {
    "openssl": {
        "primitive": "key-agreement",
        "description": "OpenSSL Core Library",
        # Native ML-KEM/ML-DSA/SLH-DSA shipped in OpenSSL 3.5.0 (Apr 2025). 3.0-3.4
        # need the external oqs-provider. source: openssl.org 3.5 release notes.
        "pqc_capable_min_version": "3.5.0",
    },
    "libcrypto": {
        "primitive": "key-agreement",
        "description": "OpenSSL libcrypto",
        "pqc_capable_min_version": "3.5.0",
    },
    "libssl": {
        "primitive": "key-agreement",
        "description": "OpenSSL libssl",
        "pqc_capable_min_version": "3.5.0",
    },
    "cryptography": {
        "primitive": "symmetric-cipher",
        "description": "Python Cryptographic Authority (pyca/cryptography)",
        # pyca/cryptography ships no PQC primitives as of 2026. source: cryptography changelog.
        "pqc_capable_min_version": "999",
    },
    "pycryptodome": {
        "primitive": "symmetric-cipher",
        "description": "PyCryptodome Library",
        "pqc_capable_min_version": "999",  # classical only
    },
    "bouncycastle": {
        "primitive": "signature",
        "description": "Legion of the Bouncy Castle Java Cryptography",
        # BC 1.77 exposes FIPS 203/204 (ML-KEM/ML-DSA). source: bouncycastle.org release notes.
        "pqc_capable_min_version": "1.77",
    },
    "bcprov-jdk15on": {
        "primitive": "signature",
        "description": "Bouncy Castle Provider jar",
        "pqc_capable_min_version": "1.77",
    },
    "golang.org/x/crypto": {
        "primitive": "key-agreement",
        "description": "Go Crypto Subrepository",
        # Only experimental hybrid KEMs in std crypto/tls; x/crypto has no
        # standardized PQC API. Treat as non-PQC to avoid a false green.
        "pqc_capable_min_version": "999",
    },
    "gnutls": {
        "primitive": "key-agreement",
        "description": "GNU Transport Layer Security Library",
        "pqc_capable_min_version": "999",  # no native standardized PQC as of 2026
    },
    "mbedtls": {
        "primitive": "key-agreement",
        "description": "ARM mbed TLS (formerly PolarSSL)",
        "pqc_capable_min_version": "999",  # no native standardized PQC as of 2026
    },
    "nss": {
        "primitive": "key-agreement",
        "description": "Mozilla Network Security Services",
        "pqc_capable_min_version": "999",  # only experimental X25519Kyber768
    },
    "ca-certificates": {
        "primitive": "related-crypto-material",
        "description": "System Certificate Authority Bundle",
        "pqc_capable_min_version": "999",  # a trust bundle, not a PQC-capable library
    },
}


def _parse_version_tuple(v_str: str):
    """Extract numeric components from a package version string."""
    nums = re.findall(r"\d+", v_str)
    return tuple(int(x) for x in nums[:3]) if nums else (0, 0, 0)


def _evaluate_container_package(pkg_name: str, version: str, location: str = "",
                                scan_method: str = "unknown",
                                confidence: str = "medium") -> Optional[Dict[str, Any]]:
    """Determine cryptographic risk profile for a discovered package.

    scan_method/confidence record HOW the package was observed:
      - trivy/syft + high  -> read from a real SBOM of the image/filesystem
      - heuristic-tag-inference + low -> inferred from the image tag (image not pulled)
    """
    pkg_lower = pkg_name.lower()
    matched_key = None
    for key in CRYPTO_PACKAGES:
        if key in pkg_lower:
            matched_key = key
            break

    if not matched_key:
        return None

    meta = CRYPTO_PACKAGES[matched_key]
    ver_parsed = _parse_version_tuple(version)
    pqc_min = _parse_version_tuple(meta["pqc_capable_min_version"])
    is_pqc = bool(pqc_min) and ver_parsed >= pqc_min

    # Assess classical and quantum security levels
    if "openssl" in matched_key or "libcrypto" in matched_key or "libssl" in matched_key:
        if ver_parsed < (1, 1, 1):
            classical_sec, qtri, compliance = 80, 15, False
            rec = f"URGENT: EOL {pkg_name} {version} has known high-severity CVEs and zero quantum resistance. Upgrade to OpenSSL 3.5+ (native ML-KEM)."
        elif ver_parsed < (3, 0, 0):
            classical_sec, qtri, compliance = 112, 35, False
            rec = f"Legacy OpenSSL {version} lacks any PQC support. Upgrade to OpenSSL 3.5+ for native ML-KEM/ML-DSA (FIPS 203/204)."
        elif ver_parsed < (3, 5, 0):
            classical_sec, qtri, compliance = 128, 60, True
            is_pqc = False
            rec = f"OpenSSL {version} is modern classical TLS but has NO native PQC. Upgrade to 3.5+ or build with the oqs-provider for ML-KEM-768."
        else:
            classical_sec, qtri, compliance = 256, 90, True
            is_pqc = True
            rec = f"OpenSSL {version} (>=3.5.0) provides native ML-KEM/ML-DSA quantum-safe key exchange."
    elif "bouncycastle" in matched_key or "bcprov" in matched_key:
        if is_pqc:
            classical_sec, qtri, compliance = 256, 95, True
            rec = f"BouncyCastle {version} exposes FIPS 203/204 (ML-KEM/ML-DSA)."
        else:
            classical_sec, qtri, compliance = 112, 45, False
            rec = f"BouncyCastle {version} predates FIPS-standardized PQC modules. Upgrade to 1.77+."
    elif "cryptography" in matched_key:
        if ver_parsed < (41, 0, 0):
            classical_sec, qtri, compliance = 112, 40, False
            rec = f"pyca/cryptography {version} is dated; it also ships no PQC primitives."
        else:
            classical_sec, qtri, compliance = 192, 70, True
            rec = f"pyca/cryptography {version} has modern classical primitives (no native PQC yet)."
    else:
        classical_sec, qtri, compliance = 112, 50, is_pqc
        rec = f"Inspect container package {pkg_name} {version} for PQC readiness."

    nist_level = 3 if is_pqc else 0

    return {
        "hostname": f"container:{pkg_name}:{version}",
        "tls_version": "N/A",
        "algorithm": f"{pkg_name}-{version}",
        "key_size": None,
        "cipher_suite": "N/A",
        "forward_secrecy": None,
        "cert_valid": None,
        "cert_expiry": None,
        "sensitivity_tier": "S2",
        "is_pqc": is_pqc,
        "policy_compliant": compliance,
        "qtri_score": qtri,
        "source_type": "container",
        "asset_type": "library",
        "evidence_file": location or f"container-image:{pkg_name}",
        "evidence_line": None,
        "evidence_function": f"package:{pkg_name}@{version}",
        "detection_method": scan_method,
        "confidence": confidence,
        "primitive": meta["primitive"],
        "classical_security_level": classical_sec,
        "nist_quantum_security_level": nist_level,
        "recommendation": rec,
    }


def scan_with_trivy_cli(target: str) -> Optional[List[Dict[str, Any]]]:
    """
    Execute AquaSecurity Trivy (preferred SBOM engine) and map every discovered
    package/version through the quantum-readiness lookup table. Returns REAL,
    high-confidence findings from an actual image/filesystem inspection.
    """
    local_trivy = os.path.join(os.path.dirname(__file__), "..", "..", ".tools", "trivy", "trivy.exe")
    trivy_bin = os.path.abspath(local_trivy) if os.path.exists(local_trivy) else shutil.which("trivy")
    if not trivy_bin:
        return None

    is_path = os.path.exists(target)
    subcmd = "fs" if is_path else "image"
    env = {**os.environ, "TRIVY_SKIP_DB_UPDATE": "1"}

    def _run(fmt: str) -> Optional[object]:
        cmd = [trivy_bin, subcmd, "--quiet", "--format", fmt]
        # Only the JSON (vuln) path needs a scanner/DB. The CycloneDX SBOM path
        # must NOT request vuln scanning or it would demand the (absent) DB and
        # break the advertised offline behavior.
        if not is_path and fmt == "json":
            cmd += ["--scanners", "vuln"]
        cmd.append(target)
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                                 env=env, encoding="utf-8", errors="replace")
            if res.returncode != 0 or not res.stdout.strip():
                return None
            return json.loads(res.stdout)
        except Exception:
            return None

    findings: List[Dict[str, Any]] = []

    # 1) Native JSON. Trivy emits a top-level OBJECT: {"Results": [{"Packages": ...}]}.
    data = _run("json")
    if isinstance(data, (dict, list)):
        results = data.get("Results", []) if isinstance(data, dict) else data
        for result in results or []:
            for pkg in result.get("Packages", []) or []:
                locations = pkg.get("Locations", []) or []
                loc = locations[0].get("Path", "") if locations else (result.get("Target", "") or target)
                finding = _evaluate_container_package(
                    pkg.get("Name", ""), pkg.get("Version", ""), loc,
                    scan_method="trivy", confidence="high")
                if finding:
                    findings.append(finding)
        if findings:
            return findings

    # 2) CycloneDX SBOM (DB-free, fully offline)
    data = _run("cyclonedx")
    if isinstance(data, dict):
        for comp in data.get("components", []) or []:
            purl = comp.get("purl", "")
            loc = f"{target}:{purl}" if purl else target
            finding = _evaluate_container_package(
                comp.get("name", ""), comp.get("version", ""), loc,
                scan_method="trivy", confidence="high")
            if finding:
                findings.append(finding)
        if findings:
            return findings

    return None


def scan_with_syft_cli(target: str) -> Optional[List[Dict[str, Any]]]:
    """Execute syft CLI and parse JSON output (real SBOM, high confidence)."""
    syft_path = shutil.which("syft")
    if not syft_path:
        return None

    cmd = [syft_path, target, "-o", "json"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                             encoding="utf-8", errors="replace")
        if res.returncode != 0 or not res.stdout.strip():
            return None
        data = json.loads(res.stdout)
    except Exception:
        return None

    findings = []
    for art in data.get("artifacts", []):
        locations = art.get("locations", [])
        loc_str = locations[0].get("path", "") if locations else ""
        finding = _evaluate_container_package(
            art.get("name", ""), art.get("version", ""), loc_str,
            scan_method="syft", confidence="high")
        if finding:
            findings.append(finding)
    return findings


def scan_container_heuristic(target: str) -> List[Dict[str, Any]]:
    """
    Tag-inference fallback used when no SBOM tool (Trivy/Syft) is available.

    For a Dockerfile it parses FROM/RUN lines as text. For an image reference it
    infers a LIKELY base-image crypto baseline from the tag string WITHOUT pulling
    the image. All findings are marked confidence="low" / heuristic so they are
    never presented as an inspected inventory.
    """
    findings: List[Dict[str, Any]] = []

    # Local Dockerfile / manifest
    if os.path.isfile(target):
        try:
            with open(target, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            for line_no, line in enumerate(content.splitlines(), start=1):
                from_match = re.search(r"^\s*FROM\s+([^\s]+)", line, re.IGNORECASE)
                if from_match:
                    findings.extend(_derive_base_image_crypto(from_match.group(1), target, line_no))
                if "apt-get install" in line or "apk add" in line or "yum install" in line:
                    for pkg in ["openssl", "libssl-dev", "ca-certificates", "gnutls"]:
                        if pkg in line:
                            f_item = _evaluate_container_package(
                                pkg, "unknown", f"{target}:{line_no}",
                                scan_method="dockerfile-parse", confidence="low")
                            if f_item:
                                findings.append(f_item)
            return findings
        except Exception:
            return findings

    # Image reference — validate before synthesizing anything.
    if not _IMAGE_REF_RE.match(target.strip()):
        return []
    findings.extend(_derive_base_image_crypto(target, target, 0))
    return findings


def _derive_base_image_crypto(image_tag: str, ref_file: str, line_no: int) -> List[Dict[str, Any]]:
    """Estimate a base-image crypto baseline from the tag string.

    NOTE: this does NOT pull, unpack or inspect the image. Versions are typical
    values for the named base image and may not match the real image. Every
    finding is stamped detection_method='heuristic-tag-inference', confidence='low'.
    """
    findings: List[Dict[str, Any]] = []
    tag = image_tag.lower()

    def _pkg(name, version, loc):
        return _evaluate_container_package(name, version, loc,
                                           scan_method="heuristic-tag-inference",
                                           confidence="low")

    if "alpine" in tag:
        ver = re.search(r"alpine:?(\d+\.\d+)?", tag)
        subver = ver.group(1) if ver and ver.group(1) else "3.19"
        if _parse_version_tuple(subver) <= (3, 17):
            findings.append(_pkg("openssl", "1.1.1u-r0", f"{image_tag}:/lib/libssl.so.1.1"))
        else:
            findings.append(_pkg("openssl", "3.1.4-r0", f"{image_tag}:/lib/libssl.so.3"))
        findings.append(_pkg("ca-certificates", "20230506-r0", f"{image_tag}:/etc/ssl/certs/ca-certificates.crt"))
    elif "nginx" in tag:
        findings.append(_pkg("openssl", "3.0.11", f"{image_tag}:/usr/lib/libcrypto.so.3"))
        findings.append(_pkg("libssl", "3.0.11", f"{image_tag}:/usr/lib/libssl.so.3"))
    elif "python" in tag:
        findings.append(_pkg("openssl", "3.0.13", f"{image_tag}:/usr/lib/x86_64-linux-gnu/libssl.so.3"))
        findings.append(_pkg("cryptography", "41.0.7", f"{image_tag}:/usr/local/lib/python3/site-packages/cryptography"))
    elif "golang" in tag or "go:" in tag:
        findings.append(_pkg("golang.org/x/crypto", "0.14.0", f"{image_tag}:go.mod"))
    elif "ubuntu" in tag or "debian" in tag:
        if "20.04" in tag or "buster" in tag:
            findings.append(_pkg("openssl", "1.1.1f", f"{image_tag}:/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1"))
        elif "22.04" in tag or "bullseye" in tag:
            findings.append(_pkg("openssl", "3.0.2", f"{image_tag}:/usr/lib/x86_64-linux-gnu/libcrypto.so.3"))
        else:
            findings.append(_pkg("openssl", "3.2.1", f"{image_tag}:/usr/lib/x86_64-linux-gnu/libcrypto.so.3"))
    else:
        findings.append(_pkg("openssl", "3.0.8", f"{image_tag}:/usr/lib/libcrypto.so.3"))
        findings.append(_pkg("ca-certificates", "2023.2.60", f"{image_tag}:/etc/ssl/certs/ca-certificates.crt"))

    for f in findings:
        if f is None:
            continue
        f["evidence_file"] = ref_file if ref_file != image_tag else f"image:{image_tag}"
        f["evidence_note"] = "version inferred from image tag; image not pulled/inspected"
        if line_no > 0:
            f["evidence_line"] = line_no

    return [f for f in findings if f]


def scan_container(target: str) -> List[Dict[str, Any]]:
    """
    Main entrypoint for container / manifest scanning.
    Scanner priority: Trivy (json -> cyclonedx) -> Syft -> tag-inference heuristic.
    """
    results = scan_with_trivy_cli(target)
    if results:
        return results

    results = scan_with_syft_cli(target)
    if results:
        return results

    return scan_container_heuristic(target)
