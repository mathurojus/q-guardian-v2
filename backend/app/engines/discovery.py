import ssl
import socket
import datetime
import json
import requests
import urllib3
from cryptography import x509
from app.settings import DISCOVERY_MAX_ASSETS
from app.engines.active_discovery import discover_active_surface
from app.net_guard import assert_target_allowed, TargetNotAllowed

_HTTP_HEADERS = {"User-Agent": "Q-Guardian-Discovery/2.0 (+quantum-risk-audit)"}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Sensitivity Tier Taxonomy (Phase 6) ──────────────────────────────────────
# Priority order: S1 (most critical) → S5 (public)
# Based on RBI classification guidelines for banking assets
TIER_TAXONOMY = {
    "S1": ["payment", "hsm", "kms", "crypto-key", "vault", "settlement", "core-engine", "auth-gateway"],
    "S2": ["auth", "login", "sso", "kyc", "identity", "oauth", "token", "biometric", "2fa", "otp"],
    "S3": ["account", "statement", "txn", "transaction", "history", "database", "ledger", "storage"],
    "S4": ["api", "internal", "vpn", "intranet", "admin", "mgmt", "manage", "gateway", "service"],
    "S5": ["www", "web", "portal", "public", "info", "static", "cdn", "media", "blog"],
}

def classify_sensitivity_tier(hostname: str, tls_data: dict, base_domain: str = "") -> str:
    """
    Classify an asset's RBI sensitivity tier using:
    1. Keyword taxonomy match (S1→S5 priority order)
    2. Apex domain rule (Minimum S3 for root domain)
    3. TLS-signal fallback for unclassified hostnames
    """
    hostname_lower = hostname.lower()
    base_domain_lower = base_domain.lower()

    # Step 1: Keyword taxonomy — check S1 and S2 (Higher priority than Apex)
    for tier in ["S1", "S2"]:
        for kw in TIER_TAXONOMY[tier]:
            if kw in hostname_lower:
                return tier

    # Step 2: Apex domain rule — root domain is at least S3
    if hostname_lower == base_domain_lower and base_domain_lower != "":
        return "S3"

    # Step 3: Check remaining keywords (S3, S4, S5)
    for tier in ["S3", "S4", "S5"]:
        for kw in TIER_TAXONOMY[tier]:
            if kw in hostname_lower:
                return tier

    # Step 4: TLS-signal fallback for unclassified hostnames
    tls_version = tls_data.get("tls_version", "Unknown")
    forward_secrecy = tls_data.get("forward_secrecy", False)
    cert_valid = tls_data.get("cert_valid", False)

    # No HTTPS / TLS completely unknown → lowest tier
    if not cert_valid or tls_version in ("Unknown", "1.0", "1.1", "TLSv1", "TLSv1.1"):
        return "S5"

    # HTTPS with TLS 1.3 + forward secrecy → assume internal/sensitive
    if tls_version in ("1.3", "TLSv1.3") and forward_secrecy:
        return "S3"

    # Everything else: treat as S4 (internal)
    return "S4"

def get_subdomains_from_crtsh(domain: str):
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url, timeout=10, headers=_HTTP_HEADERS)
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            for entry in data:
                subdomains.update(entry['name_value'].split('\n'))
            return list(subdomains)
    except Exception as e:
        print(f"Error fetching subdomains: {e}")
    return []

def get_real_tls_info(hostname: str):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    result = {
        "tls_version": "Unknown",
        "cipher_suite": "Unknown",
        "cert_expiry": datetime.datetime.now().isoformat(),
        "algorithm": "Unknown",
        "key_size": 0,
        "cert_valid": False,
        "forward_secrecy": False,
        "is_pqc": False,
        "error": None
    }
    
    try:
        ip = socket.gethostbyname(hostname)
    except Exception as e:
        result["error"] = "DNS Resolution Failed"
        return result

    try:
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bytes = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                
                result["tls_version"] = cipher[1]
                result["cipher_suite"] = cipher[0]
                
                # Check for forward secrecy
                if "EECDH" in cipher[0] or "DHE" in cipher[0] or "TLS_AES" in cipher[0] or "TLS_CHACHA20" in cipher[0]:
                    result["forward_secrecy"] = True
                    
                # Parse exact cert data securely
                loaded_cert = x509.load_der_x509_certificate(cert_bytes)
                public_key = loaded_cert.public_key()
                result["cert_expiry"] = loaded_cert.not_valid_after_utc.isoformat()
                
                # Check expiration explicitly
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                if loaded_cert.not_valid_before_utc <= now_utc <= loaded_cert.not_valid_after_utc:
                    result["cert_valid"] = True
                else:
                    result["cert_valid"] = False
                
                from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519
                if isinstance(public_key, rsa.RSAPublicKey):
                    result["algorithm"] = f"RSA-{public_key.key_size}"
                    result["key_size"] = public_key.key_size
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    result["algorithm"] = f"ECDSA-{public_key.curve.name}"
                    result["key_size"] = public_key.key_size
                elif isinstance(public_key, x25519.X25519PublicKey):
                    result["algorithm"] = "X25519"
                    result["key_size"] = 256
                else:
                    result["algorithm"] = public_key.__class__.__name__

                # Real hybrid PQC is negotiated in the KEY-EXCHANGE GROUP, not the
                # symmetric cipher-suite name. Read ssock.group() where available
                # (Python 3.13+); fall back gracefully on older runtimes.
                try:
                    group = ssock.group() if hasattr(ssock, "group") else None
                except Exception:
                    group = None
                if group:
                    result["negotiated_group"] = group
                    if any(k in group.upper() for k in ("KYBER", "MLKEM", "ML-KEM", "SNTRUP", "FRODO")):
                        result["is_pqc"] = True
    except Exception as e:
        result["error"] = str(e)
        
    return result

def scan_asset(hostname: str, base_domain: str = ""):
    tls_data = get_real_tls_info(hostname)
    
    if tls_data.get("error"):
        tls_version = "Unknown"
        algorithm = "Unknown"
        cipher_suite = "Unknown"
        forward_secrecy = False
        cert_valid = False
    else:
        tls_version = tls_data["tls_version"].replace("TLSv", "")
        algorithm = tls_data["algorithm"]
        cipher_suite = tls_data["cipher_suite"]
        forward_secrecy = tls_data["forward_secrecy"]
        cert_valid = tls_data["cert_valid"]
        
    # Classify sensitivity tier using keyword taxonomy + TLS signal fusion
    sensitivity = classify_sensitivity_tier(hostname, tls_data, base_domain)

    is_pqc = tls_data.get("is_pqc", False)

    # Trigger Active Surface Discovery (JS Crawling, Fuzzing, Spec Parsing)
    discovered_endpoints = discover_active_surface(hostname)

    return {
        "hostname": hostname,
        "tls_version": tls_version,
        "algorithm": algorithm,
        "key_size": tls_data.get("key_size", 0),
        "cipher_suite": cipher_suite,
        "forward_secrecy": forward_secrecy,
        "cert_valid": cert_valid,
        "cert_expiry": tls_data.get("cert_expiry") or datetime.datetime.now().isoformat(),
        "sensitivity_tier": sensitivity,
        "is_pqc": is_pqc,
        "policy_compliant": True if tls_version == "1.3" else False,
        "discovered_endpoints": discovered_endpoints
    }

def run_discovery(domain: str):
    # SSRF guard: refuse private/loopback/link-local (incl. cloud metadata).
    assert_target_allowed(domain)
    subdomains = get_subdomains_from_crtsh(domain)
    # Add domain itself if not in subdomains
    if domain not in subdomains:
        subdomains.insert(0, domain)
        
    results = []
    
    # Use setting to limit assets, if any
    scan_list = subdomains[:DISCOVERY_MAX_ASSETS] if DISCOVERY_MAX_ASSETS else subdomains
    
    for sub in scan_list:
        results.append(scan_asset(sub, domain))
    return results
