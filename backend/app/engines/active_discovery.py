import requests
import re
import time
from urllib.parse import urljoin, urlparse
import urllib3
from app.net_guard import assert_target_allowed, TargetNotAllowed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_UA = {"User-Agent": "Q-Guardian-Discovery/2.0 (+authorized-testing-only)"}
_PER_HOST_BUDGET_SECONDS = 25  # wall-clock cap so a host can't stall the scan

# 🌐 Enterprise Critical-Infrastructure Wordlist
ENTERPRISE_API_WORDLIST = [
    # General API versions
    "api", "v1", "v2", "v3", "api/v1", "api/v2", "api/v3", "rest/v1",
    
    # Auth & Identity
    "auth", "login", "sso", "identity", "oauth", "token", "authorize", "kms", "vault",
    
    # Core Services & APIs
    "core", "transfer", "payment", "accounts", "ledger", "statement", "kyc", "biometric",
    "services", "gateway", "crypto", "keys", "hsm", "signing",
    
    # Management & Documentation
    "admin", "manage", "mgmt", "config", "health", "metrics", "status",
    "swagger.json", "openapi.json", "v2/api-docs", "docs", "graphql", "sandbox"
]

# 🔍 Regex for extracting paths/endpoints from JS/HTML content
# Matches strings starting with / containing alphanumeric chars, dots, dashes, slashes
# Length limited to avoid catching common small strings
PATH_EXTRACT_REGEX = r'(?:["\'])(\/[a-zA-Z0-9\.\-\_\/]{4,})(?:["\'])'

def discover_active_surface(base_url: str):
    """
    Performs active discovery (Spec parsing, JS extraction, Fuzzing)
    against a given hostname/base_url.
    """
    discovered_endpoints = set()

    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    # SSRF guard: refuse private/loopback/link-local targets.
    try:
        assert_target_allowed(base_url)
    except TargetNotAllowed:
        return []

    base_host = urlparse(base_url).hostname
    deadline = time.time() + _PER_HOST_BUDGET_SECONDS

    try:
        # 1. Fetch Root Page for JS Crawling
        response = requests.get(base_url, timeout=5, verify=False, headers=_UA)
        if response.status_code == 200:
            # Extract paths from HTML directly
            found_paths = re.findall(PATH_EXTRACT_REGEX, response.text)
            for path in found_paths:
                if not path.endswith((".png", ".jpg", ".css", ".svg", ".ico", ".woff", ".woff2")):
                    discovered_endpoints.add(path)

            # Extract and fetch Scripts — same host only (avoid SSRF via absolute src)
            scripts = re.findall(r'<script.*?src=["\'](.*?)["\']', response.text)
            for script_url in scripts:
                full_script_url = urljoin(base_url, script_url)
                if urlparse(full_script_url).hostname != base_host:
                    continue
                try:
                    js_res = requests.get(full_script_url, timeout=3, verify=False, headers=_UA)
                    if js_res.status_code == 200:
                        js_paths = re.findall(PATH_EXTRACT_REGEX, js_res.text)
                        for p in js_paths:
                             if not p.endswith((".png", ".jpg", ".css", ".svg", ".ico", ".woff", ".woff2")):
                                discovered_endpoints.add(p)
                except:
                    continue

        # 2. Spec Probing
        spec_paths = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs"]
        for spec_path in spec_paths:
            if time.time() > deadline:
                break
            spec_url = urljoin(base_url, spec_path)
            try:
                s_res = requests.get(spec_url, timeout=3, verify=False, headers=_UA)
                if s_res.status_code == 200:
                    discovered_endpoints.add(spec_path)
                    # Attempt shallow parsing of paths if it's JSON
                    try:
                        spec_data = s_res.json()
                        if "paths" in spec_data:
                            for p in spec_data["paths"].keys():
                                discovered_endpoints.add(p)
                    except:
                        pass # Not a valid JSON or different format
            except:
                continue

        # 3. Targeted Directory Fuzzing
        # To keep discovery efficient, we only fuzz a curated subset per host
        # During a background scan, we'll limit this.
        for path in ENTERPRISE_API_WORDLIST:
            if time.time() > deadline:
                break
            # Prepend / if missing
            fuzz_path = f"/{path}" if not path.startswith("/") else path
            fuzz_url = urljoin(base_url, fuzz_path)
            try:
                # Use HEAD if possible for speed, fallback to GET if needed
                f_res = requests.head(fuzz_url, timeout=2, verify=False, allow_redirects=True, headers=_UA)
                if f_res.status_code in [200, 201, 204, 401, 403]:
                    discovered_endpoints.add(fuzz_path)
            except:
                continue

    except Exception as e:
        print(f"Active discovery failed for {base_url}: {e}")

    # Remove duplicates and root
    if "/" in discovered_endpoints:
        discovered_endpoints.remove("/")
        
    return sorted(list(discovered_endpoints))
