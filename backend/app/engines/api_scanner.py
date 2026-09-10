import requests
import time
from urllib.parse import urljoin
import urllib3
from app.net_guard import assert_target_allowed, TargetNotAllowed
from app.settings import ALLOW_MUTATING_API_PROBES
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_UA = {"User-Agent": "Q-Guardian-APIScan/2.0 (+authorized-testing-only)"}

OWASP_CHECKS = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Excessive Data Exposure",
    "API4": "Lack of Rate Limiting",
    "API5": "Broken Function Level Authorization",
    "API6": "Server-Side Request Forgery",
    "API7": "Security Misconfiguration",
    "API8": "Insecure TLS / Automations",
    "API9": "Improper Assets Management",
    "API10": "Unsafe Consumption of APIs"
}

def analyze_security_headers(headers):
    """Analyze HTTP security headers, case-insensitively."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    security_headers = {
        "HSTS": "strict-transport-security" in headers_lower,
        "CSP": "content-security-policy" in headers_lower,
        "X-Frame-Options": "x-frame-options" in headers_lower,
        "X-Content-Type-Options": "x-content-type-options" in headers_lower,
        "X-XSS-Protection": "x-xss-protection" in headers_lower,
        "Cache-Control": "cache-control" in headers_lower and "no-store" in headers_lower.get("cache-control", ""),
        "CORS": "access-control-allow-origin" in headers_lower
    }
    
    score = sum(1 for val in security_headers.values() if val)
    total = len(security_headers)
    return security_headers, int((score / total) * 100), headers_lower.get("access-control-allow-origin")

def normalize_url(raw_url: str) -> str:
    """Ensure the URL has a scheme. Defaults to https:// if missing."""
    if not raw_url:
        return ""
    raw_url = raw_url.strip()
    if not raw_url:
        return ""
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url
    return raw_url

def check_idor(base_url: str):
    """API1: Broken Object Level Authorization (IDOR) check."""
    # Probe predictable IDs and see if they respond with 200 OK without auth
    test_paths = ["/api/v1/users/1", "/api/v1/users/2", "/api/v1/accounts/1", "/api/v1/accounts/2"]
    for path in test_paths:
        try:
            target = urljoin(base_url, path)
            r = requests.get(target, timeout=3, verify=False)
            if r.status_code == 200 and "application/json" in r.headers.get("content-type", ""):
                return {
                    "id": "API1",
                    "severity": "CRITICAL",
                    "detail": f"IDOR Vulnerability. Sequential object ID accessed without auth context at {target}.",
                    "vector": "IDOR"
                }
        except:
            pass
    return None

def check_jwt_bypass(base_url: str):
    """API2: Broken Authentication (JWT attacks)"""
    # Test 'alg: none' bypass
    header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" # {"alg":"none","typ":"JWT"}
    payload = "eyJ1c2VyIjoiaGFja2VyIiwicm9sZSI6ImFkbWluIn0" # {"user":"hacker","role":"admin"}
    token = f"{header}.{payload}."
    
    test_paths = ["/api/v1/admin", "/api/v1/profile", "/api/v1/user"]
    for path in test_paths:
        try:
            target = urljoin(base_url, path)
            # Baseline: the endpoint must actually be PROTECTED (401/403) without
            # a token, otherwise a 200 with alg:none proves nothing (public route).
            base = requests.get(target, timeout=3, verify=False, headers=_UA)
            if base.status_code not in (401, 403):
                continue
            r = requests.get(target, headers={**_UA, "Authorization": f"Bearer {token}"}, timeout=3, verify=False)
            if r.status_code == 200:
                return {
                    "id": "API2",
                    "severity": "CRITICAL",
                    "detail": f"JWT Signature Bypass: {target} required auth (baseline {base.status_code}) "
                              f"but accepted an unsigned alg:none token (200).",
                    "vector": "JWT_ALG_NONE"
                }
        except:
            pass
    return None

def check_graphql_introspection(base_url: str):
    """API3: Excessive Data Exposure (GraphQL Introspection)"""
    query = {"query": "{ __schema { types { name } } }"}
    test_paths = ["/graphql", "/api/graphql", "/v1/graphql"]
    for path in test_paths:
        try:
            target = urljoin(base_url, path)
            r = requests.post(target, json=query, timeout=3, verify=False)
            if r.status_code == 200 and "__schema" in r.text:
                return {
                    "id": "API3",
                    "severity": "HIGH",
                    "detail": f"GraphQL Introspection is enabled at {target}. An attacker can map the entire schema.",
                    "vector": "GRAPHQL_INTRO"
                }
        except:
            pass
    return None

def check_mass_assignment(base_url: str):
    """API6: Mass Assignment"""
    payload = {"username": "test_user", "email": "test@test.com", "role": "admin", "is_admin": True}
    test_paths = ["/api/v1/users", "/api/v1/register", "/api/v1/profile"]
    for path in test_paths:
        try:
            target = urljoin(base_url, path)
            r = requests.post(target, json=payload, timeout=3, verify=False)
            # If server accepts the extra 'role' or 'is_admin' without rejecting the payload (e.g. 400)
            # and responds with 200/201, it might be vulnerable.
            if r.status_code in [200, 201]:
                return {
                    "id": "API6",
                    "severity": "HIGH",
                    "detail": f"Mass Assignment Vulnerability. Server accepted unexpected privileged fields (role, is_admin) at {target}.",
                    "vector": "MASS_ASSIGNMENT"
                }
        except:
            pass
    return None

def check_bfla(base_url: str, include_mutating: bool = False):
    """API5: Broken Function Level Authorization (Method switching, Admin paths).

    The DELETE method-switching probe is destructive and only runs when
    include_mutating is True (ALLOW_MUTATING_API_PROBES). The admin-path check is
    a read-only GET and always runs."""
    if include_mutating:
        for path in ["/api/v1/users", "/api/v1/accounts"]:
            target = urljoin(base_url, path)
            try:
                r = requests.delete(target, timeout=3, verify=False, headers=_UA)
                if r.status_code == 200:
                    return {
                        "id": "API5",
                        "severity": "CRITICAL",
                        "detail": f"Broken Function Level Auth. Unauthorized HTTP DELETE allowed at {target}.",
                        "vector": "BFLA_METHOD"
                    }
            except:
                pass

    # Test admin paths without auth (read-only)
    admin_paths = ["/api/v1/admin/users", "/api/v1/admin/config"]
    for path in admin_paths:
        target = urljoin(base_url, path)
        try:
            r = requests.get(target, timeout=3, verify=False, headers=_UA)
            if r.status_code == 200:
                 return {
                    "id": "API5",
                    "severity": "CRITICAL",
                    "detail": f"Broken Function Level Auth. Admin endpoint {target} accessible without authorization.",
                    "vector": "BFLA_ADMIN"
                }
        except:
            pass
            
    return None

def run_api_scan(base_url: str):
    findings = []
    info_disclosure = []
    endpoints_checked = []

    # --- Step 0: Normalize the URL (fix missing scheme) + SSRF guard ---
    base_url = normalize_url(base_url)
    try:
        assert_target_allowed(base_url)
    except TargetNotAllowed as e:
        return {"error": str(e)}

    tls_enforced = False
    if base_url.startswith("https"):
        tls_enforced = True
        # Pass 1: Strict TLS certificate verification
        try:
            requests.get(base_url, timeout=6, verify=True)
        except requests.exceptions.SSLError:
            findings.append({
                "id": "API8",
                "severity": "CRITICAL",
                "detail": "TLS Validation Failed. The API endpoint uses an invalid or self-signed certificate, making it vulnerable to MITM interception.",
                "vector": "TLS_ERROR"
            })
        except requests.exceptions.ConnectionError:
            return {"error": f"Could not resolve or connect to host: {base_url}. The server may be offline or the domain does not exist."}
        except requests.exceptions.Timeout:
            return {"error": f"Connection to {base_url} timed out during TLS verification."}
        except requests.exceptions.RequestException as e:
            return {"error": f"Invalid URL or request failed for {base_url}: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error during pre-scan of {base_url}: {e}"}
    else:
        # Plain HTTP — flag as a vulnerability without blocking scan
        findings.append({
            "id": "API8",
            "severity": "HIGH",
            "detail": "No TLS detected. The API is serving traffic over unencrypted HTTP, exposing all data in transit.",
            "vector": "NO_TLS"
        })

    # --- Pass 2: Application Layer Scan ---
    try:
        response = requests.get(base_url, timeout=8, verify=False)
        endpoints_checked.append({"url": base_url, "status": response.status_code})
    except requests.exceptions.ConnectionError:
        return {"error": f"Could not connect to {base_url}. The server may be offline, the domain may not resolve, or a firewall is blocking the request."}
    except requests.exceptions.Timeout:
        return {"error": f"Request to {base_url} timed out. The server is too slow or unreachable."}
    except requests.exceptions.RequestException as e:
        return {"error": f"Invalid URL or request failed for {base_url}: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error connecting to {base_url}: {e}"}

    sec_headers, header_score, cors_origin = analyze_security_headers(response.headers)

    # --- Information Disclosure Check ---
    if "server" in {k.lower() for k in response.headers}:
        info_disclosure.append(f"Server header exposed: {response.headers.get('Server', response.headers.get('server'))}")
    if "x-powered-by" in {k.lower() for k in response.headers}:
        info_disclosure.append(f"Framework exposed via X-Powered-By: {response.headers.get('X-Powered-By', response.headers.get('x-powered-by'))}")

    # --- Rate Limiting Check (API4) ---
    rate_limited = False
    successful_probes = 0
    start_time = time.time()
    for _ in range(15):  # Make 15 rapid requests (matching docs)
        try:
            r = requests.get(base_url, timeout=2, verify=False)
            if r.status_code in [429, 503]:
                rate_limited = True
                break
            # Only genuine 2xx responses count — a fast-404ing host is NOT proof
            # of a missing rate limit.
            if 200 <= r.status_code < 300:
                successful_probes += 1
        except Exception:
            # Drop errors during burst probe but do not count as success
            pass

    total_time = time.time() - start_time
    avg_latency = total_time / max(successful_probes, 1)

    if not rate_limited and successful_probes >= 10 and avg_latency < 1.0:
        findings.append({
            "id": "API4",
            "severity": "HIGH",
            "detail": f"No rate limiting detected after {successful_probes} rapid automated requests (Avg: {avg_latency:.2f}s/req). The API is vulnerable to DDoS and credential-stuffing attacks.",
            "vector": "NO_RATE_LIMIT"
        })

    # --- CORS Policy Check (API7) ---
    cors_risk = "LOW"
    if cors_origin == "*":
        cors_risk = "HIGH"
        findings.append({
            "id": "API7",
            "severity": "MEDIUM",
            "detail": "Wildcard CORS origin (*) detected. Any website can make credentialed requests to this API, enabling cross-site request forgery attacks.",
            "vector": "WILDCARD_CORS"
        })

    # --- Endpoint Discovery & Authentication Check (API2, API3) ---
    common_paths = [
        '/api', '/v1', '/api/v1', '/swagger.json', '/openapi.json',
        '/health', '/docs', '/graphql', '/admin', '/api/users', '/api/accounts'
    ]
    auth_required = False
    open_endpoint_seen = False  # a real 200 on an API-ish path (positive evidence)

    for path in common_paths:
        target = urljoin(base_url, path)
        try:
            r = requests.get(target, timeout=4, verify=False, headers=_UA)
            if r.status_code in [401, 403]:
                auth_required = True
                endpoints_checked.append({"url": target, "status": r.status_code})
            elif r.status_code == 200:
                open_endpoint_seen = True
                endpoints_checked.append({"url": target, "status": 200})
                if any(kw in path for kw in ['swagger', 'openapi', 'docs', 'graphql']):
                    info_disclosure.append(f"API documentation is publicly accessible at {target}")
                    findings.append({
                        "id": "API3",
                        "severity": "MEDIUM",
                        "detail": f"Publicly accessible API specification at {target} reveals endpoint structure, parameters, and data schema — enabling targeted attacks.",
                        "vector": "SPEC_EXPOSED"
                    })
        except:
            pass

    # Only assert "possibly unauthenticated" when we actually saw an OPEN (200)
    # API endpoint AND never saw an auth challenge — a host that 404s everything
    # is not evidence of a missing auth layer.
    if not auth_required and open_endpoint_seen:
        findings.append({
            "id": "API2",
            "severity": "HIGH",
            "detail": "An API endpoint returned HTTP 200 and no endpoint issued an auth challenge (401/403). "
                      "The API may expose unauthenticated data — verify manually.",
            "vector": "NO_AUTH"
        })

    # --- Deep Scanning Modules (read-only by default) ---
    idor_res = check_idor(base_url)
    if idor_res: findings.append(idor_res)

    jwt_res = check_jwt_bypass(base_url)
    if jwt_res: findings.append(jwt_res)

    gql_res = check_graphql_introspection(base_url)
    if gql_res: findings.append(gql_res)

    # State-changing probes (POST privileged fields / DELETE) only with opt-in.
    if ALLOW_MUTATING_API_PROBES:
        mass_assign_res = check_mass_assignment(base_url)
        if mass_assign_res: findings.append(mass_assign_res)

    bfla_res = check_bfla(base_url, include_mutating=ALLOW_MUTATING_API_PROBES)
    if bfla_res: findings.append(bfla_res)


    # --- Deduplicate findings by OWASP ID ---
    seen_ids = set()
    unique_findings = []
    for f in findings:
        if f["id"] not in seen_ids:
            unique_findings.append(f)
            seen_ids.add(f["id"])

    # --- Risk Score: header score minus severity-weighted penalties ---
    severity_penalties = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    penalty = sum(severity_penalties.get(f["severity"], 5) for f in unique_findings)
    api_risk_score = max(0, min(100, header_score - penalty))

    return {
        "url": base_url,
        "status_code": response.status_code,
        "tls_enforced": tls_enforced,
        "security_headers": sec_headers,
        "header_score": header_score,
        "owasp_findings": unique_findings,
        "cors_policy": {"allow_origin": cors_origin, "risk": cors_risk},
        "auth_required": auth_required,
        "info_disclosure": info_disclosure,
        "api_risk_score": api_risk_score,
        "endpoints_discovered": endpoints_checked
    }
