import os
import re
import ast

# Guardrails for scanning untrusted/large trees.
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024   # skip files larger than 2 MB
MAX_FILES_PER_SCAN = 20000                # cap files walked per directory scan

# Rules catalog mapping static code patterns to CBOM Cryptographic Asset fields
PYTHON_STATIC_RULES = [
    {
        "id": "PY-CRYPTO-MD5",
        "pattern": r"hashlib\.md5\(",
        "algorithm": "MD5",
        "key_size": None,
        "primitive": "hash",
        "asset_type": "library",
        "sensitivity_tier": "S3",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 20,
        "classical_security_level": 0,
        "nist_quantum_security_level": 0,
        "recommendation": "Replace MD5 with SHA-256 or SHA-3 (FIPS 202) digest."
    },
    {
        "id": "PY-CRYPTO-SHA1",
        "pattern": r"hashlib\.sha1\(",
        "algorithm": "SHA-1",
        "key_size": None,
        "primitive": "hash",
        "asset_type": "library",
        "sensitivity_tier": "S3",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 35,
        "classical_security_level": 64,
        "nist_quantum_security_level": 0,
        "recommendation": "Replace SHA-1 with SHA-256, SHA-512, or SHA3-256."
    },
    {
        "id": "PY-RSA-WEAK-GEN",
        "pattern": r"RSA\.generate\(\s*(1024|512)\s*\)",
        "algorithm": "RSA-1024",
        "key_size": 1024,
        "primitive": "public-key-encryption",
        "asset_type": "library",
        "sensitivity_tier": "S1",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 15,
        "classical_security_level": 80,
        "nist_quantum_security_level": 0,
        "recommendation": "Upgrade to RSA-4096 or Hybrid ML-KEM-768 key encapsulation."
    },
    {
        "id": "PY-RSA-2048-GEN",
        "pattern": r"RSA\.generate\(\s*2048\s*\)",
        "algorithm": "RSA-2048",
        "key_size": 2048,
        "primitive": "public-key-encryption",
        "asset_type": "library",
        "sensitivity_tier": "S2",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 50,
        "classical_security_level": 112,
        "nist_quantum_security_level": 0,
        "recommendation": "Plan migration to ML-KEM-768 (FIPS 203) per NIST PQC transition guidance."
    },
    {
        "id": "PY-SSL-LEGACY-PROTO",
        "pattern": r"ssl\.PROTOCOL_(SSLv23|TLSv1|TLSv1_1)",
        "algorithm": "TLSv1.0",
        "key_size": None,
        "primitive": "protocol",
        "asset_type": "service",
        "sensitivity_tier": "S1",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 10,
        "classical_security_level": 80,
        "nist_quantum_security_level": 0,
        "recommendation": "Upgrade SSLContext to ssl.PROTOCOL_TLS_CLIENT / TLS 1.3 with PFS."
    },
    {
        "id": "PY-WEAK-CIPHER-DES",
        "pattern": r"algorithms\.(DES|TripleDES|ARC4|Blowfish)\(",
        "algorithm": "DES/ARC4-Legacy",
        "key_size": 56,
        "primitive": "symmetric-cipher",
        "asset_type": "library",
        "sensitivity_tier": "S2",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 10,
        "classical_security_level": 0,
        "nist_quantum_security_level": 0,
        "recommendation": "Replace legacy symmetric ciphers with AES-256-GCM."
    },
    {
        "id": "PY-HARDCODED-PRIVATE-KEY",
        "pattern": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        "algorithm": "Hardcoded-Private-Key",
        "key_size": None,
        "primitive": "public-key-encryption",
        "asset_type": "secret",
        "sensitivity_tier": "S1",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 5,
        "classical_security_level": 0,
        "nist_quantum_security_level": 0,
        "recommendation": "Remove hardcoded keys immediately. Store keys in Cloud KMS or Hardware Security Module (HSM)."
    }
]

JS_STATIC_RULES = [
    {
        "id": "JS-CRYPTO-MD5",
        "pattern": r"crypto\.createHash\(\s*['\"]md5['\"]\s*\)",
        "algorithm": "MD5",
        "key_size": None,
        "primitive": "hash",
        "asset_type": "library",
        "sensitivity_tier": "S3",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 20,
        "classical_security_level": 0,
        "nist_quantum_security_level": 0,
        "recommendation": "Replace Node.js md5 hash with sha256 or sha512."
    },
    {
        "id": "JS-CRYPTO-SHA1",
        "pattern": r"crypto\.createHash\(\s*['\"]sha1['\"]\s*\)",
        "algorithm": "SHA-1",
        "key_size": None,
        "primitive": "hash",
        "asset_type": "library",
        "sensitivity_tier": "S3",
        "is_pqc": False,
        "policy_compliant": False,
        "qtri_score": 35,
        "classical_security_level": 64,
        "nist_quantum_security_level": 0,
        "recommendation": "Replace sha1 hash with sha256 or sha3-256."
    }
]

_COMMENT_PREFIXES = ("#", "//", "*", "/*")


class PythonASTVisitor(ast.NodeVisitor):
    """Real AST pass for Python. Unlike a raw-line regex it resolves the actual
    call target (so comments/strings don't false-positive), records the enclosing
    function, and reads RSA.generate()'s literal key size from the syntax tree."""

    def __init__(self, filepath: str, lines: list):
        self.filepath = filepath
        self.lines = lines
        self.findings = []
        self._func_stack = []
        self._seen = set()

    def _enclosing(self):
        return self._func_stack[-1] if self._func_stack else "<module>"

    def visit_FunctionDef(self, node):
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        try:
            base = ast.unparse(node.func)
        except Exception:
            base = ""
        # Reconstruct the call WITH a trailing '(' so it matches the same
        # patterns the regex pass uses (the original bug: 'hashlib.md5' never
        # matched r'hashlib\.md5\(').
        call_str = f"{base}(" if base else ""
        # AST-derived precision: pull the real integer key size for RSA.generate.
        if base.endswith("RSA.generate") and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                call_str = f"RSA.generate({arg.value})"
        for rule in PYTHON_STATIC_RULES:
            if re.search(rule["pattern"], call_str):
                line_no = getattr(node, "lineno", 1)
                dedupe_key = (line_no, rule["id"])
                if dedupe_key in self._seen:
                    continue
                self._seen.add(dedupe_key)
                self.findings.append({
                    "rule": rule,
                    "file": self.filepath,
                    "line": line_no,
                    "function": self._enclosing(),
                    "detection_method": "python-ast",
                    "code_snippet": self.lines[line_no - 1].strip() if line_no <= len(self.lines) else ""
                })
        self.generic_visit(node)


def _nearest_scope(lines: list, line_idx: int) -> str:
    """Nearest preceding def/class name for a regex hit (best-effort)."""
    for i in range(min(line_idx, len(lines)) - 1, -1, -1):
        stripped = lines[i].lstrip()
        m = re.match(r"(?:async\s+)?def\s+(\w+)", stripped) or re.match(r"class\s+(\w+)", stripped)
        if m:
            return m.group(1)
    return "<module>"


def scan_file_static(filepath: str) -> list:
    """
    Scans a single source file: real AST for Python + regex fallback for other
    languages. Returns a list of discovered cryptographic assets with genuine
    file/line/function evidence (no fabricated TLS/certificate attributes).
    """
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return []
    try:
        if os.path.getsize(filepath) > MAX_SOURCE_FILE_BYTES:
            return []
    except OSError:
        return []

    findings = []
    rel_path = os.path.normpath(filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()
    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        return []

    ext = os.path.splitext(filepath)[1].lower()

    # 1. AST Analysis for Python Files (authoritative — regex only fills gaps)
    if ext == ".py":
        try:
            tree = ast.parse(content, filename=filepath)
            visitor = PythonASTVisitor(rel_path, lines)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except Exception:
            pass  # syntax error / non-parseable: fall through to regex

    # 2. Regex Pattern Matching (skips comment-only lines to cut false positives)
    rules_to_check = (
        PYTHON_STATIC_RULES if ext == ".py"
        else JS_STATIC_RULES if ext in (".js", ".ts", ".jsx", ".tsx")
        else PYTHON_STATIC_RULES + JS_STATIC_RULES
    )
    existing_locations = {(f["file"], f["line"], f["rule"]["id"]) for f in findings}

    for line_idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith(_COMMENT_PREFIXES):
            continue
        for rule in rules_to_check:
            if re.search(rule["pattern"], line):
                loc_key = (rel_path, line_idx, rule["id"])
                if loc_key not in existing_locations:
                    existing_locations.add(loc_key)
                    findings.append({
                        "rule": rule,
                        "file": rel_path,
                        "line": line_idx,
                        "function": _nearest_scope(lines, line_idx) if ext == ".py" else "<top>",
                        "detection_method": "regex",
                        "code_snippet": stripped
                    })

    # 3. Dependency Manifest Analysis
    filename = os.path.basename(filepath).lower()
    if filename == "requirements.txt":
        if "cryptography<3.0" in content:
            findings.append({
                "rule": {
                    "id": "MANIFEST-OLD-CRYPTOGRAPHY",
                    "algorithm": "Legacy-PyCA-Cryptography",
                    "key_size": None,
                    "primitive": "library",
                    "asset_type": "library",
                    "sensitivity_tier": "S2",
                    "is_pqc": False,
                    "policy_compliant": False,
                    "qtri_score": 30,
                    "classical_security_level": 80,
                    "nist_quantum_security_level": 0,
                    "recommendation": "Upgrade pyca/cryptography to a current release and track ML-KEM/ML-DSA provider support."
                },
                "file": rel_path,
                "line": 1,
                "function": "<manifest>",
                "detection_method": "manifest",
                "code_snippet": "cryptography<3.0"
            })

    # Map findings into unified asset dictionary format. Source findings have no
    # TLS session/certificate — those fields are N/A, never invented.
    discovered_assets = []
    for item in findings:
        r = item["rule"]
        hostname_label = f"static::{os.path.basename(item['file'])}:{item['line']}"
        discovered_assets.append({
            "hostname": hostname_label,
            "tls_version": "N/A",
            "algorithm": r["algorithm"],
            "key_size": r.get("key_size"),
            "cipher_suite": "N/A",
            "forward_secrecy": None,
            "cert_valid": None,
            "cert_expiry": None,
            "sensitivity_tier": r["sensitivity_tier"],
            "is_pqc": r["is_pqc"],
            "policy_compliant": r["policy_compliant"],
            "qtri_score": r["qtri_score"],
            "source_type": "static_code",
            "asset_type": r["asset_type"],
            "evidence_file": item["file"],
            "evidence_line": item["line"],
            "evidence_function": item.get("function", "<module>"),
            "detection_method": item.get("detection_method", "regex"),
            "primitive": r["primitive"],
            "classical_security_level": r["classical_security_level"],
            "nist_quantum_security_level": r["nist_quantum_security_level"],
            "recommendation": r["recommendation"]
        })

    return discovered_assets


def scan_directory_static(target_dir: str) -> list:
    """
    Recursively scans a directory for Python, JavaScript, TypeScript and
    requirements.txt manifests. Prunes vendored/build dirs and caps file count.
    """
    if not os.path.exists(target_dir):
        return []
    if not os.path.isdir(target_dir):
        return scan_file_static(target_dir)

    all_assets = []
    seen_files = 0
    ignore_dirs = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build", ".tox", "site-packages"}

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
            if f.endswith((".py", ".js", ".ts", ".jsx", ".tsx")) or f.lower() == "requirements.txt":
                if seen_files >= MAX_FILES_PER_SCAN:
                    return all_assets
                seen_files += 1
                filepath = os.path.join(root, f)
                all_assets.extend(scan_file_static(filepath))

    return all_assets
