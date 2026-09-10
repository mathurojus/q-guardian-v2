"""
CBOM Reconciliation & Divergence Engine for Q-Guardian-v2.

Correlates discoveries across vectors (static-source, binary, container,
network-live) and flags "modern-vs-legacy" divergences.

HONESTY MODEL: the scan vectors emit heterogeneous identifiers (bin:<file>,
container:<pkg>, live domains) that rarely share a logical identity, so most
findings are ENVIRONMENT-LEVEL co-presence observations ("this environment
contains both modern X and legacy Y"), NOT per-asset "the source for THIS host
declares Z". When two assets DO share a normalized identity we upgrade the
finding to identity-matched (higher confidence). Every divergence carries a
`correlation` and `confidence` field so nothing is overstated. Stale flags are
cleared at the start of every run so results reflect the current inventory.
"""

from typing import Dict, Any, List, Optional
from sqlmodel import Session, select
from datetime import datetime
import re

from app.database import DBAsset

# Generic package/host tokens that must NOT be treated as a shared identity.
_GENERIC_KEYS = {"openssl", "libssl", "libcrypto", "ca-certificates", "", "unknown"}


def _normalize_hostname(h: str) -> str:
    """Normalize an asset hostname to a candidate logical-service key."""
    cleaned = re.sub(r"^(bin|src|container|live|static):+", "", h or "", flags=re.IGNORECASE)
    cleaned = re.sub(r":.*$", "", cleaned)  # strip line/port/package suffix
    return cleaned.lower().strip()


def _shared_identity(a: DBAsset, b: DBAsset) -> Optional[str]:
    """Return the shared normalized key if two assets plausibly name the same
    logical service, else None. Generic library names don't count."""
    ka, kb = _normalize_hostname(a.hostname), _normalize_hostname(b.hostname)
    if ka and ka == kb and ka not in _GENERIC_KEYS:
        return ka
    return None


def reconcile_assets(session: Session, job_uuid: Optional[str] = None) -> Dict[str, Any]:
    """Evaluate assets, (re)compute divergence flags and crypto-agility maturity.

    Passing job_uuid scopes evaluation to that scan when the schema tracks it;
    otherwise all assets are evaluated. Flags are always cleared first so a
    remediated + re-scanned asset can actually drop its divergence.
    """
    assets = list(session.exec(select(DBAsset)).all())
    if job_uuid is not None and hasattr(DBAsset, "job_uuid"):
        scoped = [a for a in assets if getattr(a, "job_uuid", None) == job_uuid]
        if scoped:
            assets = scoped

    if not assets:
        return {
            "status": "empty",
            "total_evaluated": 0,
            "divergence_count": 0,
            "divergences": [],
            "crypto_agility_score": 1,
            "maturity_label": "Level 1: Initial / Undiscovered"
        }

    # Clear stale flags so this run reflects the current inventory.
    for a in assets:
        a.divergence_flag = None

    by_source: Dict[str, List[DBAsset]] = {"static": [], "binary": [], "container": [], "network": []}
    for a in assets:
        st = (a.source_type or "").lower()
        if "static" in st or "source" in st:
            by_source["static"].append(a)
        elif "binary" in st:
            by_source["binary"].append(a)
        elif "container" in st:
            by_source["container"].append(a)
        else:
            by_source["network"].append(a)

    divergent_items: List[Dict[str, Any]] = []
    updated_records = 0

    def _emit(primary: DBAsset, counterpart: Optional[DBAsset], dtype: str,
              base_severity: str, flag: str, declared: str, actual: str,
              impact: str, remediation: str):
        nonlocal updated_records
        if primary.divergence_flag:
            return
        shared = _shared_identity(primary, counterpart) if counterpart is not None else None
        correlation = "identity-matched" if shared else "environment-level"
        confidence = "high" if shared else "medium"
        # Environment-level co-presence isn't per-asset proof, so cap its severity.
        severity = base_severity if shared else ("HIGH" if base_severity == "CRITICAL" else "MEDIUM")
        primary.divergence_flag = flag
        session.add(primary)
        updated_records += 1
        divergent_items.append({
            "type": dtype,
            "severity": severity,
            "correlation": correlation,
            "confidence": confidence,
            "shared_identity": shared,
            "divergence_flag": flag,
            "asset_id": primary.asset_uuid,
            "target": primary.hostname,
            "declared": declared,
            "actual": actual,
            "impact": impact,
            "remediation": remediation,
        })

    # ─── Check 1: modern (source PQC/TLS1.3) co-present with weak live TLS ───
    static_pqc_or_tls13 = [a for a in by_source["static"]
                           if a.is_pqc or a.tls_version == "1.3" or "ml-kem" in (a.algorithm or "").lower()]
    live_weak_tls = [a for a in by_source["network"]
                     if a.tls_version in ["1.0", "1.1", "1.2"] or not a.policy_compliant]
    if static_pqc_or_tls13 and live_weak_tls:
        for net_a in live_weak_tls:
            match = next((s for s in static_pqc_or_tls13 if _shared_identity(s, net_a)), None)
            _emit(net_a, match or static_pqc_or_tls13[0],
                  "STATIC_VS_LIVE_PROTOCOL_DIVERGENCE", "CRITICAL",
                  f"DIV_STATIC_TLS1.3_VS_LIVE_{net_a.tls_version or '1.0'}",
                  "Source/config assets in this environment target modern TLS 1.3 / PQC",
                  f"This live endpoint enforces {net_a.tls_version} with {net_a.cipher_suite}",
                  "Potential MITM / Harvest-Now-Decrypt-Later exposure on this endpoint.",
                  "Align reverse-proxy/gateway cipher configuration to disable legacy TLS.")

    # ─── Check 2: modern container libs co-present with legacy binary constants ─
    container_modern = [a for a in by_source["container"]
                        if re.search(r"[- ]3\.", a.algorithm or "") or a.is_pqc]
    binary_legacy = [a for a in by_source["binary"]
                     if not a.is_pqc and (a.qtri_score or 100) < 40]
    if container_modern and binary_legacy:
        for bin_a in binary_legacy:
            match = next((c for c in container_modern if _shared_identity(c, bin_a)), None)
            _emit(bin_a, match or container_modern[0],
                  "CONTAINER_VS_BINARY_DIVERGENCE", "HIGH",
                  f"DIV_CONTAINER_MODERN_VS_BINARY_{bin_a.algorithm or 'LEGACY'}",
                  "Container base image supplies modern OpenSSL 3.x libraries",
                  f"A compiled binary embeds a legacy primitive: {bin_a.algorithm} ({bin_a.evidence_function or ''})",
                  "Statically-linked/embedded legacy routines bypass container library updates.",
                  "Recompile against the shared modern OpenSSL and drop embedded legacy routines.")

    # ─── Check 3: PQC-ready code co-present with classical RSA<=2048 live cert ──
    live_classical_certs = [a for a in by_source["network"]
                            if not a.is_pqc and (a.key_size or 0) and a.key_size <= 2048]
    if static_pqc_or_tls13 and live_classical_certs:
        for net_a in live_classical_certs:
            match = next((s for s in static_pqc_or_tls13 if _shared_identity(s, net_a)), None)
            _emit(net_a, match or static_pqc_or_tls13[0],
                  "ALGORITHM_READINESS_DIVERGENCE", "HIGH",
                  "DIV_CODE_PQC_VS_LIVE_RSA2048",
                  "Application architecture is flagged for post-quantum migration",
                  f"Public certificate remains classical RSA-{net_a.key_size} without hybrid KEM",
                  "Store-Now-Decrypt-Later exposure persists on edge communications.",
                  "Pilot a hybrid PQC TLS certificate (X25519MLKEM768).")

    # ─── Check 4: single-asset S1 tier vs non-compliance (true per-asset check) ─
    for a in assets:
        if a.sensitivity_tier == "S1" and not a.policy_compliant and not a.divergence_flag:
            a.divergence_flag = "DIV_TIER_S1_CRITICAL_NON_COMPLIANT"
            session.add(a)
            updated_records += 1
            divergent_items.append({
                "type": "CRITICAL_TIER_POLICY_DIVERGENCE",
                "severity": "CRITICAL",
                "correlation": "single-asset",
                "confidence": "high",
                "shared_identity": None,
                "divergence_flag": "DIV_TIER_S1_CRITICAL_NON_COMPLIANT",
                "asset_id": a.asset_uuid,
                "target": a.hostname,
                "declared": "Sensitivity Tier S1 (mission-critical / financial)",
                "actual": f"Non-compliant crypto configuration with QTRI score {a.qtri_score}/100",
                "impact": "Audit finding under CERT-In / RBI cyber-resilience baseline controls.",
                "remediation": "Prioritize cryptographic remediation for this tier-S1 asset.",
            })

    session.commit()

    total_count = len(assets)
    div_count = len(divergent_items)
    pqc_count = sum(1 for a in assets if a.is_pqc)

    if div_count == 0 and pqc_count > 0:
        maturity_score, maturity_label = 5, "Level 5: Quantum Agile & Continuously Correlated"
    elif div_count == 0:
        maturity_score, maturity_label = 4, "Level 4: Monitored & Reconciled (No Divergence)"
    elif div_count <= 2:
        maturity_score, maturity_label = 3, "Level 3: Partially Agile (Minor Vector Divergence)"
    elif div_count <= 5:
        maturity_score, maturity_label = 2, "Level 2: Fragmented (Multi-Vector Divergence Detected)"
    else:
        maturity_score, maturity_label = 1, "Level 1: High Risk Divergence (Substantial Declared-vs-Actual Drift)"

    for a in assets:
        a.maturity_level = maturity_score
        session.add(a)
    session.commit()

    return {
        "status": "completed",
        "timestamp": datetime.now().isoformat(),
        "total_evaluated": total_count,
        "divergence_count": div_count,
        "updated_records": updated_records,
        "crypto_agility_score": maturity_score,
        "maturity_label": maturity_label,
        "divergences": divergent_items
    }
