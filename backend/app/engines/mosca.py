import math
import re

# Mosca countdown logic
# X + Y > Z (Threat exists)
# X: Migration time
# Y: Data shelf life (Sensitivity)
# Z: Time until Cryptographically Relevant Quantum Computer (CRQC)

# Data shelf life Y (years). Illustrative RBI-sensitivity-tiered planning
# assumptions for how long data must stay confidential — configurable, not
# measured telemetry.
SENSITIVITY_SHELF_LIFE = {
    "S1": 10,  # Core payment / PKI root
    "S2": 7,   # KYC / Identity
    "S3": 5,   # Transaction history
    "S4": 3,   # Internal business
    "S5": 1    # Public info
}

# CRQC arrival probability curve P(CRQC <= horizon), as (lower, upper) bounds.
# These are ILLUSTRATIVE expert-elicitation planning estimates broadly informed
# by the Global Risk Institute (GRI) "Quantum Threat Timeline" survey trend
# (near-term single-digit %, rising past ~50% around the 15-year horizon). They
# are NOT a verbatim quote of a specific GRI table/figure and should be treated
# as configurable planning assumptions, not a measured forecast.
GRI_PROBABILITY_TABLE = {
    5:  (0.05, 0.12),
    10: (0.28, 0.49),
    15: (0.51, 0.70),
    20: (0.75, 0.90),
}

# Default CRQC horizon bounds used for the days-remaining countdown.
CRQC_TIMELINE_YEARS = {
    "worst_case": 10,  # aggressive 10-yr horizon
    "best_case": 15    # moderate 15-yr horizon
}

def get_gri_crqc_probability(years: float, bound: str = "median") -> float:
    """
    Interpolates CRQC arrival probability P(CRQC <= years) based on
    the Global Risk Institute (GRI) Quantum Threat Report expert consensus.
    Bound options: 'lower', 'upper', 'median'
    """
    if years <= 0:
        return 0.0

    def pick_p(yr: int) -> float:
        low, high = GRI_PROBABILITY_TABLE[yr]
        if bound == "lower":
            return low
        elif bound == "upper":
            return high
        return (low + high) / 2.0

    if years <= 5:
        p5 = pick_p(5)
        return max(0.0, (years / 5.0) * p5)
    elif years <= 10:
        p5 = pick_p(5)
        p10 = pick_p(10)
        t = (years - 5.0) / 5.0
        return p5 + t * (p10 - p5)
    elif years <= 15:
        p10 = pick_p(10)
        p15 = pick_p(15)
        t = (years - 10.0) / 5.0
        return p10 + t * (p15 - p10)
    elif years <= 20:
        p15 = pick_p(15)
        p20 = pick_p(20)
        t = (years - 15.0) / 5.0
        return p15 + t * (p20 - p15)
    else:
        # Asymptotic approach toward 0.99 for > 20 years
        p20 = pick_p(20)
        excess = years - 20.0
        return min(0.99, p20 + (1.0 - p20) * (1.0 - math.exp(-0.15 * excess)))

def derive_migration_complexity(asset: dict) -> float:
    """
    Derives migration complexity (X) from the REAL algorithm / key-size /
    primitive surface surfaced by any scanner family (network-tls,
    static-source, container-image, binary, cloud-kms, hsm).
    Returns a value between 0.5 and 4.0 years.
    """
    complexity = 0.5  # Base minimum

    algo = str(asset.get("algorithm", "")).upper()
    primitive = str(asset.get("primitive", "")).lower()
    source = str(asset.get("source_type", "")).lower()
    try:
        key_size = int(asset.get("key_size") or 0)
    except (TypeError, ValueError):
        key_size = 0
    try:
        nist_level = int(asset.get("nist_quantum_security_level") or 0)
    except (TypeError, ValueError):
        nist_level = 0

    # Assets already PQC-deployed (or actively migrating) shrink X to the floor.
    if asset.get("is_pqc") or nist_level >= 1:
        return 0.5

    # Hardware module / HSM key replacement cycles require physical ceremony
    if source in ("hardware_module", "hsm"):
        complexity += 1.0

    # ── Weak / legacy hash families (MD5, SHA-1) ──
    if "MD5" in algo or "SHA-1" in algo or re.search(r"\bSHA1\b", algo):
        complexity += 0.75
    elif primitive == "hash":
        complexity += 0.5

    # ── Legacy symmetric ciphers (DES/3DES/RC4) and unsafe modes (ECB) ──
    if re.search(r"(DES|3DES|RC4|RC2|BLOWFISH)", algo):
        complexity += 1.25
    elif "ECB" in algo:
        complexity += 0.75

    # ── Public-key families — key size matters for RSA/DSA ──
    if "RSA" in algo:
        complexity += 1.0
        if 0 < key_size < 2048:
            complexity += 0.75
        elif key_size >= 4096:
            complexity += 0.25
    elif re.search(r"\bDSA\b", algo) and "ECDSA" not in algo:
        complexity += 1.25
    elif "ECDSA" in algo:
        complexity += 0.5

    tls_ver = str(asset.get("tls_version", ""))
    if tls_ver in ("1.0", "1.1"):
        complexity += 1.0
    elif tls_ver == "1.2":
        complexity += 0.5

    tier = asset.get("sensitivity_tier", "S5")
    if tier in ("S1", "S2"):
        complexity += 0.75

    if not asset.get("forward_secrecy", True):
        complexity += 0.5

    return min(max(complexity, 0.5), 4.0)

def calculate_mosca_clocks(migration_complexity: float, sensitivity_tier: str,
                           is_pqc: bool = False, data_lifetime_years=None):
    # X = migration_complexity (years: 0.5 to 4.0)
    x = migration_complexity
    # Y = per-asset data shelf-life override (statement iii classification) —
    #     falls back to the tier default when not supplied.
    if data_lifetime_years is not None:
        try:
            y = max(0.0, float(data_lifetime_years))
        except (TypeError, ValueError):
            y = SENSITIVITY_SHELF_LIFE.get(sensitivity_tier, 1)
    else:
        y = SENSITIVITY_SHELF_LIFE.get(sensitivity_tier, 1)
    t_total = x + y  # Total time window required for migration + data protection

    # The Mosca inequality assumes quantum-vulnerable crypto. An asset that is
    # ALREADY post-quantum is out of the risk window by definition — do not flag
    # a completed migration as CRITICAL.
    if is_pqc:
        return {
            "x_migration_years": x,
            "y_shelf_life": y,
            "total_protection_horizon": round(t_total, 2),
            "days_remaining_worst": None,
            "days_remaining_best": None,
            "risk_state": "SAFE",
            "gri_probability": {
                "p_crqc_arrival_median": round(get_gri_crqc_probability(t_total), 3),
                "p_crqc_arrival_range": [
                    round(get_gri_crqc_probability(t_total, "lower"), 3),
                    round(get_gri_crqc_probability(t_total, "upper"), 3),
                ],
                "note": "Asset is post-quantum; Mosca risk window not applicable.",
            },
        }

    # Calculate CRQC arrival probability across horizon T = X + Y
    p_arrival_median = get_gri_crqc_probability(t_total, bound="median")
    p_arrival_lower = get_gri_crqc_probability(t_total, bound="lower")
    p_arrival_upper = get_gri_crqc_probability(t_total, bound="upper")
    # Risk window onset: Z - (X + Y)
    z_worst = CRQC_TIMELINE_YEARS["worst_case"] # 10 years (GRI 10-yr lower horizon)
    z_best = CRQC_TIMELINE_YEARS["best_case"]   # 15 years (GRI 15-yr median horizon)

    days_remaining_worst = (z_worst - t_total) * 365.25
    days_remaining_best = (z_best - t_total) * 365.25

    # Risk state calibrated against GRI threat probability
    if p_arrival_median >= 0.50 or days_remaining_worst <= 0:
        risk_state = "CRITICAL"
    elif p_arrival_median >= 0.28 or days_remaining_worst < 365:
        risk_state = "WARNING"
    elif p_arrival_median >= 0.10 or days_remaining_best < 365 * 3:
        risk_state = "MONITOR"
    else:
        risk_state = "SAFE"

    return {
        "x_migration_years": x,
        "y_shelf_life": y,
        "total_protection_horizon": round(t_total, 2),
        "days_remaining_worst": max(0, int(days_remaining_worst)),
        "days_remaining_best": max(0, int(days_remaining_best)),
        "risk_state": risk_state,
        "gri_probability": {
            "p_crqc_arrival_median": round(p_arrival_median, 3),
            "p_crqc_arrival_range": [round(p_arrival_lower, 3), round(p_arrival_upper, 3)],
            "model_reference": {
                "note": "Illustrative CRQC-arrival planning curve (see GRI_PROBABILITY_TABLE); not a specific GRI figure.",
                "10yr": GRI_PROBABILITY_TABLE[10],
                "15yr": GRI_PROBABILITY_TABLE[15]
            }
        }
    }


def apply_business_impact(risk_state: str, business_impact: str) -> str:
    """
    Statement iii classification: business criticality biases the Mosca risk
    window. High-impact assets (PII, payment, core) are escalated one step;
    Low-impact public assets are downgraded one step so capital-intensive
    PQC migration focuses on what actually matters.
    """
    level = {
        "SAFE": 0, "MONITOR": 1, "WARNING": 2, "CRITICAL": 3,
    }
    impact = (business_impact or "Medium")
    # High escalates one step; Low de-escalates one step; Medium neutral
    if impact == "High":
        shift = 1
    elif impact == "Low":
        shift = -1
    else:
        shift = 0
    names = ["SAFE", "MONITOR", "WARNING", "CRITICAL"]
    idx = min(3, max(0, level.get(risk_state, 0) + shift))
    return names[idx]
