from datetime import datetime, timedelta
from app.engines.mosca import SENSITIVITY_SHELF_LIFE, get_gri_crqc_probability, GRI_PROBABILITY_TABLE

# HNDL: Harvest Now, Decrypt Later
# Exposure = Traffic Volume * Retention Window * Sensitivity * CRQC Arrival Probability
#
# HONESTY NOTE: only the CRQC arrival probability term is model-derived (see
# mosca.get_gri_crqc_probability). The per-tier traffic volumes and sensitivity
# multipliers below are ILLUSTRATIVE, configurable planning baselines — they are
# NOT measured traffic and NOT sourced from any GRI publication. The resulting
# "GB at risk" is therefore a theoretical planning ceiling, not telemetry.

TIER_TRAFFIC_BASELINES = {
    "S1": 800, # illustrative core transaction throughput (GB/month)
    "S2": 400, # illustrative identity / auth API traffic
    "S3": 200, # illustrative statement & payment-log traffic
    "S4": 80,  # illustrative internal microservice traffic
    "S5": 20   # illustrative public portal content
}

def calculate_hndl_exposure(asset: dict, harvest_start_date: str = "2023-01-01"):
    # Only relevant for assets lacking forward secrecy or relying on broken/quantum-vulnerable keys
    if asset.get("forward_secrecy", False) and asset.get("is_pqc", False):
        return None
    
    sensitivity_tier = asset.get("sensitivity_tier", "S5")
    shelf_life_years = SENSITIVITY_SHELF_LIFE.get(sensitivity_tier, 1)

    sensitivity_multiplier = {
        "S1": 10.0, "S2": 5.0, "S3": 2.0, "S4": 1.0, "S5": 0.5
    }.get(sensitivity_tier, 0.5)
    
    # Deterministic traffic volume (GB/month) based on enterprise sensitivity tier
    traffic_volume = TIER_TRAFFIC_BASELINES.get(sensitivity_tier, 20)
    
    # Months of adversary traffic interception accumulated so far
    try:
        harvest_start = datetime.strptime(harvest_start_date, "%Y-%m-%d")
    except ValueError:
        harvest_start = datetime(2023, 1, 1)
        
    months_captured = max(1, (datetime.now() - harvest_start).days // 30)
    total_gb_at_risk = traffic_volume * months_captured

    # GRI Probability Weight: likelihood that a CRQC arrives during the data's useful shelf life
    gri_prob_median = get_gri_crqc_probability(float(shelf_life_years), bound="median")
    gri_prob_upper = get_gri_crqc_probability(float(shelf_life_years), bound="upper")

    # Modulated exposure value (GB * sensitivity * probability). No probability
    # floor — the weight is exactly the model arrival probability so the reported
    # hndl_risk_score reconciles with gri_arrival_probability.
    raw_exposure = total_gb_at_risk * sensitivity_multiplier
    probability_weighted_risk = raw_exposure * gri_prob_median

    return {
        "traffic_volume_monthly_gb": traffic_volume,
        "months_captured": months_captured,
        "total_gb_at_risk": total_gb_at_risk,
        "hndl_risk_score": round(probability_weighted_risk, 2),
        "raw_exposure_score": round(raw_exposure, 2),
        "gri_arrival_probability": round(gri_prob_median, 3),
        "gri_upper_probability": round(gri_prob_upper, 3),
        "retention_shelf_life_years": shelf_life_years,
        "harvest_start_date": harvest_start.isoformat(),
        "traffic_basis": "illustrative tier baseline (configurable, not measured telemetry)",
        "estimate_type": "theoretical planning ceiling",
        "methodology_note": ("Probability-weighted HNDL model. Arrival probability from the "
                             "CRQC planning curve; traffic/sensitivity weights are illustrative "
                             "configurable baselines, not measured or GRI-published.")
    }
