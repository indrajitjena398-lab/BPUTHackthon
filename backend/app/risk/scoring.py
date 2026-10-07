from app.config import settings

def calculate_risk_level(score: int) -> str:
    """Classify 0-100 risk score into standard enterprise cybersecurity tiers."""
    if score >= settings.RISK_CRITICAL_MIN:
        return "CRITICAL"
    elif score > settings.RISK_MEDIUM_MAX:
        return "HIGH"
    elif score > settings.RISK_LOW_MAX:
        return "MEDIUM"
    elif score > settings.RISK_SAFE_MAX:
        return "LOW"
    else:
        return "SAFE"

def calibrate_score(
    base_score: float,
    confidence: float,
    asset_criticality: str = "HIGH",
    user_sensitivity: str = "HIGH",
    indicator_count: int = 1
) -> int:
    """
    Adjust raw detector score based on environmental context:
    - High-value assets (e.g. Domain Controller, ERP) receive risk multiplier
    - Sensitive users (C-suite, Admin) receive higher vigilance
    - Indicator correlation count boosts confidence
    """
    multiplier = 1.0
    
    # Asset criticality multiplier
    if asset_criticality == "CRITICAL":
        multiplier *= 1.15
    elif asset_criticality == "HIGH":
        multiplier *= 1.05
    elif asset_criticality == "LOW":
        multiplier *= 0.90
        
    # User sensitivity multiplier
    if user_sensitivity == "EXECUTIVE":
        multiplier *= 1.20
    elif user_sensitivity == "ADMIN":
        multiplier *= 1.15
    elif user_sensitivity == "STANDARD":
        multiplier *= 1.0
        
    # Indicator density boost
    if indicator_count >= 4:
        multiplier *= 1.10
    elif indicator_count >= 2:
        multiplier *= 1.05
        
    adjusted = base_score * multiplier * (0.8 + (0.2 * confidence))
    return int(min(99, max(5, round(adjusted))))
