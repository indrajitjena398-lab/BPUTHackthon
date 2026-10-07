from typing import Any
from app.risk.scoring import calculate_risk_level, calibrate_score

class ThreatFusionEngine:
    def __init__(self):
        self.version = "v2.0-dynamic-evidence-fusion"
        # Configurable model weightings
        self.weights = {
            "phishing_nlp": 0.25,
            "url_analysis": 0.25,
            "identity_impersonation": 0.20,
            "behavior_anomaly": 0.15,
            "multimedia_deepfake": 0.15,
            "network_threat": 0.15,
            "threat_intelligence": 0.20
        }

    def fuse(
        self,
        primary_category: str,
        detector_results: dict[str, dict[str, Any]],
        asset_criticality: str = "HIGH",
        user_sensitivity: str = "HIGH"
    ) -> dict[str, Any]:
        """
        Combines multi-modal detector scores, retaining all underlying evidence.
        Example:
            detector_results = {
                "phishing": {...},
                "url": {...},
                "identity": {...},
                "threat_intel": {...}
            }
        """
        all_indicators = []
        all_actions = set()
        all_mitre = []
        shap_aggregated = {}
        weighted_sum = 0.0
        total_weight = 0.0
        confidences = []

        # Track granular breakdown
        detector_breakdown = {}

        for detector_key, res in detector_results.items():
            if not res:
                continue
                
            score = float(res.get("risk_score", 10))
            conf = float(res.get("confidence", 0.85))
            weight = self.weights.get(detector_key, 0.20)

            detector_breakdown[detector_key] = {
                "score": int(score),
                "confidence": conf,
                "classification": res.get("classification", "N/A"),
                "risk_level": res.get("risk_level", "LOW")
            }

            weighted_sum += score * weight
            total_weight += weight
            confidences.append(conf)

            # Preserve granular evidence
            for ind in res.get("indicators", []):
                if ind not in all_indicators:
                    all_indicators.append(ind)
                    
            for act in res.get("recommended_actions", []):
                all_actions.add(act)

            for mit in res.get("mitre_mappings", []):
                if mit not in all_mitre:
                    all_mitre.append(mit)

            for feat, val in res.get("shap_contributions", {}).items():
                shap_aggregated[f"{detector_key}:{feat}"] = val

        # Handle case where max single detector detected an extreme threat
        max_single_score = max([d["score"] for d in detector_breakdown.values()]) if detector_breakdown else 10
        base_fused = (weighted_sum / total_weight) if total_weight > 0 else 10.0
        
        # Threat Fusion logic: if any primary engine found high/critical certainty,
        # blend base average with the max detector score so critical threats aren't diluted
        fused_raw = (base_fused * 0.4) + (max_single_score * 0.6)
        avg_confidence = float(sum(confidences) / len(confidences)) if confidences else 0.85

        final_score = calibrate_score(
            base_score=fused_raw,
            confidence=avg_confidence,
            asset_criticality=asset_criticality,
            user_sensitivity=user_sensitivity,
            indicator_count=len(all_indicators)
        )

        final_level = calculate_risk_level(final_score)

        # Unified Classification
        if final_score >= 81:
            classification = f"CRITICAL {primary_category.upper()} INCIDENT"
        elif final_score >= 61:
            classification = f"HIGH-RISK {primary_category.upper()}"
        elif final_score >= 41:
            classification = f"SUSPICIOUS {primary_category.upper()}"
        elif final_score >= 21:
            classification = f"LOW-RISK {primary_category.upper()}"
        else:
            classification = f"VERIFIED SAFE {primary_category.upper()}"

        # Explainable synthesis
        evidence_summary = (
            f"Threat Fusion Engine synthesized {len(detector_breakdown)} detection pipelines "
            f"with an overall risk score of {final_score}/100 ({final_level}). "
            f"Key corroborating evidence includes: {'; '.join(all_indicators[:3])}."
        )

        return {
            "classification": classification,
            "probability": round(min(0.99, final_score / 100.0), 2),
            "risk_score": final_score,
            "risk_level": final_level,
            "confidence": round(avg_confidence, 2),
            "indicators": all_indicators,
            "explanation": evidence_summary,
            "recommended_actions": list(all_actions),
            "mitre_mappings": all_mitre,
            "shap_contributions": shap_aggregated,
            "detector_breakdown": detector_breakdown
        }

fusion_engine = ThreatFusionEngine()
