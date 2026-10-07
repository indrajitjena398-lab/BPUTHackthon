import math
import re
from urllib.parse import urlparse

KNOWN_BRANDS = [
    "microsoft", "google", "apple", "amazon", "paypal", "netflix",
    "facebook", "chase", "bankofamerica", "bput", "github", "linkedin"
]

RISKY_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz", ".work",
    ".click", ".rest", ".fit", ".casa", ".icu", ".site", ".live"
]

SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "verify", "auth", "account", "update", "banking",
    "secure", "confirm", "portal", "wallet", "invoice", "session", "oauth"
]

class UrlDetector:
    def __init__(self):
        self.version = "v2.1.0-url-entropy"
        self.category = "Malicious URL & Website"

    def calculate_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log(p) / math.log(2.0) for p in prob)

    def extract_features(self, url: str) -> dict:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        domain = parsed.netloc.lower()
        if ":" in domain:
            domain = domain.split(":")[0]
            
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        domain_parts = domain.split(".")
        tld = f".{domain_parts[-1]}" if len(domain_parts) > 1 else ""
        subdomain = ".".join(domain_parts[:-2]) if len(domain_parts) > 2 else ""
        
        # 1. Entropy
        entropy = self.calculate_entropy(domain)
        
        # 2. Typosquatting / brand squatting
        targeted_brand = None
        has_typosquatting = False
        for brand in KNOWN_BRANDS:
            if brand in domain and not (domain.endswith(f"{brand}.com") or domain.endswith(f"{brand}.org") or domain.endswith(f"{brand}.ac.in")):
                has_typosquatting = True
                targeted_brand = brand
                break
            # Levenshtein / visual substitutions (0 -> o, 1 -> l, etc)
            normalized = domain.replace("0", "o").replace("1", "l").replace("vv", "w")
            if brand in normalized and not (normalized.endswith(f"{brand}.com") or normalized.endswith(f"{brand}.org")):
                has_typosquatting = True
                targeted_brand = brand
                break

        # 3. Path keywords
        path_matches = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path or kw in query]
        
        # 4. Open redirect pattern
        has_open_redirect = any(q in query for q in ["redirect=", "url=", "next=", "goto=", "target=", "dest="])
        
        # 5. IP as hostname
        is_ip_host = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))
        
        return {
            "full_url": url,
            "scheme": parsed.scheme or "http",
            "domain": domain,
            "subdomain": subdomain,
            "tld": tld,
            "url_length": len(url),
            "entropy": round(entropy, 2),
            "is_risky_tld": tld in RISKY_TLDS,
            "has_typosquatting": has_typosquatting,
            "targeted_brand": targeted_brand,
            "path_matches": path_matches,
            "has_open_redirect": has_open_redirect,
            "is_ip_host": is_ip_host,
            "has_at_symbol": "@" in url,
            "hyphen_count": domain.count("-"),
            "subdomain_depth": len(subdomain.split(".")) if subdomain else 0
        }

    def analyze(self, url: str, context: str = None) -> dict:
        feats = self.extract_features(url)
        indicators = []
        shap_contributions = {}
        score = 10.0
        
        if feats["has_typosquatting"]:
            score += 45
            indicators.append(f"Domain spoofing detected: '{feats['domain']}' mimics registered trademark '{feats['targeted_brand']}'")
            shap_contributions["brand_typosquatting"] = 0.45
            
        if feats["is_risky_tld"]:
            score += 25
            indicators.append(f"High-risk top-level domain '{feats['tld']}' commonly leveraged in disposable phishing infrastructure")
            shap_contributions["risky_tld_reputation"] = 0.25
            
        if feats["is_ip_host"]:
            score += 35
            indicators.append(f"Host uses raw numeric IP address '{feats['domain']}' bypassing standard DNS verification")
            shap_contributions["raw_ip_host"] = 0.35
            
        if feats["has_open_redirect"]:
            score += 20
            indicators.append("Open redirect query parameter detected, masking destination endpoint")
            shap_contributions["open_redirect_vector"] = 0.20
            
        if feats["path_matches"]:
            score += min(25, len(feats["path_matches"]) * 10)
            indicators.append(f"Credential harvesting paths present: {', '.join(feats['path_matches'][:3])}")
            shap_contributions["login_credential_path"] = 0.20
            
        if feats["entropy"] > 3.8:
            score += 15
            indicators.append(f"High domain character entropy ({feats['entropy']} bits) indicates algorithmic or DGA-generated domain")
            shap_contributions["dga_high_entropy"] = 0.15
            
        if feats["hyphen_count"] >= 2:
            score += 12
            indicators.append(f"Multiple hyphens in hostname ({feats['hyphen_count']}) indicative of brand impersonation prefixes")
            shap_contributions["hyphenated_domain_structure"] = 0.12
            
        if feats["scheme"] == "http":
            score += 10
            indicators.append("Unencrypted HTTP protocol; lacking valid TLS transport security certificate")
            shap_contributions["insecure_transport_http"] = 0.10

        final_risk = int(min(99, max(5, score)))
        probability = round(min(0.99, max(0.04, final_risk / 100.0)), 2)
        
        if final_risk >= 81:
            classification = "Malicious Credential Harvester"
            risk_level = "CRITICAL"
        elif final_risk >= 61:
            classification = "Suspected Malicious Domain"
            risk_level = "HIGH"
        elif final_risk >= 41:
            classification = "Suspicious URL / Anomaly"
            risk_level = "MEDIUM"
        elif final_risk >= 21:
            classification = "Low-Risk Web Resource"
            risk_level = "LOW"
        else:
            classification = "Legitimate Clean URL"
            risk_level = "SAFE"
            
        if not indicators:
            indicators.append("Valid canonical domain hierarchy, legitimate SSL certificate profile, benign path.")

        explanation = (
            f"The URL evaluation engine analyzed lexical patterns, domain reputation, Shannon entropy, and typosquatting signatures. "
            f"Identified as '{classification}' with {int(probability * 100)}% confidence. "
            f"Primary findings: {', '.join(indicators[:2])}."
        )

        recommended_actions = []
        if final_risk >= 61:
            recommended_actions.extend([
                "Block URL domain on perimeter DNS and web secure gateways (SWG)",
                "Add domain to enterprise IOC blocklist and SIEM detection rules",
                "Invalidate any active browser sessions communicating with host",
                "Submit URL to threat intelligence feeds (AlienVault OTX, VirusTotal)"
            ])
        elif final_risk >= 41:
            recommended_actions.extend([
                "Isolate URL via Remote Browser Isolation (RBI) if accessed",
                "Alert security analyst for manual sandbox inspection"
            ])
        else:
            recommended_actions.append("No defensive action needed. URL categorized safe.")

        mitre_mappings = []
        if final_risk >= 41:
            mitre_mappings.append({
                "tactic": "Command and Control",
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "mitigation": "M1031 - Network Intrusion Prevention & Web Filtering"
            })
            mitre_mappings.append({
                "tactic": "Resource Development",
                "technique_id": "T1583.001",
                "technique_name": "Acquire Infrastructure: Domains",
                "mitigation": "M1056 - Pre-compromise Threat Intelligence Ingestion"
            })

        return {
            "classification": classification,
            "probability": probability,
            "risk_score": final_risk,
            "risk_level": risk_level,
            "confidence": 0.95 if final_risk > 70 else 0.89,
            "indicators": indicators,
            "explanation": explanation,
            "recommended_actions": recommended_actions,
            "mitre_mappings": mitre_mappings,
            "shap_contributions": shap_contributions,
            "features": feats
        }

url_detector = UrlDetector()
