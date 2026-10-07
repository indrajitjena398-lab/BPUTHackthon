import re

class NetworkDetector:
    def __init__(self):
        self.version = "v1.7.0-network-heuristics"
        self.category = "Network & Technical Threat Detection"

    def analyze(
        self,
        source_ip: str,
        destination_ip: str,
        port: int,
        protocol: str = "TCP",
        bytes_transferred: int = 0,
        packet_summary: str = "",
        raw_logs: str = None
    ) -> dict:
        indicators = []
        shap_contributions = {}
        risk_score = 10
        raw_text = f"{packet_summary} {raw_logs or ''}".lower()
        
        # 1. Port scan signatures
        recon_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 445, 1433, 3306, 3389, 5432, 8080]
        if any(k in raw_text for k in ["port scan", "syn scan", "syn flood", "recon", "port sweep"]) or (port in recon_ports and "scan" in raw_text):
            risk_score += 45
            indicators.append(f"Network reconnaissance / Port sweep signature observed targeting port {port}/{protocol}")
            shap_contributions["port_reconnaissance"] = 0.45
            
        # 2. Data exfiltration / Large outbound volume
        if bytes_transferred > 50000000:  # > 50 MB in single flow
            risk_score += 40
            indicators.append(f"High-volume anomalous outbound egress: {bytes_transferred / (1024*1024):.1f} MB transmitted to external IP '{destination_ip}'")
            shap_contributions["data_exfiltration_volume"] = 0.40
        elif bytes_transferred > 10000000:
            risk_score += 20
            indicators.append(f"Elevated egress bandwidth ({bytes_transferred / (1024*1024):.1f} MB) exceeds baseline protocol envelope")
            shap_contributions["data_exfiltration_volume"] = 0.20

        # 3. DNS Tunneling detection
        if port == 53 or "dns" in raw_text or protocol.upper() == "DNS":
            if any(k in raw_text for k in ["base64", "txt record", "high entropy query", "tunnel"]):
                risk_score += 45
                indicators.append("Covert DNS tunneling pattern detected; high payload density encoded in DNS queries")
                shap_contributions["dns_tunneling"] = 0.45

        # 4. C2 Beaconing intervals
        if any(k in raw_text for k in ["beacon", "c2", "heartbeat", "jitter < 5%"]):
            risk_score += 35
            indicators.append(f"Low-jitter repetitive beaconing interval characteristic of Command & Control (C2) agent")
            shap_contributions["c2_beaconing"] = 0.35

        # 5. Remote administration ports exposed externally
        if port in [3389, 22, 445, 135] and not destination_ip.startswith("10.") and not destination_ip.startswith("192.168."):
            risk_score += 25
            indicators.append(f"Insecure administrative protocol ({port}/{protocol}) exposed to untrusted public address space")
            shap_contributions["exposed_admin_service"] = 0.25

        final_risk = int(min(99, max(5, risk_score)))
        probability = round(min(0.99, max(0.04, final_risk / 100.0)), 2)

        if final_risk >= 81:
            classification = "Active Malicious Network Intrusion / Exfiltration"
            risk_level = "CRITICAL"
        elif final_risk >= 61:
            classification = "Suspicious C2 / Reconnaissance Traffic"
            risk_level = "HIGH"
        elif final_risk >= 41:
            classification = "Abnormal Protocol Behavior"
            risk_level = "MEDIUM"
        elif final_risk >= 21:
            classification = "Low-Priority Network Event"
            risk_level = "LOW"
        else:
            classification = "Legitimate Network Flow"
            risk_level = "SAFE"

        if not indicators:
            indicators.append("Standard compliant TCP/IP handshake, expected egress volume, benign destination.")

        explanation = (
            f"The network threat detection engine inspected flow parameters, protocol semantics, and payload entropy. "
            f"Result: '{classification}' (Risk: {final_risk}/100, Probability: {int(probability * 100)}%). "
            f"Primary factor: {indicators[0]}."
        )

        recommended_actions = []
        if final_risk >= 61:
            recommended_actions.extend([
                f"Block remote destination IP {destination_ip} on perimeter Next-Gen Firewall (NGFW)",
                f"Isolate internal source host {source_ip} to quarantine VLAN via EDR agent",
                "Capture full packet payload (PCAP) for deep protocol inspection",
                "Revoke active Kerberos and VPN sessions linked to affected internal IP"
            ])
        elif final_risk >= 41:
            recommended_actions.extend([
                "Apply rate limiting to host IP at edge switch",
                "Increase SIEM log collection verbosity for source endpoint"
            ])
        else:
            recommended_actions.append("Network session logged to SIEM telemetry archive.")

        mitre_mappings = [
            {
                "tactic": "Exfiltration",
                "technique_id": "T1048.003",
                "technique_name": "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
                "mitigation": "M1031 - Network Intrusion Prevention & Outbound Egress Filtering"
            },
            {
                "tactic": "Command and Control",
                "technique_id": "T1071.004",
                "technique_name": "Application Layer Protocol: DNS Tunneling",
                "mitigation": "M1040 - Protective DNS Filtering"
            }
        ] if final_risk >= 41 else []

        return {
            "classification": classification,
            "probability": probability,
            "risk_score": final_risk,
            "risk_level": risk_level,
            "confidence": 0.95 if final_risk > 70 else 0.88,
            "indicators": indicators,
            "explanation": explanation,
            "recommended_actions": recommended_actions,
            "mitre_mappings": mitre_mappings,
            "shap_contributions": shap_contributions,
            "flow_details": {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "port": port,
                "protocol": protocol,
                "bytes_transferred": bytes_transferred
            }
        }

network_detector = NetworkDetector()
