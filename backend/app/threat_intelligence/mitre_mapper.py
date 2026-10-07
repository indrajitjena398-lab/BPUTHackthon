# Standard Enterprise MITRE ATT&CK Matrix mapping for CyberGuard
MITRE_ATTACK_MATRIX = {
    "T1566.001": {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.",
        "mitigation": "M1049 - Antivirus/Antimalware & M1054 - Software Configuration"
    },
    "T1566.002": {
        "id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a link in an attempt to gain access to victim systems or harvest credentials.",
        "mitigation": "M1021 - Restrict Web-Based Content & M1031 - Network Intrusion Prevention"
    },
    "T1036.005": {
        "id": "T1036.005",
        "name": "Masquerading: Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
        "description": "Adversaries may match or approximate legitimate names or locations of software, services, or communication handles.",
        "mitigation": "M1047 - Audit & Digital Signature Verification"
    },
    "T1110.003": {
        "id": "T1110.003",
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "description": "Adversaries may use a single or small list of commonly used passwords against many accounts to avoid lockout thresholds.",
        "mitigation": "M1036 - Account Use Policies & M1032 - Multi-factor Authentication"
    },
    "T1078.004": {
        "id": "T1078.004",
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obtain and abuse credentials of existing cloud accounts to gain initial access, persist, or privilege escalate.",
        "mitigation": "M1026 - Privileged Account Management & Conditional Access"
    },
    "T1071.001": {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols (HTTP/HTTPS) to blend in with normal network traffic.",
        "mitigation": "M1031 - Network Intrusion Prevention & SSL/TLS Inspection"
    },
    "T1071.004": {
        "id": "T1071.004",
        "name": "Application Layer Protocol: DNS Tunneling",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using DNS to covertly bypass network filtering.",
        "mitigation": "M1040 - Protective DNS Filtering"
    },
    "T1048.003": {
        "id": "T1048.003",
        "name": "Exfiltration Over Unencrypted/Obfuscated Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by transferring it over an alternative network protocol without encryption.",
        "mitigation": "M1037 - Filter Network Traffic & DLP Enforcers"
    },
    "T1583.001": {
        "id": "T1583.001",
        "name": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "description": "Adversaries may purchase or register domains that can be used during targeting to support operations (typosquatting).",
        "mitigation": "M1056 - Pre-compromise Threat Intelligence Monitoring"
    }
}

def get_technique_details(technique_id: str) -> dict:
    return MITRE_ATTACK_MATRIX.get(technique_id, {
        "id": technique_id,
        "name": "Custom Cyber Technique",
        "tactic": "Initial Access",
        "description": "Adversary observed executing anomalous activity.",
        "mitigation": "M1030 - General Network Isolation"
    })
