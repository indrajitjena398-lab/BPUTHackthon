import datetime
from app.database import SessionLocal, Base, engine
from app.models.sql_models import (
    User, Threat, Incident, Evidence, Asset, Device, Session, IOC,
    ThreatIntelligence, ResponseAction, AuditLog, Notification
)
from app.threat_intelligence.ioc_repo import INITIAL_IOCS
from app.threat_intelligence.mitre_mapper import MITRE_ATTACK_MATRIX

def seed_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # Check if already seeded
    if db.query(User).count() > 0:
        db.close()
        return

    print("Seeding initial CyberGuard enterprise dataset...")

    # 1. Users
    users = [
        User(email="admin@cyberguard.local", full_name="Eleanor Vance (Enterprise Admin)", hashed_password="hashed_secret", role="Admin", department="Global IT Security"),
        User(email="analyst@cyberguard.local", full_name="Ankit Kumar (Senior Security Analyst)", hashed_password="hashed_secret", role="Security Analyst", department="SOC Threat Intelligence"),
        User(email="operator@cyberguard.local", full_name="Marcus Chen (Tier-2 SOC Operator)", hashed_password="hashed_secret", role="SOC Operator", department="Incident Operations Center"),
        User(email="manager@cyberguard.local", full_name="Dr. Sarah Al-Mansoor (CISO)", hashed_password="hashed_secret", role="Organisation Manager", department="Executive Cyber Governance"),
        User(email="viewer@cyberguard.local", full_name="David Ross (Compliance Auditor)", hashed_password="hashed_secret", role="Viewer", department="Internal Risk & Audit"),
        User(email="cfo@enterprise.com", full_name="Robert Hastings (CFO)", hashed_password="hashed_secret", role="Viewer", department="Corporate Finance"),
        User(email="ankit.kumar@bput.ac.in", full_name="Ankit Kumar (Staff/Faculty)", hashed_password="hashed_secret", role="Security Analyst", department="Computer Science & Engineering")
    ]
    db.add_all(users)

    # 2. Assets
    assets = [
        Asset(asset_id="AST-001", name="Identity Provider (Okta/AD Connector)", asset_type="Cloud Service", ip_address="10.14.0.12", owner="SecOps Team", critical_level="CRITICAL", status="Healthy"),
        Asset(asset_id="AST-002", name="Perimeter Exchange Mail Gateway", asset_type="Server", ip_address="10.14.0.25", owner="Exchange Admins", critical_level="CRITICAL", status="Warning"),
        Asset(asset_id="AST-003", name="Financial ERP Core Database", asset_type="Database", ip_address="10.14.10.88", owner="Finance IT", critical_level="CRITICAL", status="Healthy"),
        Asset(asset_id="AST-004", name="Campus Web Portal Server", asset_type="Server", ip_address="192.168.1.100", owner="Web Infrastructure", critical_level="HIGH", status="Healthy"),
        Asset(asset_id="AST-005", name="Core DNS & DHCP Gateway", asset_type="API Gateway", ip_address="10.14.0.1", owner="Network Infrastructure", critical_level="HIGH", status="Warning")
    ]
    db.add_all(assets)

    # 3. IOCs
    for item in INITIAL_IOCS:
        ioc = IOC(
            ioc_type=item["ioc_type"],
            value=item["value"],
            threat_type=item["threat_type"],
            confidence=item["confidence"],
            source=item["source"],
            description=item["description"],
            first_seen=datetime.datetime.utcnow() - datetime.timedelta(days=3),
            last_seen=datetime.datetime.utcnow()
        )
        db.add(ioc)

    # 4. MITRE entries
    for m_id, item in MITRE_ATTACK_MATRIX.items():
        ti = ThreatIntelligence(
            title=item["name"],
            threat_type=item["tactic"],
            mitre_technique_id=item["id"],
            mitre_technique_name=item["name"],
            severity="HIGH",
            description=item["description"],
            indicators_json=["Correlated via CyberGuard behavioral detectors"],
            mitigation=item["mitigation"]
        )
        db.add(ti)

    # 5. Baseline Threats & Incidents (Demo Scenarios)
    demo_scenarios = [
        {
            "threat_id": "THT-20261006-001A",
            "category": "Phishing",
            "classification": "Urgent Credential Harvesting Phishing",
            "risk_score": 92,
            "risk_level": "CRITICAL",
            "confidence": 0.94,
            "user": "finance-officer@enterprise.com",
            "asset": "Perimeter Exchange Mailbox",
            "indicators": [
                "Sender domain 'service-security-chase.com' mimics legitimate financial institution",
                "Severe urgency language detected: 'Your account will be suspended in 24 hours'",
                "Embedded link routes to credential harvesting script on newly registered .xyz TLD",
                "SPF/DKIM cryptographic validation failed on inbound message transport"
            ],
            "explanation": "Threat Fusion Engine identified coordinated spearphishing payload targeting corporate financial officers with deceptive credential extraction forms.",
            "inc_title": "Critical Phishing Campaign Targeting Corporate Finance",
            "inc_status": "Investigating"
        },
        {
            "threat_id": "THT-20261006-002B",
            "category": "Impersonation",
            "classification": "Executive BEC & Synthetic Voice Media",
            "risk_score": 89,
            "risk_level": "CRITICAL",
            "confidence": 0.96,
            "user": "accounts-payable@enterprise.com",
            "asset": "Executive Communications Channel",
            "indicators": [
                "Display name 'Satya Nadella' spoofed from non-corporate domain 'exec-updates.org'",
                "Audio voicemail attached exhibited synthetic neural vocoder characteristics (authenticity score: 18/100)",
                "Demands emergency wire transfer with instruction to bypass standard multi-signature signoff",
                "Sender IP matches foreign anonymizing proxy node"
            ],
            "explanation": "High-confidence digital impersonation combined with synthetic audio voice cloning attempting business email compromise (BEC).",
            "inc_title": "Executive Impersonation & Deepfake Voice Authorization Fraud",
            "inc_status": "Contained"
        },
        {
            "threat_id": "THT-20261006-003C",
            "category": "Account Takeover",
            "classification": "Impossible Travel & Credential Stuffing",
            "risk_score": 94,
            "risk_level": "CRITICAL",
            "confidence": 0.95,
            "user": "cfo@enterprise.com",
            "asset": "Cloud Identity Provider / Workstation",
            "indicators": [
                "Impossible travel detected: User logged in from Mumbai, followed 14 minutes later by Frankfurt, Germany",
                "Hardware fingerprint does not match any registered corporate laptop or mobile device",
                "Preceded by 7 consecutive failed password attempts within 90 seconds",
                "Isolation Forest anomaly detector produced an extreme outlier score (-0.42)"
            ],
            "explanation": "Behavioral analytics confirmed account takeover attempt via stolen session token or credential replay from unapproved geographic region.",
            "inc_title": "Account Takeover & Impossible Travel: CFO Account",
            "inc_status": "Contained"
        },
        {
            "threat_id": "THT-20261006-004D",
            "category": "Network Threat",
            "classification": "Covert DNS Tunneling & Data Exfiltration",
            "risk_score": 84,
            "risk_level": "HIGH",
            "confidence": 0.91,
            "user": "Host 10.14.80.114",
            "asset": "Core DNS Gateway Port 53",
            "indicators": [
                "Abnormal volume of high-entropy TXT queries directed towards unregistered domain",
                "Repetitive beaconing interval observed at 30-second heartbeats with <2% jitter",
                "Total outbound payload transferred via DNS queries exceeded 48 MB over 1 hour",
                "Matches MITRE ATT&CK Technique T1071.004 (DNS Tunneling)"
            ],
            "explanation": "Network heuristics identified automated data exfiltration leveraging covert DNS query tunneling to bypass perimeter egress proxies.",
            "inc_title": "DNS Tunneling Exfiltration from Engineering VLAN",
            "inc_status": "New"
        }
    ]

    for s in demo_scenarios:
        threat = Threat(
            threat_id=s["threat_id"],
            category=s["category"],
            classification=s["classification"],
            risk_score=s["risk_score"],
            risk_level=s["risk_level"],
            confidence=s["confidence"],
            status="ACTIVE",
            indicators_json=s["indicators"],
            explanation=s["explanation"],
            mitre_tactics_json=[{
                "tactic": "Initial Access",
                "technique_id": "T1566.002",
                "technique_name": "Spearphishing Link",
                "mitigation": "M1049 - Antivirus & Email Gateway Filtering"
            }]
        )
        db.add(threat)
        
        inc_id = f"INC-20261006-{s['threat_id'][-4:]}"
        inc = Incident(
            incident_id=inc_id,
            threat_id=s["threat_id"],
            title=s["inc_title"],
            severity=s["risk_level"],
            category=s["category"],
            affected_user=s["user"],
            affected_asset=s["asset"],
            detection_source="CyberGuard Threat Fusion Engine",
            status=s["inc_status"],
            assigned_analyst="Ankit Kumar (Senior Security Analyst)",
            timeline_json=[
                {"timestamp": (datetime.datetime.utcnow() - datetime.timedelta(minutes=30)).isoformat(), "event": "Threat signature triggered in ingestion stream", "actor": "Fusion Engine"},
                {"timestamp": (datetime.datetime.utcnow() - datetime.timedelta(minutes=25)).isoformat(), "event": "Incident escalated to Tier-2 SOC Queue", "actor": "Automated Policy"},
                {"timestamp": (datetime.datetime.utcnow() - datetime.timedelta(minutes=15)).isoformat(), "event": "Assigned to Security Analyst for containment", "actor": "Marcus Chen"}
            ],
            resolution_notes="Containment playbooks successfully dispatched." if s["inc_status"] == "Contained" else None
        )
        db.add(inc)

        # Evidence
        for ind in s["indicators"]:
            ev = Evidence(
                threat_id=s["threat_id"],
                detector=s["category"],
                rule_name="Enterprise Threat Signature",
                score=float(s["risk_score"]),
                detail=ind,
                raw_features_json={}
            )
            db.add(ev)

        # Baseline defensive action
        action = ResponseAction(
            action_id=f"ACT-20261006-{s['threat_id'][-4:]}",
            incident_id=inc_id,
            threat_id=s["threat_id"],
            action_type="Quarantine Email" if s["category"] == "Phishing" else ("Require MFA" if s["category"] == "Account Takeover" else "Block IP"),
            target=s["user"],
            reason=f"Automated risk mitigation for {s['classification']}",
            evidence_summary=s["indicators"][0],
            status="EXECUTED",
            actor="Security Policy Engine",
            executed_at=datetime.datetime.utcnow() - datetime.timedelta(minutes=10),
            rollback_action=f"Release {s['user']} from quarantine",
            rolled_back=False
        )
        db.add(action)

    db.commit()
    db.close()
    print("Database successfully seeded with realistic enterprise cybersecurity telemetry.")

if __name__ == "__main__":
    seed_database()
