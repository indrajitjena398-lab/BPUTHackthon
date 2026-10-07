import datetime

INITIAL_IOCS = [
    {
        "ioc_type": "domain",
        "value": "micros0ft-support-portal.net",
        "threat_type": "Credential Phishing / C2",
        "confidence": 98,
        "source": "CyberGuard Global TI Feeds",
        "description": "Known Typosquatted Microsoft 365 credential collection portal"
    },
    {
        "ioc_type": "domain",
        "value": "bput-exam-portal-verify.top",
        "threat_type": "Educational Phishing",
        "confidence": 95,
        "source": "State CERT Advisory",
        "description": "Malicious clone targeting student and faculty credential harvesting"
    },
    {
        "ioc_type": "ip",
        "value": "185.220.101.5",
        "threat_type": "Tor Exit Node / Brute Force",
        "confidence": 92,
        "source": "AbuseIPDB Verified",
        "description": "Observed executing automated password spraying and credential stuffing"
    },
    {
        "ioc_type": "ip",
        "value": "194.26.29.112",
        "threat_type": "C2 Infrastructure",
        "confidence": 94,
        "source": "AlienVault OTX",
        "description": "Command and control beacon receiver endpoint"
    },
    {
        "ioc_type": "url",
        "value": "http://185.220.101.5/auth/session/harvest.php",
        "threat_type": "Phishing Landing Page",
        "confidence": 99,
        "source": "CyberGuard Sandbox",
        "description": "Direct IP-hosted login credential exfiltration script"
    },
    {
        "ioc_type": "hash",
        "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "threat_type": "Trojan Dropper",
        "confidence": 90,
        "source": "VirusTotal Intelligence",
        "description": "SHA-256 signature associated with spearphishing invoice payload"
    },
    {
        "ioc_type": "email",
        "value": "ceo-urgent-action@exec-notice-mail.com",
        "threat_type": "Executive Impersonation / BEC",
        "confidence": 96,
        "source": "Internal SOC Telemetry",
        "description": "Active BEC address targeting corporate finance departments"
    }
]

class IOCRepository:
    def __init__(self):
        self.iocs = INITIAL_IOCS.copy()

    def check_match(self, value: str) -> dict | None:
        if not value:
            return None
        val_lower = value.lower().strip()
        for ioc in self.iocs:
            if ioc["value"].lower() == val_lower or val_lower in ioc["value"].lower():
                return ioc
        return None

    def get_all(self) -> list[dict]:
        return self.iocs

    def export_stix21(self) -> dict:
        """Export current IOC database in STIX 2.1 standard JSON format."""
        objects = []
        for i, ioc in enumerate(self.iocs):
            stix_indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--cyberguard-{i+1:04d}",
                "created": datetime.datetime.utcnow().isoformat() + "Z",
                "modified": datetime.datetime.utcnow().isoformat() + "Z",
                "name": f"CyberGuard Indicator: {ioc['value']}",
                "description": ioc["description"],
                "indicator_types": ["malicious-activity"],
                "pattern": f"[{ioc['ioc_type']}:value = '{ioc['value']}']",
                "pattern_type": "stix",
                "confidence": ioc["confidence"]
            }
            objects.append(stix_indicator)

        return {
            "type": "bundle",
            "id": f"bundle--cyberguard-intel-{int(datetime.datetime.utcnow().timestamp())}",
            "objects": objects
        }

ioc_repository = IOCRepository()
