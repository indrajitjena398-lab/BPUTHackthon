import pytest
import os
import sys
import io
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.main import app

client = TestClient(app)

def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert data["database"] == "CONNECTED"

def test_auth_login():
    res = client.post("/api/auth/login", json={
        "email": "analyst@cyberguard.local",
        "password": "any_password"
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user_info"]["role"] == "Security Analyst"

def test_auth_switch_demo_role():
    res = client.post("/api/auth/switch-demo-role?role=Admin")
    assert res.status_code == 200
    data = res.json()
    assert data["user_info"]["role"] == "Admin"

def test_dashboard_metrics_and_kill_chain():
    res = client.get("/api/dashboard/metrics")
    assert res.status_code == 200
    data = res.json()
    assert data["events_analyzed"] > 0
    assert "Phishing" in data["threats_by_category"]
    assert "Safe (0-20)" in data["risk_distribution"]
    # Check new Page 5 fields
    assert "attack_timeline" in data
    assert len(data["attack_timeline"]) >= 3
    assert "frequently_targeted_users" in data
    assert len(data["frequently_targeted_users"]) >= 3
    assert "frequently_targeted_services" in data

def test_analyze_email_endpoint():
    res = client.post("/api/analyze/email", json={
        "subject": "CRITICAL: Security Breach Detected - Verify Credentials Immediately",
        "sender": "alert@micros0ft-portal.net",
        "body": "Your corporate account will be suspended within 24 hours. Sign in to confirm identity.",
        "recipient": "victim@enterprise.com",
        "links": ["http://micros0ft-portal.net/login/verify.php"]
    })
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] >= 80
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert len(data["indicators"]) >= 2
    assert len(data["recommended_actions"]) >= 1

def test_analyze_url_endpoint():
    res = client.post("/api/analyze/url", json={
        "url": "http://bput-exam-portal-verify.top/auth/session/harvest.php",
        "context": "User clicked in suspicious message"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] >= 75
    assert data["risk_level"] in ["HIGH", "CRITICAL"]

def test_analyze_quishing_endpoint():
    file_bytes = b"fake_qr_png_bytes"
    res = client.post(
        "/api/analyze/quishing",
        files={"file": ("quishing_scan.png", io.BytesIO(file_bytes), "image/png")}
    )
    assert res.status_code == 200
    data = res.json()
    assert "is_quishing" in data
    assert "risk_score" in data

def test_analyze_genai_phishing_endpoint():
    res = client.post(
        "/api/analyze/genai-phishing",
        data={"text": "Kindly be advised that it is imperative to take immediate action to preserve uninterrupted access."}
    )
    assert res.status_code == 200
    data = res.json()
    assert "ai_generated_probability" in data
    assert "stylometric_metrics" in data

def test_incidents_lifecycle():
    res = client.post("/api/incidents", json={
        "title": "Suspected API Key Exfiltration",
        "severity": "HIGH",
        "category": "Network Threat",
        "affected_user": "dev-ops@enterprise.com",
        "affected_asset": "Kubernetes Ingress Gateway",
        "detection_source": "WAF Log Inspector",
        "assigned_analyst": "Marcus Chen"
    })
    assert res.status_code == 200
    inc_id = res.json()["incident_id"]

    up_res = client.patch(f"/api/incidents/{inc_id}", json={
        "status": "Contained",
        "resolution_notes": "Ingress token revoked and regenerated"
    })
    assert up_res.status_code == 200
    assert up_res.json()["current_status"] == "Contained"

def test_response_execution_and_rollback():
    exec_res = client.post("/api/response/execute", json={
        "action_type": "Quarantine Email",
        "target": "malicious-phish@external.net",
        "reason": "High-urgency phishing payload detected",
        "evidence_summary": "Lookalike domain and credential harvesting keywords"
    })
    assert exec_res.status_code == 200
    action_data = exec_res.json()
    action_id = action_data["action_id"]
    assert action_data["status"] == "EXECUTED"

    rb_res = client.post(f"/api/response/rollback/{action_id}")
    assert rb_res.status_code == 200
    assert rb_res.json()["status"] == "ROLLED_BACK"

def test_assistant_query():
    res = client.post("/api/assistant/query", json={
        "query": "What MITRE techniques are relevant for phishing and credential harvesting?",
        "incident_id": None
    })
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert len(data["answer"]) > 50

def test_attack_graph_endpoint():
    res = client.get("/api/graph")
    assert res.status_code == 200
    data = res.json()
    assert len(data["nodes"]) > 0
    assert len(data["edges"]) > 0

def test_settings_models_registry():
    res = client.get("/api/settings/models")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 7
    for m in data:
        assert "status" in m
        assert "latency_ms" in m
