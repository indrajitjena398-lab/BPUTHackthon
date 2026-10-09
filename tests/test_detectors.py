import pytest
import os
import sys

# Ensure backend directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.detectors.phishing_detector import phishing_detector
from app.detectors.url_detector import url_detector
from app.detectors.deepfake_detector import deepfake_detector
from app.detectors.impersonation_detector import impersonation_detector
from app.detectors.behavior_detector import behavior_detector
from app.detectors.network_detector import network_detector
from app.detectors.quishing_detector import quishing_detector
from app.detectors.ai_generated_phishing_detector import ai_phishing_detector
from app.detectors.steganography_detector import steganography_detector
from app.risk.fusion_engine import fusion_engine
from app.threat_intelligence.ioc_repo import ioc_repository

def test_phishing_detector_high_urgency():
    res = phishing_detector.analyze(
        subject="URGENT: Your Account Has Been Suspended",
        sender="security@paypal-security.org",
        body="Action required immediately! Sign in to verify your account credentials within 24 hours or your access will be terminated.",
        links=["http://paypal-security.org/login/verify.php"]
    )
    assert res["risk_score"] >= 80
    assert res["risk_level"] in ["HIGH", "CRITICAL"]
    assert len(res["indicators"]) >= 2

def test_phishing_detector_clean_email():
    res = phishing_detector.analyze(
        subject="Team Meeting Notes - Project Milestone Update",
        sender="colleague@bput.ac.in",
        body="Hi team, please find attached the minutes from our weekly sync. Have a great weekend.",
        links=[]
    )
    assert res["risk_score"] < 40
    assert res["risk_level"] in ["SAFE", "LOW"]

def test_url_detector_typosquatting():
    res = url_detector.analyze("http://micros0ft-login-verify.top/auth/session")
    assert res["risk_score"] >= 70
    assert res["features"]["has_typosquatting"] is True
    assert res["features"]["is_risky_tld"] is True

def test_deepfake_detector_labels():
    res = deepfake_detector.fallback_analysis("image", "face_test.jpg")
    assert "authenticity_score" in res
    assert "manipulation_probability" in res
    assert "status_label" in res
    assert res["confidence"] > 0.8

def test_impersonation_detector_vip_spoof():
    res = impersonation_detector.analyze(
        claimed_name="Satya Nadella",
        sender_email="satya-nadella@exec-mail-wire.com",
        content="Are you at your desk? I need an urgent wire transfer executed for a confidential acquisition."
    )
    assert res["is_impersonation"] is True
    assert res["risk_score"] >= 80
    assert res["risk_level"] in ["HIGH", "CRITICAL"]

def test_university_authority_impersonation():
    res = impersonation_detector.analyze(
        claimed_name="Prof. Amiya Kumar Rath",
        sender_email="vc-notice@bput-exam-portal.top",
        content="Students and faculty must verify semester registration by submitting examination fee immediately."
    )
    assert res["is_impersonation"] is True
    assert res["target_entity"]["category"] == "University / Academic Authority"
    assert res["risk_score"] >= 80

def test_quishing_detector():
    # Pass simulated quishing payload
    res = quishing_detector.analyze_image_bytes(b"dummy_qr_bytes", filename="quishing_poster.png")
    assert res["is_quishing"] is True
    assert res["qr_detected"] is True
    assert res["risk_score"] >= 75
    assert len(res["indicators"]) >= 1

def test_ai_generated_phishing_detector():
    ai_text = (
        "Kindly be advised that it is imperative that you take immediate action to ensure your access is preserved. "
        "Failure to comply will result in account termination in accordance with our security policy."
    )
    res = ai_phishing_detector.analyze(ai_text)
    assert "ai_generated_probability" in res
    assert res["ai_generated_probability"] > 0.5
    assert "burstiness_score" in res["stylometric_metrics"]

def test_behavior_detector_impossible_travel():
    res = behavior_detector.analyze(
        user_email="ankit.kumar@bput.ac.in",
        login_location="Frankfurt, Germany",
        ip_address="185.220.101.5",
        device_name="Unknown Linux Box",
        browser="Headless Chrome",
        failed_attempts=5
    )
    assert res["risk_score"] >= 80
    assert res["risk_level"] in ["HIGH", "CRITICAL"]
    assert res["behavioral_details"]["is_new_country"] is True
    assert res["behavioral_details"]["is_new_device"] is True

def test_network_detector_recon():
    res = network_detector.analyze(
        source_ip="192.168.1.50",
        destination_ip="10.14.0.25",
        port=445,
        protocol="TCP",
        bytes_transferred=60000000,
        packet_summary="Rapid SYN scan pattern detected with large payload egress"
    )
    assert res["risk_score"] >= 70
    assert len(res["indicators"]) >= 1

def test_threat_fusion_engine():
    phish_res = phishing_detector.analyze(
        subject="Urgent Security Alert",
        sender="support@micros0ft-portal.net",
        body="Please sign in to verify credentials immediately."
    )
    url_res = url_detector.analyze("http://micros0ft-portal.net/login")
    
    fused = fusion_engine.fuse(
        primary_category="Phishing",
        detector_results={
            "phishing_nlp": phish_res,
            "url_analysis": url_res
        },
        asset_criticality="CRITICAL",
        user_sensitivity="ADMIN"
    )
    assert fused["risk_score"] >= 75
    assert len(fused["indicators"]) >= 2
    assert "detector_breakdown" in fused

def test_ioc_repository_lookup():
    match = ioc_repository.check_match("185.220.101.5")
    assert match is not None
    assert match["threat_type"] == "Tor Exit Node / Brute Force"

def test_steganography_detector_embedded_c2():
    # Construct PNG with appended C2 URL past IEND chunk
    clean_png = (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00\x90\x91\x68\x36"
        b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
    )
    stego_payload = b"\x00\x00\x00STEG_C2_PAYLOAD: http://bput-c2-tunnel.darknet-relay.top/beacon/exfil.php COMMAND=POLL"
    carrier_bytes = clean_png + stego_payload

    res = steganography_detector.analyze_image_bytes(carrier_bytes, filename="test_stego_carrier.png")
    assert res["is_steganography"] is True
    assert res["risk_score"] >= 80
    assert res["risk_level"] in ["HIGH", "CRITICAL"]
    assert len(res["recovered_urls"]) >= 1
    assert "http://bput-c2-tunnel.darknet-relay.top/beacon/exfil.php" in res["recovered_urls"]
    assert res["forensic_details"]["eof_overlay_detected"] is True
    assert len(res["mitre_mappings"]) >= 1

def test_steganography_detector_clean_image():
    clean_png = (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00\x90\x91\x68\x36"
        b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
    )
    res = steganography_detector.analyze_image_bytes(clean_png, filename="clean_image.png")
    assert res["is_steganography"] is False
    assert res["risk_score"] <= 30
    assert res["risk_level"] in ["SAFE", "LOW"]
    assert res["forensic_details"]["eof_overlay_detected"] is False
    assert len(res["recovered_urls"]) == 0

