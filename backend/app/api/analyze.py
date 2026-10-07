import datetime
import uuid
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.schemas import (
    EmailAnalysisRequest, UrlAnalysisRequest, BehavioralLogRequest,
    NetworkLogRequest, EventCreate, DetectionResultOutput, DeepfakeAnalysisOutput
)
from app.models.sql_models import Threat, Incident, Event, Evidence, AuditLog
from app.detectors.phishing_detector import phishing_detector
from app.detectors.url_detector import url_detector
from app.detectors.deepfake_detector import deepfake_detector
from app.detectors.impersonation_detector import impersonation_detector
from app.detectors.behavior_detector import behavior_detector
from app.detectors.network_detector import network_detector
from app.detectors.quishing_detector import quishing_detector
from app.detectors.ai_generated_phishing_detector import ai_phishing_detector
from app.risk.fusion_engine import fusion_engine

from app.explainability.xai_service import xai_service
from app.threat_intelligence.ioc_repo import ioc_repository
from app.services.websocket_manager import ws_manager

router = APIRouter(prefix="/analyze", tags=["Detection & Analysis Engines"])

def _persist_threat_and_incident(
    db: Session,
    category: str,
    fusion_result: dict,
    event_id: str = None,
    affected_user: str = "Corporate User",
    affected_asset: str = "Enterprise Gateway"
) -> Threat:
    threat_id = f"THT-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    
    threat = Threat(
        threat_id=threat_id,
        event_id=event_id,
        category=category,
        classification=fusion_result["classification"],
        risk_score=fusion_result["risk_score"],
        risk_level=fusion_result["risk_level"],
        confidence=fusion_result["confidence"],
        status="ACTIVE",
        indicators_json=fusion_result["indicators"],
        explanation=fusion_result["explanation"],
        mitre_tactics_json=fusion_result.get("mitre_mappings", [])
    )
    db.add(threat)
    
    # Store evidence records
    for ind in fusion_result.get("indicators", []):
        ev = Evidence(
            threat_id=threat_id,
            detector=category,
            rule_name="Threat Correlation Engine",
            score=float(fusion_result["risk_score"]),
            detail=ind,
            raw_features_json={}
        )
        db.add(ev)
        
    # Automatically generate Incident if risk score >= 60
    if fusion_result["risk_score"] >= 60:
        incident_id = f"INC-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        inc = Incident(
            incident_id=incident_id,
            threat_id=threat_id,
            title=f"{fusion_result['classification']} detected for {affected_user}",
            severity=fusion_result["risk_level"],
            category=category,
            affected_user=affected_user,
            affected_asset=affected_asset,
            detection_source="CyberGuard Multi-Source Fusion Engine",
            status="New",
            assigned_analyst="SOC Queue",
            timeline_json=[{
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "event": "Automated incident generated following Threat Fusion threshold trigger",
                "actor": "System"
            }]
        )
        db.add(inc)

    db.commit()
    db.refresh(threat)
    return threat

@router.post("/email", response_model=DetectionResultOutput)
async def analyze_email(req: EmailAnalysisRequest, db: Session = Depends(get_db)):
    # 1. Phishing NLP & heuristics
    phish_res = phishing_detector.analyze(
        subject=req.subject,
        sender=req.sender,
        body=req.body,
        links=req.links or []
    )
    
    # 2. Impersonation analysis
    imp_res = impersonation_detector.analyze(
        claimed_name=req.subject,
        sender_email=req.sender,
        content=req.body
    )
    
    # 3. URL analysis if links exist
    url_res = None
    if req.links:
        url_res = url_detector.analyze(req.links[0])

    # 4. Threat Fusion
    detector_results = {
        "phishing_nlp": phish_res,
        "identity_impersonation": imp_res
    }
    if url_res:
        detector_results["url_analysis"] = url_res

    fused = fusion_engine.fuse(
        primary_category="Phishing & Impersonation",
        detector_results=detector_results,
        asset_criticality="HIGH",
        user_sensitivity="EXECUTIVE" if imp_res.get("is_impersonation") else "STANDARD"
    )

    # 5. Persist
    threat = _persist_threat_and_incident(
        db,
        category="Phishing",
        fusion_result=fused,
        affected_user=req.recipient or "Corporate Employee",
        affected_asset="Perimeter Exchange Mailbox"
    )

    # 6. Broadcast live alert via WebSocket
    await ws_manager.broadcast({
        "type": "NEW_THREAT_DETECTED",
        "threat_id": threat.threat_id,
        "classification": fused["classification"],
        "risk_score": fused["risk_score"],
        "risk_level": fused["risk_level"]
    })

    return fused

@router.post("/url", response_model=DetectionResultOutput)
async def analyze_url(req: UrlAnalysisRequest, db: Session = Depends(get_db)):
    # 1. URL detector
    url_res = url_detector.analyze(req.url, req.context)
    
    # 2. Threat Intelligence IOC correlation
    ioc_match = ioc_repository.check_match(req.url)
    ti_res = None
    if ioc_match:
        ti_res = {
            "risk_score": 96,
            "confidence": 0.99,
            "classification": f"Known Malicious IOC ({ioc_match['threat_type']})",
            "risk_level": "CRITICAL",
            "indicators": [f"Direct match with verified threat intelligence feed: {ioc_match['description']}"],
            "recommended_actions": ["Block host at firewall boundary immediately"]
        }

    # 3. Threat Fusion
    detector_results = {"url_analysis": url_res}
    if ti_res:
        detector_results["threat_intelligence"] = ti_res

    fused = fusion_engine.fuse(
        primary_category="Malicious URL",
        detector_results=detector_results,
        asset_criticality="HIGH"
    )

    # 4. Persist
    threat = _persist_threat_and_incident(
        db,
        category="Malicious URL",
        fusion_result=fused,
        affected_user="Web Gateway Client",
        affected_asset="DNS Resolver / Edge Proxy"
    )

    await ws_manager.broadcast({
        "type": "NEW_THREAT_DETECTED",
        "threat_id": threat.threat_id,
        "classification": fused["classification"],
        "risk_score": fused["risk_score"],
        "risk_level": fused["risk_level"]
    })

    return fused

@router.post("/image", response_model=DeepfakeAnalysisOutput)
async def analyze_image(
    file: UploadFile = File(...),
    notes: str = Form(None),
    db: Session = Depends(get_db)
):
    contents = await file.read()
    # File upload validation: max 25MB, image types
    if len(contents) > 25 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds safe processing limit of 25MB")
        
    res = deepfake_detector.analyze_image_bytes(contents, filename=file.filename or "sample.jpg")
    
    # Persist threat if manipulation probability high
    if res["manipulation_probability"] >= 0.60:
        fused_equiv = {
            "classification": f"Synthetic Deepfake Image ({res['status_label']})",
            "risk_score": int(res["manipulation_probability"] * 100),
            "risk_level": "CRITICAL" if res["manipulation_probability"] > 0.8 else "HIGH",
            "confidence": res["confidence"],
            "indicators": res["indicators"],
            "explanation": f"Multimedia forensic pipeline identified synthetic generative signatures. Status: {res['status_label']}.",
            "recommended_actions": res["recommended_actions"],
            "mitre_mappings": [{
                "tactic": "Defense Evasion",
                "technique_id": "T1036",
                "technique_name": "Masquerading: Synthetic Media Impersonation",
                "mitigation": "M1047 - Biometric and cryptographic identity proofing"
            }]
        }
        _persist_threat_and_incident(
            db,
            category="Deepfake",
            fusion_result=fused_equiv,
            affected_user="Executive Identity Channel",
            affected_asset="Corporate Identity Proofing Portal"
        )

    return res

@router.post("/audio", response_model=DeepfakeAnalysisOutput)
async def analyze_audio(
    file: UploadFile = File(...),
    notes: str = Form(None),
    db: Session = Depends(get_db)
):
    contents = await file.read()
    if len(contents) > 30 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds limit of 30MB")

    res = deepfake_detector.analyze_audio_bytes(contents, filename=file.filename or "sample.wav")
    
    if res["manipulation_probability"] >= 0.60:
        fused_equiv = {
            "classification": f"Synthetic Voice Clone ({res['status_label']})",
            "risk_score": int(res["manipulation_probability"] * 100),
            "risk_level": "CRITICAL",
            "confidence": res["confidence"],
            "indicators": res["indicators"],
            "explanation": f"Acoustic spectrogram analysis detected synthetic neural vocoder characteristics. Status: {res['status_label']}.",
            "recommended_actions": res["recommended_actions"]
        }
        _persist_threat_and_incident(
            db,
            category="Deepfake",
            fusion_result=fused_equiv,
            affected_user="VIP Executive Voice Line",
            affected_asset="Corporate PBX / Voice Authorizations"
        )

    return res

@router.post("/video", response_model=DeepfakeAnalysisOutput)
async def analyze_video(
    file: UploadFile = File(...),
    notes: str = Form(None),
    db: Session = Depends(get_db)
):
    res = deepfake_detector.analyze_video(filename=file.filename or "sample.mp4")
    
    if res["manipulation_probability"] >= 0.60:
        fused_equiv = {
            "classification": f"Synthetic Deepfake Video ({res['status_label']})",
            "risk_score": int(res["manipulation_probability"] * 100),
            "risk_level": "CRITICAL",
            "confidence": res["confidence"],
            "indicators": res["indicators"],
            "explanation": f"Facial temporal tracking and blink frequency analysis flagged synthetic video manipulation. Status: {res['status_label']}.",
            "recommended_actions": res["recommended_actions"]
        }
        _persist_threat_and_incident(
            db,
            category="Deepfake",
            fusion_result=fused_equiv,
            affected_user="Executive Broadcast Recipient",
            affected_asset="Video Conference Portal"
        )

    return res

@router.post("/behavior", response_model=DetectionResultOutput)
def analyze_behavior(req: BehavioralLogRequest, db: Session = Depends(get_db)):
    beh_res = behavior_detector.analyze(
        user_email=req.user_email,
        login_location=req.login_location,
        ip_address=req.ip_address,
        device_name=req.device_name,
        browser=req.browser,
        failed_attempts=req.failed_attempts,
        timestamp=req.timestamp
    )

    fused = fusion_engine.fuse(
        primary_category="Account Takeover",
        detector_results={"behavior_anomaly": beh_res},
        asset_criticality="CRITICAL",
        user_sensitivity="ADMIN" if "admin" in req.user_email.lower() else "STANDARD"
    )

    _persist_threat_and_incident(
        db,
        category="Account Takeover",
        fusion_result=fused,
        affected_user=req.user_email,
        affected_asset=f"Identity Provider / {req.device_name}"
    )

    return fused

@router.post("/network", response_model=DetectionResultOutput)
def analyze_network(req: NetworkLogRequest, db: Session = Depends(get_db)):
    net_res = network_detector.analyze(
        source_ip=req.source_ip,
        destination_ip=req.destination_ip,
        port=req.port,
        protocol=req.protocol,
        bytes_transferred=req.bytes_transferred,
        packet_summary=req.packet_summary,
        raw_logs=req.raw_logs
    )

    fused = fusion_engine.fuse(
        primary_category="Network Threat",
        detector_results={"network_threat": net_res},
        asset_criticality="HIGH"
    )

    _persist_threat_and_incident(
        db,
        category="Network Threat",
        fusion_result=fused,
        affected_user=f"Host {req.source_ip}",
        affected_asset=f"VLAN Switch / Interface Port {req.port}"
    )

    return fused

@router.post("/event", response_model=DetectionResultOutput)
async def analyze_unified_event(evt: EventCreate, db: Session = Depends(get_db)):
    """
    Unified Ingestion endpoint (EVT-001 format).
    Dispatches to appropriate detector depending on source_type.
    """
    event_id = evt.event_id or f"EVT-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    
    # Store raw event
    db_event = Event(
        event_id=event_id,
        timestamp=evt.timestamp or datetime.datetime.utcnow(),
        source_type=evt.source_type,
        source=evt.source,
        user=evt.user,
        content=evt.content,
        metadata_json=evt.metadata,
        attachments_json=evt.attachments,
        ip=evt.ip,
        device=evt.device,
        status="processed"
    )
    db.add(db_event)
    db.commit()

    # Route based on source_type
    if evt.source_type in ["email", "sms", "message", "social"]:
        req = EmailAnalysisRequest(
            subject=evt.metadata.get("subject", "Inbound Message Inspection"),
            sender=evt.source or "unknown@external.net",
            body=evt.content,
            recipient=evt.user,
            links=evt.metadata.get("links", [])
        )
        return await analyze_email(req, db)

    elif evt.source_type == "url":
        req = UrlAnalysisRequest(url=evt.source or evt.content, context=evt.content)
        return await analyze_url(req, db)

    elif evt.source_type == "auth":
        req = BehavioralLogRequest(
            user_email=evt.user,
            login_location=evt.metadata.get("location", "Unknown Location"),
            ip_address=evt.ip,
            device_name=evt.device,
            browser=evt.metadata.get("browser", "Unknown Browser"),
            failed_attempts=evt.metadata.get("failed_attempts", 0)
        )
        return analyze_behavior(req, db)

    elif evt.source_type in ["network", "system"]:
        req = NetworkLogRequest(
            source_ip=evt.ip,
            destination_ip=evt.metadata.get("destination_ip", "198.51.100.1"),
            port=evt.metadata.get("port", 443),
            protocol=evt.metadata.get("protocol", "TCP"),
            bytes_transferred=evt.metadata.get("bytes", 1024),
            packet_summary=evt.content
        )
        return analyze_network(req, db)

    else:
        # Default text analysis
        req = EmailAnalysisRequest(subject="Generic Event Inspection", sender=evt.source, body=evt.content)
        return await analyze_email(req, db)

@router.post("/quishing")
async def analyze_quishing(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    contents = await file.read()
    if len(contents) > 25 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds limit of 25MB")
        
    res = quishing_detector.analyze_image_bytes(contents, filename=file.filename or "qr_code.png")
    
    if res.get("is_quishing"):
        fused_equiv = {
            "classification": res["classification"],
            "risk_score": res["risk_score"],
            "risk_level": res["risk_level"],
            "confidence": res["confidence"],
            "indicators": res["indicators"],
            "explanation": res["explanation"],
            "recommended_actions": res["recommended_actions"],
            "mitre_mappings": res.get("mitre_mappings", [])
        }
        _persist_threat_and_incident(
            db,
            category="QR-Code Phishing (Quishing)",
            fusion_result=fused_equiv,
            affected_user="Mobile Endpoint / Flyer Recipient",
            affected_asset="Perimeter Gateway / Visual Scanner"
        )
    return res

@router.post("/genai-phishing")
def analyze_genai_phishing(text: str = Form(...)):
    res = ai_phishing_detector.analyze(text)
    return res

