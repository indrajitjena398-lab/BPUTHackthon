from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.sql_models import Threat, Evidence, Incident, ResponseAction
from app.explainability.xai_service import xai_service

router = APIRouter(prefix="/threats", tags=["Threat Management"])

@router.get("")
def list_threats(
    category: str = Query(None),
    risk_level: str = Query(None),
    status: str = Query(None),
    limit: int = 50,
    db: Session = Depends(get_db)
):
    query = db.query(Threat)
    if category:
        query = query.filter(Threat.category == category)
    if risk_level:
        query = query.filter(Threat.risk_level == risk_level)
    if status:
        query = query.filter(Threat.status == status)
    threats = query.order_by(Threat.created_at.desc()).limit(limit).all()
    
    return [
        {
            "id": t.id,
            "threat_id": t.threat_id,
            "event_id": t.event_id,
            "category": t.category,
            "classification": t.classification,
            "risk_score": t.risk_score,
            "risk_level": t.risk_level,
            "confidence": t.confidence,
            "status": t.status,
            "created_at": t.created_at.isoformat(),
            "indicators": t.indicators_json or [],
            "mitre_tactics": t.mitre_tactics_json or []
        }
        for t in threats
    ]

@router.get("/{threat_id}")
def get_threat_detail(threat_id: str, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.threat_id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail=f"Threat '{threat_id}' not found")

    evidence_items = db.query(Evidence).filter(Evidence.threat_id == threat_id).all()
    related_incident = db.query(Incident).filter(Incident.threat_id == threat_id).first()
    actions = db.query(ResponseAction).filter(ResponseAction.threat_id == threat_id).all()

    # Generate XAI explanation
    xai_report = xai_service.generate_explanation_report(
        risk_score=threat.risk_score,
        risk_level=threat.risk_level,
        category=threat.category,
        indicators=threat.indicators_json or [],
        shap_contributions={
            "linguistic_coercion": 0.35 if "Phishing" in threat.category else 0.1,
            "brand_spoofing": 0.45 if "URL" in threat.category or "Impersonation" in threat.category else 0.05,
            "behavioral_outlier": 0.40 if "Takeover" in threat.category else 0.05,
            "synthetic_artifacts": 0.50 if "Deepfake" in threat.category else 0.0
        }
    )

    return {
        "threat_id": threat.threat_id,
        "event_id": threat.event_id,
        "category": threat.category,
        "classification": threat.classification,
        "risk_score": threat.risk_score,
        "risk_level": threat.risk_level,
        "confidence": threat.confidence,
        "status": threat.status,
        "created_at": threat.created_at.isoformat(),
        "indicators": threat.indicators_json or [],
        "explanation": threat.explanation,
        "mitre_tactics": threat.mitre_tactics_json or [],
        "xai_report": xai_report,
        "evidence": [
            {
                "detector": e.detector,
                "rule_name": e.rule_name,
                "score": e.score,
                "detail": e.detail
            }
            for e in evidence_items
        ],
        "related_incident": {
            "incident_id": related_incident.incident_id,
            "title": related_incident.title,
            "status": related_incident.status,
            "severity": related_incident.severity
        } if related_incident else None,
        "response_actions": [
            {
                "action_id": a.action_id,
                "action_type": a.action_type,
                "status": a.status,
                "actor": a.actor,
                "executed_at": a.executed_at.isoformat(),
                "rolled_back": a.rolled_back
            }
            for a in actions
        ]
    }
