import datetime
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.sql_models import Incident, Threat, ResponseAction, AuditLog
from app.models.schemas import IncidentCreate, IncidentUpdate

router = APIRouter(prefix="/incidents", tags=["Incident Management"])

@router.get("")
def list_incidents(
    status: str = Query(None),
    severity: str = Query(None),
    category: str = Query(None),
    limit: int = 50,
    db: Session = Depends(get_db)
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    if category:
        query = query.filter(Incident.category == category)
        
    incidents = query.order_by(Incident.created_at.desc()).limit(limit).all()
    return [
        {
            "id": inc.id,
            "incident_id": inc.incident_id,
            "threat_id": inc.threat_id,
            "title": inc.title,
            "severity": inc.severity,
            "category": inc.category,
            "affected_user": inc.affected_user,
            "affected_asset": inc.affected_asset,
            "detection_source": inc.detection_source,
            "status": inc.status,
            "assigned_analyst": inc.assigned_analyst,
            "created_at": inc.created_at.isoformat(),
            "updated_at": inc.updated_at.isoformat() if inc.updated_at else inc.created_at.isoformat(),
            "timeline": inc.timeline_json or [],
            "resolution_notes": inc.resolution_notes
        }
        for inc in incidents
    ]

@router.post("")
def create_incident(data: IncidentCreate, db: Session = Depends(get_db)):
    incident_id = f"INC-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    new_inc = Incident(
        incident_id=incident_id,
        threat_id=data.threat_id,
        title=data.title,
        severity=data.severity,
        category=data.category,
        affected_user=data.affected_user,
        affected_asset=data.affected_asset,
        detection_source=data.detection_source,
        status="New",
        assigned_analyst=data.assigned_analyst,
        timeline_json=[{
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "event": "Incident manually logged by SOC analyst",
            "actor": data.assigned_analyst
        }]
    )
    db.add(new_inc)
    db.commit()
    db.refresh(new_inc)
    return {"status": "SUCCESS", "incident_id": new_inc.incident_id}

@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    threat = db.query(Threat).filter(Threat.threat_id == inc.threat_id).first() if inc.threat_id else None
    actions = db.query(ResponseAction).filter(ResponseAction.incident_id == incident_id).all()

    return {
        "incident_id": inc.incident_id,
        "threat_id": inc.threat_id,
        "title": inc.title,
        "severity": inc.severity,
        "category": inc.category,
        "affected_user": inc.affected_user,
        "affected_asset": inc.affected_asset,
        "detection_source": inc.detection_source,
        "status": inc.status,
        "assigned_analyst": inc.assigned_analyst,
        "created_at": inc.created_at.isoformat(),
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else inc.created_at.isoformat(),
        "timeline": inc.timeline_json or [],
        "resolution_notes": inc.resolution_notes,
        "threat_detail": {
            "risk_score": threat.risk_score,
            "risk_level": threat.risk_level,
            "classification": threat.classification,
            "indicators": threat.indicators_json or [],
            "mitre_tactics": threat.mitre_tactics_json or []
        } if threat else None,
        "actions_taken": [
            {
                "action_id": a.action_id,
                "action_type": a.action_type,
                "status": a.status,
                "actor": a.actor,
                "executed_at": a.executed_at.isoformat()
            }
            for a in actions
        ]
    }

@router.patch("/{incident_id}")
def update_incident(incident_id: str, data: IncidentUpdate, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    timeline = list(inc.timeline_json or [])
    
    if data.status and data.status != inc.status:
        timeline.append({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "event": f"Status updated from '{inc.status}' to '{data.status}'",
            "actor": data.assigned_analyst or inc.assigned_analyst
        })
        inc.status = data.status

    if data.assigned_analyst and data.assigned_analyst != inc.assigned_analyst:
        timeline.append({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "event": f"Reassigned to analyst '{data.assigned_analyst}'",
            "actor": "SOC Supervisor"
        })
        inc.assigned_analyst = data.assigned_analyst

    if data.severity:
        inc.severity = data.severity
    if data.resolution_notes:
        inc.resolution_notes = data.resolution_notes

    inc.timeline_json = timeline
    inc.updated_at = datetime.datetime.utcnow()
    db.commit()

    return {"status": "SUCCESS", "incident_id": inc.incident_id, "current_status": inc.status}
