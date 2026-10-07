from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.sql_models import ResponseAction
from app.models.schemas import ResponseActionCreate
from app.response.action_runner import response_engine

router = APIRouter(prefix="/response", tags=["Controlled Response Engine"])

@router.post("/execute")
def execute_response(data: ResponseActionCreate, db: Session = Depends(get_db)):
    result = response_engine.execute_action(
        db=db,
        action_type=data.action_type,
        target=data.target,
        reason=data.reason,
        evidence_summary=data.evidence_summary or "Manual analyst execution",
        actor="Security Analyst (Manual Trigger)",
        threat_id=data.threat_id,
        incident_id=data.incident_id,
        force_execute=True
    )
    return result

@router.post("/rollback/{action_id}")
def rollback_action(action_id: str, db: Session = Depends(get_db)):
    try:
        res = response_engine.rollback_action(db=db, action_id=action_id)
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/actions")
def list_response_actions(db: Session = Depends(get_db)):
    actions = db.query(ResponseAction).order_by(ResponseAction.executed_at.desc()).limit(50).all()
    return [
        {
            "action_id": a.action_id,
            "threat_id": a.threat_id,
            "incident_id": a.incident_id,
            "action_type": a.action_type,
            "target": a.target,
            "reason": a.reason,
            "status": a.status,
            "actor": a.actor,
            "executed_at": a.executed_at.isoformat(),
            "rollback_action": a.rollback_action,
            "rolled_back": a.rolled_back
        }
        for a in actions
    ]
