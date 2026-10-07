from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.schemas import AssistantQueryRequest, AssistantQueryResponse
from app.services.assistant_service import ai_assistant

router = APIRouter(prefix="/assistant", tags=["AI Security Assistant"])

@router.post("/query", response_model=AssistantQueryResponse)
def query_assistant(req: AssistantQueryRequest, db: Session = Depends(get_db)):
    result = ai_assistant.query(
        db=db,
        user_query=req.query,
        incident_id=req.incident_id,
        threat_id=req.threat_id
    )
    return result
