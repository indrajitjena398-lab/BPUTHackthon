from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.schemas import IOCCreate
from app.threat_intelligence.ioc_repo import ioc_repository
from app.threat_intelligence.mitre_mapper import MITRE_ATTACK_MATRIX

router = APIRouter(prefix="/intelligence", tags=["Threat Intelligence & MITRE"])

@router.get("/iocs")
def get_iocs():
    return ioc_repository.get_all()

@router.post("/iocs")
def add_ioc(data: IOCCreate):
    ioc_repository.iocs.insert(0, {
        "ioc_type": data.ioc_type,
        "value": data.value,
        "threat_type": data.threat_type,
        "confidence": data.confidence,
        "source": data.source,
        "description": data.description
    })
    return {"status": "SUCCESS", "message": f"IOC {data.value} registered"}

@router.get("/stix")
def export_stix():
    return ioc_repository.export_stix21()

@router.get("/mitre")
def get_mitre_matrix():
    return list(MITRE_ATTACK_MATRIX.values())
