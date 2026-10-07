from fastapi import APIRouter
from app.services.graph_service import attack_graph_service

router = APIRouter(prefix="/graph", tags=["Attack & Identity Graph"])

@router.get("")
def get_attack_graph():
    return attack_graph_service.get_graph_data()

@router.get("/cypher")
def export_cypher():
    return {"cypher": attack_graph_service.generate_cypher_export()}
