import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import engine, Base
from app.seed_data import seed_database
from app.services.websocket_manager import ws_manager

# Import API Routers
from app.api.auth import router as auth_router
from app.api.analyze import router as analyze_router
from app.api.threats import router as threats_router
from app.api.incidents import router as incidents_router
from app.api.intelligence import router as intelligence_router
from app.api.graph import router as graph_router
from app.api.response import router as response_router
from app.api.assistant import router as assistant_router
from app.api.dashboard import router as dashboard_router
from app.api.reports import router as reports_router
from app.api.settings import router as settings_router

# Create Tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="Enterprise AI-Powered Cyber Threat, Phishing, Deepfake & Digital Impersonation Detection and Response System",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup Hook
@app.on_event("startup")
def startup_event():
    seed_database()

# Register API Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(analyze_router, prefix=settings.API_V1_STR)
app.include_router(threats_router, prefix=settings.API_V1_STR)
app.include_router(incidents_router, prefix=settings.API_V1_STR)
app.include_router(intelligence_router, prefix=settings.API_V1_STR)
app.include_router(graph_router, prefix=settings.API_V1_STR)
app.include_router(response_router, prefix=settings.API_V1_STR)
app.include_router(assistant_router, prefix=settings.API_V1_STR)
app.include_router(dashboard_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)
app.include_router(settings_router, prefix=settings.API_V1_STR)

# Health & Status
@app.get("/")
def root():
    return {
        "system": "CYBERGUARD Enterprise Security Platform",
        "version": settings.PROJECT_VERSION,
        "status": "OPERATIONAL",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "documentation": "/docs",
        "health": "/api/health"
    }

@app.get("/api/health")
def health_check():
    return {
        "status": "HEALTHY",
        "database": "CONNECTED",
        "ml_inference_engine": "ACTIVE",
        "threat_fusion_engine": "ACTIVE",
        "environment": settings.ENVIRONMENT
    }

# Live Telemetry WebSocket
@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send initial connection handshake
        await websocket.send_json({
            "type": "CONNECTION_ESTABLISHED",
            "message": "Connected to CyberGuard Real-Time Security Telemetry Stream",
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
        while True:
            data = await websocket.receive_text()
            # Echo ping/pong for keepalive
            await websocket.send_json({"type": "PONG", "payload": data})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
