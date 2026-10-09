from typing import Optional, Any
from pydantic import BaseModel, Field
import datetime

# --- Auth Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str
    user_info: dict

class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None

class UserLogin(BaseModel):
    email: str
    password: str

class UserCreate(BaseModel):
    email: str
    full_name: str
    password: str
    role: str = "Security Analyst"
    department: str = "Information Security"

class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    department: str
    is_active: bool
    created_at: datetime.datetime

    class Config:
        from_attributes = True

# --- Ingestion & Event Schemas ---
class EventCreate(BaseModel):
    event_id: Optional[str] = None
    timestamp: Optional[datetime.datetime] = None
    source_type: str = "email"  # email, url, image, audio, video, auth, network, system
    source: str = ""
    user: str = "unknown"
    content: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    attachments: list[str] = Field(default_factory=list)
    ip: str = "127.0.0.1"
    device: str = "Unknown Device"

class EventResponse(BaseModel):
    id: int
    event_id: str
    timestamp: datetime.datetime
    source_type: str
    source: Optional[str]
    user: Optional[str]
    content: Optional[str]
    metadata_json: dict[str, Any]
    attachments_json: list[str]
    ip: Optional[str]
    device: Optional[str]
    status: str

    class Config:
        from_attributes = True

# --- Detector Requests ---
class EmailAnalysisRequest(BaseModel):
    subject: str
    sender: str
    body: str
    recipient: Optional[str] = "target@enterprise.com"
    headers: Optional[dict[str, str]] = None
    links: Optional[list[str]] = None

class UrlAnalysisRequest(BaseModel):
    url: str
    context: Optional[str] = "User clicked link in suspicious email"

class BehavioralLogRequest(BaseModel):
    user_email: str
    login_location: str
    ip_address: str
    device_name: str
    browser: str
    failed_attempts: int = 0
    timestamp: Optional[datetime.datetime] = None

class NetworkLogRequest(BaseModel):
    source_ip: str
    destination_ip: str
    port: int
    protocol: str = "TCP"
    bytes_transferred: int = 0
    packet_summary: str = ""
    raw_logs: Optional[str] = None

class MediaAnalysisRequest(BaseModel):
    media_type: str = "image"  # image, audio, video
    media_url_or_path: Optional[str] = None
    notes: Optional[str] = None

# --- Standard Threat Detection Result (as required by prompt) ---
class DetectionResultOutput(BaseModel):
    classification: str
    probability: float
    risk_score: int
    risk_level: str  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    confidence: float
    indicators: list[str]
    explanation: str
    recommended_actions: list[str]
    detector_scores: Optional[dict[str, Any]] = None
    mitre_mappings: Optional[list[dict[str, str]]] = None
    shap_contributions: Optional[dict[str, float]] = None

class DeepfakeAnalysisOutput(BaseModel):
    authenticity_score: int  # 0-100 (high = authentic)
    manipulation_probability: float  # 0.0 - 1.0 (high = manipulated)
    confidence: float
    indicators: list[str]
    status_label: str = "Potentially manipulated"
    media_type: str = "image"
    forensic_details: dict[str, Any] = Field(default_factory=dict)
    recommended_actions: list[str] = Field(default_factory=list)

class SteganographyAnalysisOutput(BaseModel):
    is_steganography: bool
    classification: str
    risk_score: int
    risk_level: str
    confidence: float
    recovered_urls: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    explanation: str
    recommended_actions: list[str] = Field(default_factory=list)
    forensic_details: dict[str, Any] = Field(default_factory=dict)
    mitre_mappings: list[dict[str, str]] = Field(default_factory=list)
    url_analyses: list[dict[str, Any]] = Field(default_factory=list)

# --- Threat Database Schema ---
class ThreatResponse(BaseModel):
    id: int
    threat_id: str
    event_id: Optional[str]
    category: str
    classification: str
    risk_score: int
    risk_level: str
    confidence: float
    status: str
    created_at: datetime.datetime
    indicators_json: list[str]
    explanation: Optional[str]
    mitre_tactics_json: list[dict[str, str]]

    class Config:
        from_attributes = True

# --- Incident Schemas ---
class IncidentCreate(BaseModel):
    threat_id: Optional[str] = None
    title: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    category: str
    affected_user: Optional[str] = "Unknown"
    affected_asset: Optional[str] = "Unknown"
    detection_source: str = "Manual Investigation"
    assigned_analyst: str = "SOC Operator"

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    assigned_analyst: Optional[str] = None
    resolution_notes: Optional[str] = None

class IncidentResponse(BaseModel):
    id: int
    incident_id: str
    threat_id: Optional[str]
    title: str
    severity: str
    category: str
    affected_user: Optional[str]
    affected_asset: Optional[str]
    detection_source: Optional[str]
    status: str
    assigned_analyst: Optional[str]
    created_at: datetime.datetime
    updated_at: datetime.datetime
    timeline_json: list[dict[str, Any]]
    resolution_notes: Optional[str]

    class Config:
        from_attributes = True

# --- Response Actions ---
class ResponseActionCreate(BaseModel):
    threat_id: Optional[str] = None
    incident_id: Optional[str] = None
    action_type: str  # Quarantine Email, Block URL, Require MFA, Revoke Session, Block IP, Escalate to SOC
    target: str
    reason: str
    evidence_summary: Optional[str] = None

class ResponseActionResponse(BaseModel):
    id: int
    action_id: str
    incident_id: Optional[str]
    threat_id: Optional[str]
    action_type: str
    target: str
    reason: Optional[str]
    evidence_summary: Optional[str]
    status: str
    actor: str
    executed_at: datetime.datetime
    rollback_action: Optional[str]
    rolled_back: bool

    class Config:
        from_attributes = True

# --- Threat Intelligence / IOC ---
class IOCResponse(BaseModel):
    id: int
    ioc_type: str
    value: str
    threat_type: Optional[str]
    confidence: int
    source: str
    description: Optional[str]
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    is_active: bool

    class Config:
        from_attributes = True

class IOCCreate(BaseModel):
    ioc_type: str
    value: str
    threat_type: str
    confidence: int = 90
    source: str = "Manual SOC Entry"
    description: Optional[str] = None

# --- Attack Graph ---
class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # person, email, domain, ip, device, organization, threat
    risk_level: Optional[str] = "SAFE"
    details: Optional[dict[str, Any]] = None

class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str  # sent_from, resolves_to, belongs_to, connected_with, targeted

class AttackGraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]

# --- AI Security Assistant ---
class AssistantQueryRequest(BaseModel):
    query: str
    incident_id: Optional[str] = None
    threat_id: Optional[str] = None
    conversation_history: Optional[list[dict[str, str]]] = None

class AssistantQueryResponse(BaseModel):
    answer: str
    evidence_cited: list[str]
    mitre_techniques: list[dict[str, str]]
    recommended_actions: list[str]
    affected_entities: list[str]
    similar_incidents: list[str]

# --- Dashboard & Metrics ---
class DashboardMetrics(BaseModel):
    events_analyzed: int
    threats_detected: int
    critical_threats: int
    open_incidents: int
    threats_by_category: dict[str, int]
    risk_distribution: dict[str, int]
    recent_incidents: list[dict[str, Any]]
    recommended_actions: list[dict[str, Any]]
