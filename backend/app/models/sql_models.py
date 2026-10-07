import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from app.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="Security Analyst")  # Admin, Security Analyst, SOC Operator, Organisation Manager, Viewer
    department = Column(String(100), default="Information Security")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Event(Base):
    __tablename__ = "events"
    
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(100), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    source_type = Column(String(50), index=True)  # email, url, image, audio, video, auth, network, system
    source = Column(String(255))
    user = Column(String(255), index=True)
    content = Column(Text)
    metadata_json = Column(JSON, default=dict)
    attachments_json = Column(JSON, default=list)
    ip = Column(String(50))
    device = Column(String(100))
    status = Column(String(50), default="processed")  # ingested, processing, processed, flagged

class Threat(Base):
    __tablename__ = "threats"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(100), unique=True, index=True, nullable=False)
    event_id = Column(String(100), ForeignKey("events.event_id"), nullable=True)
    category = Column(String(50), index=True)  # Phishing, Malicious URL, Deepfake, Impersonation, Account Takeover, Network Threat
    classification = Column(String(100), nullable=False)
    risk_score = Column(Integer, index=True)  # 0-100
    risk_level = Column(String(20), index=True)  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, default=0.0)  # 0.0 - 1.0
    status = Column(String(50), default="ACTIVE")  # ACTIVE, MITIGATED, RESOLVED, FALSE_POSITIVE
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    indicators_json = Column(JSON, default=list)
    explanation = Column(Text)
    mitre_tactics_json = Column(JSON, default=list)
    
    # Relationships
    incidents = relationship("Incident", back_populates="threat")
    evidence_items = relationship("Evidence", back_populates="threat")
    response_actions = relationship("ResponseAction", back_populates="threat")

class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(100), unique=True, index=True, nullable=False)
    threat_id = Column(String(100), ForeignKey("threats.threat_id"), nullable=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    category = Column(String(50), index=True)
    affected_user = Column(String(255))
    affected_asset = Column(String(255))
    detection_source = Column(String(100))
    status = Column(String(50), default="New", index=True)  # New, Investigating, Contained, Resolved, False Positive, Closed
    assigned_analyst = Column(String(255), default="Unassigned")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    timeline_json = Column(JSON, default=list)
    resolution_notes = Column(Text, nullable=True)
    
    # Relationship
    threat = relationship("Threat", back_populates="incidents")
    response_actions = relationship("ResponseAction", back_populates="incident")

class Evidence(Base):
    __tablename__ = "evidence"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(100), ForeignKey("threats.threat_id"), nullable=False)
    detector = Column(String(50))
    rule_name = Column(String(100))
    score = Column(Float)
    detail = Column(Text)
    raw_features_json = Column(JSON, default=dict)
    
    threat = relationship("Threat", back_populates="evidence_items")

class DetectionResult(Base):
    __tablename__ = "detection_results"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(100), index=True)
    detector_name = Column(String(50), index=True)
    model_version = Column(String(50))
    confidence = Column(Float)
    score = Column(Float)
    latency_ms = Column(Float)
    result_payload_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Asset(Base):
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(String(100), unique=True, index=True)
    name = Column(String(255), nullable=False)
    asset_type = Column(String(50))  # Server, Database, Workstation, Cloud Service, API Gateway
    ip_address = Column(String(50))
    owner = Column(String(255))
    critical_level = Column(String(20), default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(50), default="Healthy")  # Healthy, Warning, Compromised

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(100), unique=True, index=True)
    user_email = Column(String(255), index=True)
    device_name = Column(String(255))
    os = Column(String(100))
    ip_address = Column(String(50))
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    is_trusted = Column(Boolean, default=True)

class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(100), unique=True, index=True)
    user_email = Column(String(255), index=True)
    ip_address = Column(String(50))
    user_agent = Column(String(255))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True)

class IOC(Base):
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String(50), index=True)  # ip, domain, url, hash, email
    value = Column(String(255), index=True, nullable=False)
    threat_type = Column(String(100))
    confidence = Column(Integer, default=90)
    source = Column(String(100), default="CyberGuard TI Feeds")
    description = Column(Text)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    is_active = Column(Boolean, default=True)

class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    threat_type = Column(String(100))
    mitre_technique_id = Column(String(50), index=True)
    mitre_technique_name = Column(String(255))
    severity = Column(String(20))
    description = Column(Text)
    indicators_json = Column(JSON, default=list)
    mitigation = Column(Text)

class ResponseAction(Base):
    __tablename__ = "response_actions"
    
    id = Column(Integer, primary_key=True, index=True)
    action_id = Column(String(100), unique=True, index=True, nullable=False)
    incident_id = Column(String(100), ForeignKey("incidents.incident_id"), nullable=True)
    threat_id = Column(String(100), ForeignKey("threats.threat_id"), nullable=True)
    action_type = Column(String(100), nullable=False)  # Warn User, Quarantine Email, Block URL, Require MFA, Revoke Session, Block IP, Escalate to SOC
    target = Column(String(255), nullable=False)
    reason = Column(Text)
    evidence_summary = Column(Text)
    status = Column(String(50), default="EXECUTED")  # PENDING_APPROVAL, EXECUTED, ROLLED_BACK, FAILED
    actor = Column(String(255), default="System Auto-Response")
    executed_at = Column(DateTime, default=datetime.datetime.utcnow)
    rollback_action = Column(String(255), nullable=True)
    rolled_back = Column(Boolean, default=False)
    
    threat = relationship("Threat", back_populates="response_actions")
    incident = relationship("Incident", back_populates="response_actions")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    actor = Column(String(255), nullable=False)
    action = Column(String(100), nullable=False)
    target_type = Column(String(50))
    target_id = Column(String(100))
    details_json = Column(JSON, default=dict)
    ip_address = Column(String(50), default="127.0.0.1")

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    recipient = Column(String(255), index=True)
    title = Column(String(255), nullable=False)
    message = Column(Text)
    severity = Column(String(20), default="INFO")  # INFO, WARNING, CRITICAL
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    link = Column(String(255), nullable=True)

class ModelRegistry(Base):
    __tablename__ = "model_registry"
    
    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String(100), unique=True, nullable=False)
    version = Column(String(50), nullable=False)
    category = Column(String(100))
    accuracy = Column(Float)
    precision = Column(Float)
    recall = Column(Float)
    f1 = Column(Float)
    status = Column(String(50), default="Production Ready")  # Production Ready, Calibrated, Demonstration Mode
    updated_at = Column(DateTime, default=datetime.datetime.utcnow)
