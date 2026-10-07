import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "CYBERGUARD"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Security & Auth
    SECRET_KEY: str = os.getenv("SECRET_KEY", "cyberguard-enterprise-super-secure-secret-key-2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./cyberguard.db")
    
    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEMO_MODE: bool = os.getenv("DEMO_MODE", "True").lower() in ("true", "1", "t")
    
    # Risk Scoring Thresholds
    RISK_SAFE_MAX: int = 20
    RISK_LOW_MAX: int = 40
    RISK_MEDIUM_MAX: int = 60
    RISK_HIGH_MAX: int = 80
    RISK_CRITICAL_MIN: int = 81
    
    # CORS
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "*"
    ]
    
    model_config = {"case_sensitive": True}

settings = Settings()

