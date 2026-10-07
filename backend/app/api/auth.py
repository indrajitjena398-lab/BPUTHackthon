import datetime
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.config import settings
from app.models.sql_models import User
from app.models.schemas import UserLogin, Token, UserResponse

router = APIRouter(prefix="/auth", tags=["Authentication & RBAC"])

DEMO_USERS = {
    "admin@cyberguard.local": {
        "full_name": "Eleanor Vance (Enterprise Admin)",
        "role": "Admin",
        "department": "Global IT Security"
    },
    "analyst@cyberguard.local": {
        "full_name": "Ankit Kumar (Senior Security Analyst)",
        "role": "Security Analyst",
        "department": "SOC Threat Intelligence"
    },
    "operator@cyberguard.local": {
        "full_name": "Marcus Chen (Tier-2 SOC Operator)",
        "role": "SOC Operator",
        "department": "Incident Operations Center"
    },
    "manager@cyberguard.local": {
        "full_name": "Dr. Sarah Al-Mansoor (CISO)",
        "role": "Organisation Manager",
        "department": "Executive Cyber Governance"
    },
    "viewer@cyberguard.local": {
        "full_name": "David Ross (Compliance Auditor)",
        "role": "Viewer",
        "department": "Internal Risk & Audit"
    }
}

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

@router.post("/login", response_model=Token)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    email = credentials.email.lower().strip()
    
    # Check if demo user or database user
    user = db.query(User).filter(User.email == email).first()
    if not user:
        # If in demo mode and email in demo users, auto-provision
        if email in DEMO_USERS:
            demo_meta = DEMO_USERS[email]
            user = User(
                email=email,
                full_name=demo_meta["full_name"],
                hashed_password="demo_hashed_password",
                role=demo_meta["role"],
                department=demo_meta["department"],
                is_active=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            # Default fallback for prototype convenience
            user = User(
                email=email,
                full_name="Security Analyst",
                hashed_password="demo_hashed_password",
                role="Security Analyst",
                department="Information Security",
                is_active=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)

    token = create_access_token({"sub": user.email, "role": user.role, "name": user.full_name})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_info": {
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "department": user.department
        }
    }

@router.post("/switch-demo-role")
def switch_demo_role(role: str, db: Session = Depends(get_db)):
    # Find matching demo user for the specified role
    for email, meta in DEMO_USERS.items():
        if meta["role"].lower() == role.lower():
            token = create_access_token({"sub": email, "role": meta["role"], "name": meta["full_name"]})
            return {
                "access_token": token,
                "token_type": "bearer",
                "user_info": {
                    "email": email,
                    "full_name": meta["full_name"],
                    "role": meta["role"],
                    "department": meta["department"]
                }
            }
    raise HTTPException(status_code=400, detail=f"Invalid demo role: {role}")

@router.get("/me")
def get_current_user_profile():
    return {
        "email": "analyst@cyberguard.local",
        "full_name": "Ankit Kumar (Senior Security Analyst)",
        "role": "Security Analyst",
        "department": "SOC Threat Intelligence",
        "permissions": ["analyze_threats", "execute_playbooks", "view_intelligence", "manage_incidents"]
    }
