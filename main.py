from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from typing import Optional
import jwt
import bcrypt
import os
import uuid
import uvicorn

app = FastAPI(title="EAC Super App", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "eac-super-secret-key-change-in-production-2024")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

# In-memory database for demo (replace with PostgreSQL in production)
users_db = {}
payments_db = {}
access_logs = []

# Default admin user
default_admin = {
    "id": str(uuid.uuid4()),
    "email": "admin@eac.com",
    "username": "admin",
    "password_hash": bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
    "is_active": True,
    "is_admin": True,
    "is_dba": False,  # DBA has higher privileges
    "payment_verified": True,
    "subscription_expiry": datetime.now() + timedelta(days=365),
    "created_at": datetime.now(),
    "last_login": None
}
users_db[default_admin["email"]] = default_admin

# Default DBA user
default_dba = {
    "id": str(uuid.uuid4()),
    "email": "dba@eac.com",
    "username": "dba_admin",
    "password_hash": bcrypt.hashpw("dba123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
    "is_active": True,
    "is_admin": True,
    "is_dba": True,  # Highest privilege level
    "payment_verified": True,
    "subscription_expiry": datetime.now() + timedelta(days=365),
    "created_at": datetime.now(),
    "last_login": None
}
users_db[default_dba["email"]] = default_dba

# Pydantic Models
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    is_active: bool
    is_admin: bool
    is_dba: bool
    payment_verified: bool
    subscription_expiry: Optional[datetime]
    created_at: datetime
    last_login: Optional[datetime]

class PaymentVerification(BaseModel):
    user_email: str
    amount: float
    subscription_months: int = 1

class DirectUserCreation(BaseModel):
    email: EmailStr
    username: str
    password: str
    grant_immediate_access: bool = True

# Utility functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        user = users_db.get(email)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except Exception as e:
        raise HTTPException(status_code=401, detail="Authentication error")

def get_admin_user(current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

def get_dba_user(current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_dba", False):
        raise HTTPException(status_code=403, detail="DBA access required")
    return current_user

# Authentication Routes
@app.post("/auth/register")
async def register(user: UserCreate, current_admin: dict = Depends(get_admin_user)):
    """Admin-only user registration after payment verification"""
    if user.email in users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    new_user = {
        "id": str(uuid.uuid4()),
        "email": user.email,
        "username": user.username,
        "password_hash": hash_password(user.password),
        "is_active": False,  # Requires payment verification
        "is_admin": False,
        "is_dba": False,
        "payment_verified": False,
        "subscription_expiry": None,
        "created_at": datetime.now(),
        "last_login": None
    }
    
    users_db[user.email] = new_user
    
    return {"message": "User created successfully. Awaiting payment verification.", "user_id": new_user["id"]}

@app.post("/auth/login", response_model=Token)
async def login(user: UserLogin):
    """User login with JWT token generation"""
    db_user = users_db.get(user.email)
    if not db_user or not verify_password(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not db_user["is_active"]:
        raise HTTPException(status_code=401, detail="Account not active. Payment verification required.")
    
    # Update last login
    db_user["last_login"] = datetime.now()
    
    # Log access
    access_logs.append({
        "user_id": db_user["id"],
        "app_accessed": "super_app_login",
        "access_time": datetime.now(),
        "ip_address": "127.0.0.1"
    })
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    user_data = {k: v for k, v in db_user.items() if k != "password_hash"}
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_data
    }

@app.get("/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    user_data = {k: v for k, v in current_user.items() if k != "password_hash"}
    return user_data

# DBA Routes - Highest privilege level
@app.post("/dba/create-user-direct")
async def create_user_direct(user: DirectUserCreation, current_dba: dict = Depends(get_dba_user)):
    """DBA-only: Create user with immediate access without payment verification"""
    if user.email in users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    new_user = {
        "id": str(uuid.uuid4()),
        "email": user.email,
        "username": user.username,
        "password_hash": hash_password(user.password),
        "is_active": user.grant_immediate_access,
        "is_admin": False,
        "is_dba": False,
        "payment_verified": user.grant_immediate_access,
        "subscription_expiry": datetime.now() + timedelta(days=365) if user.grant_immediate_access else None,
        "created_at": datetime.now(),
        "last_login": None
    }
    
    users_db[user.email] = new_user
    
    return {
        "message": "User created successfully with DBA privileges",
        "user_id": new_user["id"],
        "access_granted": user.grant_immediate_access,
        "created_by": current_dba["email"]
    }

@app.post("/dba/toggle-user-access/{user_email}")
async def toggle_user_access(user_email: str, current_dba: dict = Depends(get_dba_user)):
    """DBA-only: Toggle user access without payment verification"""
    user = users_db.get(user_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Toggle access
    user["is_active"] = not user["is_active"]
    user["payment_verified"] = user["is_active"]
    
    if user["is_active"] and not user["subscription_expiry"]:
        user["subscription_expiry"] = datetime.now() + timedelta(days=365)
    
    return {
        "message": f"User access {'granted' if user['is_active'] else 'revoked'} for {user_email}",
        "user_status": "active" if user["is_active"] else "inactive",
        "action_by": current_dba["email"]
    }

@app.get("/dba/stats")
async def get_dba_stats(current_dba: dict = Depends(get_dba_user)):
    """DBA-only: Get comprehensive system statistics"""
    total_users = len(users_db)
    active_users = sum(1 for user in users_db.values() if user["is_active"])
    admin_users = sum(1 for user in users_db.values() if user["is_admin"])
    paid_users = sum(1 for user in users_db.values() if user["payment_verified"])
    
    return {
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": total_users - active_users,
        "admin_users": admin_users,
        "paid_users": paid_users,
        "total_payments": len(payments_db),
        "total_access_logs": len(access_logs),
        "system_health": "healthy"
    }

# Admin Routes
@app.get("/admin/users")
async def get_all_users(current_admin: dict = Depends(get_admin_user)):
    """Get all users for admin management"""
    users_list = []
    for user in users_db.values():
        user_data = {k: v for k, v in user.items() if k != "password_hash"}
        users_list.append(user_data)
    return users_list

@app.post("/admin/verify-payment")
async def verify_payment(payment: PaymentVerification, current_admin: dict = Depends(get_admin_user)):
    """Verify user payment and activate account"""
    user = users_db.get(payment.user_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update user status
    user["payment_verified"] = True
    user["is_active"] = True
    user["subscription_expiry"] = datetime.now() + timedelta(days=30 * payment.subscription_months)
    
    # Log payment
    payment_record = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "amount": payment.amount,
        "payment_date": datetime.now(),
        "verification_date": datetime.now(),
        "verified_by": current_admin["id"],
        "status": "verified",
        "subscription_months": payment.subscription_months
    }
    payments_db[payment_record["id"]] = payment_record
    
    return {"message": f"Payment verified for {payment.user_email}. Account activated."}

@app.get("/admin/payments")
async def get_payments(current_admin: dict = Depends(get_admin_user)):
    """Get all payment records"""
    return list(payments_db.values())

@app.get("/admin/access-logs")
async def get_access_logs(current_admin: dict = Depends(get_admin_user)):
    """Get user access logs"""
    return access_logs

# User Dashboard Routes
@app.get("/dashboard/apps")
async def get_user_apps(current_user: dict = Depends(get_current_user)):
    """Get available apps for user dashboard"""
    apps = [
        {
            "id": "elsa",
            "name": "ELSA",
            "description": "English Language Skills App - Improve your pronunciation and speaking skills",
            "status": "active",
            "url": "https://elsaspeak.com/",
            "icon": "🗣️",
            "category": "Language Learning"
        },
        {
            "id": "app2",
            "name": "EduTech Pro",
            "description": "Coming Soon - Advanced Educational Content Platform",
            "status": "coming_soon",
            "launch_date": "2025-12-01",
            "icon": "📚",
            "category": "Education"
        },
        {
            "id": "app3",
            "name": "ProductivityHub",
            "description": "Coming Soon - All-in-One Productivity Tools Suite",
            "status": "coming_soon",
            "launch_date": "2026-01-15",
            "icon": "⚡",
            "category": "Productivity"
        }
    ]
    
    # Log dashboard access
    access_logs.append({
        "user_id": current_user["id"],
        "app_accessed": "dashboard",
        "access_time": datetime.now(),
        "ip_address": "127.0.0.1"
    })
    
    return apps

@app.post("/dashboard/access-app/{app_id}")
async def access_app(app_id: str, current_user: dict = Depends(get_current_user)):
    """Log app access and return access details"""
    if app_id == "elsa":
        access_logs.append({
            "user_id": current_user["id"],
            "app_accessed": app_id,
            "access_time": datetime.now(),
            "ip_address": "127.0.0.1"
        })
        return {
            "message": f"Access granted to {app_id}", 
            "redirect_url": "https://elsaspeak.com/",
            "status": "success"
        }
    else:
        return {
            "message": "App not yet available", 
            "status": "coming_soon",
            "app_id": app_id
        }

# Health check
@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "timestamp": datetime.now(),
        "version": "1.0.0",
        "users_count": len(users_db),
        "payments_count": len(payments_db)
    }

@app.get("/")
async def root():
    return {
        "message": "EAC Super App API",
        "version": "1.0.0",
        "docs_url": "/docs",
        "health_url": "/health"
    }

if __name__ == "__main__":
    import os
    print("🚀 Starting EAC Super App Backend...")
    print("📊 Admin Login: admin@eac.com / admin123")
    print("🔧 DBA Login: dba@eac.com / dba123")
    print("🌐 API Documentation: /docs")
    print("❤️  Health Check: /health")
    
    # Get port from environment variable (Render sets this)
    port = int(os.environ.get("PORT", 8000))
    
    # For production (Render), don't use reload
    is_production = os.environ.get("RENDER", False)
    
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=port, 
        reload=not is_production  # Disable reload in production
    )