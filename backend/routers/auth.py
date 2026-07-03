from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from backend import models, schemas, auth
from backend.database import get_db
from backend.config import settings

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def register(user_data: schemas.UserCreate, db: Session = Depends(get_db)):
    # Check if username exists
    existing_user = db.query(models.User).filter(models.User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Check if email exists
    existing_email = db.query(models.User).filter(models.User.email == user_data.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Hash the password and save
    hashed_pwd = auth.get_password_hash(user_data.password)
    
    # Check if this is the first user; if so, make them Admin
    user_count = db.query(models.User).count()
    role = "Admin" if user_count == 0 else user_data.role

    new_user = models.User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_pwd,
        role=role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    
    # Log login attempts for security auditing
    # (Notice how we log both successful and failed attempts for real-time brute force evaluation)
    login_successful = False
    
    if user and auth.verify_password(form_data.password, user.hashed_password):
        login_successful = True
        
    # Write login monitor log to the database
    log_entry = models.PredictionLog(
        threat_type="Login Monitor",
        input_data=f"User: {form_data.username}",
        prediction_output="Success" if login_successful else "Failed Attempt",
        confidence_score=100.0,
        explanation=f"User logon attempt {'succeeded' if login_successful else 'failed'}.",
        is_malicious=not login_successful,
        source_ip="127.0.0.1",  # Simplification for dev, can be parsed from request headers
        user_id=user.id if user else None
    )
    db.add(log_entry)
    
    if login_successful and user:
        # Create alert if there was a critical risk on user login history
        from backend.services.rules import evaluate_login_risk
        risk_profile = evaluate_login_risk(db, user.username, "127.0.0.1")
        if risk_profile["risk_level"] in ["High", "Critical"]:
            alert = models.Alert(
                threat_type="Login Monitor",
                source_ip="127.0.0.1",
                payload=f"Suspicious activity for user: {user.username}",
                risk_level=risk_profile["risk_level"],
                explanation=", ".join(risk_profile["reasons"])
            )
            db.add(alert)
        
        db.commit()
        
        # Issue JWT Access Token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = auth.create_access_token(
            data={"sub": user.username, "role": user.role},
            expires_delta=access_token_expires
        )
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "role": user.role,
            "username": user.username
        }
    else:
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
