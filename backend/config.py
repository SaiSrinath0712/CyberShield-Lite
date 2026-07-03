import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # App General Settings
    APP_NAME: str = "CyberShield AI"
    DEBUG: bool = True
    
    # JWT Auth Settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "cybershield_ai_super_secret_jwt_key_2026_change_me")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Database Settings
    # Defaulting to sqlite local database inside the project workspace
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///c:/Users/unknown/OneDrive/Desktop/Cyber/cybershield.db")
    
    # Rate Limiting & Admin Credentials (Default Setup)
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
