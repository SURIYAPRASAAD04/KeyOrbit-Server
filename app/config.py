import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # MongoDB Configuration
    MONGODB_URI = os.getenv("MONGODB_URI")
    
    # JWT Configuration
    JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", 1440))  # 24 hours
    
    # Google OAuth Configuration
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")
    
    # Email Configuration
    SMTP_SERVER = os.getenv("SMTP_SERVER")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
    FROM_EMAIL = os.getenv("FROM_EMAIL")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@keyorbit.com")
    
    # App Configuration
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
    VERIFICATION_CODE_EXPIRE_MINUTES = int(os.getenv("VERIFICATION_CODE_EXPIRE_MINUTES", 30))

    COMPANY_NAME = os.getenv("COMPANY_NAME", "KeyOrbit KMS")
    COMPANY_WEBSITE = os.getenv("COMPANY_WEBSITE", "https://keyorbit.com")
    SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "support@keyorbit.com")
    
    # Timezone Configuration
    DEFAULT_TIMEZONE = os.getenv("DEFAULT_TIMEZONE", "Asia/Kolkata")  # IST