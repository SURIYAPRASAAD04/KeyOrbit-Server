import jwt
import secrets
from datetime import datetime, timedelta
from pytz import timezone, UTC
import bcrypt
from app.config import Config
import hashlib
import base64


IST = timezone('Asia/Kolkata')

# Add these functions if they don't exist

def generate_key_id():
    """Generate a unique key ID"""
    import secrets
    import time
    
    timestamp = int(time.time() * 1000)
    random_part = secrets.token_hex(8)
    return f"key_{timestamp}_{random_part}"

def hash_key_material(key_material):
    """Hash key material for integrity verification"""
    if isinstance(key_material, bytes):
        return hashlib.sha256(key_material).hexdigest()
    return hashlib.sha256(key_material.encode()).hexdigest()

def get_current_ist_time():
    """Get current time in IST"""
    return datetime.now(IST)

def format_ist_time(dt):
    """Format datetime to IST string"""
    if dt.tzinfo is None:
        dt = IST.localize(dt)
    return dt.astimezone(IST).isoformat()

def parse_expiration_date(expires_at):
    """Parse expiration date string"""
    from dateutil import parser
    
    if isinstance(expires_at, str):
        dt = parser.parse(expires_at)
        if dt.tzinfo is None:
            dt = IST.localize(dt)
        return dt
    return expires_at

def is_token_expired(expires_at):
    """Check if token has expired"""
    now = get_current_ist_time()
    if expires_at.tzinfo is None:
        expires_at = IST.localize(expires_at)
    return now > expires_at

def generate_verification_code():
    """Generate a 6-digit verification code"""
    return ''.join(secrets.choice('0123456789') for _ in range(6))

def get_current_ist_time():
    """Get current time in IST timezone"""
    return datetime.now(IST)

def get_current_utc_time():
    """Get current time in UTC"""
    return datetime.now(UTC)

def format_datetime_for_db(dt):
    """Format datetime for MongoDB storage - Store as IST timezone aware"""
    if dt.tzinfo is None:
        dt = IST.localize(dt)
    return dt

def hash_password(password):
    """Hash a password for storing"""
    if isinstance(password, str):
        password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password, salt).decode('utf-8')

def verify_password(password, hashed_password):
    """Verify a stored password against one provided by user"""
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password, hashed_password)

def generate_jwt(payload):
    """Generate a JWT token"""
    payload.update({
        'exp': datetime.utcnow() + timedelta(minutes=Config.JWT_EXPIRE_MINUTES),
        'iat': datetime.utcnow()
    })
    return jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)

def verify_jwt(token):
    """Verify and decode a JWT token"""
    try:
        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def generate_verification_code():
    """Generate a 6-digit verification code"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

def generate_api_token():
    """Generate a secure API token"""
    return secrets.token_urlsafe(64)

def generate_token_preview(token):
    """Generate a preview of the token (first 8 chars)"""
    return token[:8] if token else ""

def is_token_expired(expires_at):
    """Check if token is expired with proper timezone handling"""
    if not expires_at:
        return False
    
    current_utc = get_current_utc_time()
    
    # If expires_at is a datetime object
    if isinstance(expires_at, datetime):
        # Convert to UTC for comparison
        if expires_at.tzinfo is None:
            # If no timezone, assume it's IST
            expires_at = IST.localize(expires_at)
        expires_utc = expires_at.astimezone(UTC)
        return current_utc > expires_utc
    
    # If expires_at is a string
    try:
        if isinstance(expires_at, str):
            # Handle Z suffix for UTC
            if expires_at.endswith('Z'):
                expires_utc = datetime.fromisoformat(expires_at[:-1] + '+00:00')
            else:
                # Assume IST if no timezone specified
                expires_dt = datetime.fromisoformat(expires_at)
                if expires_dt.tzinfo is None:
                    expires_dt = IST.localize(expires_dt)
                expires_utc = expires_dt.astimezone(UTC)
            
            return current_utc > expires_utc
    except (ValueError, AttributeError) as e:
        print(f"Error parsing expiration date: {e}")
    
    return False

def calculate_expiry_time(days=90):
    """Calculate expiry time (default 90 days from now in IST)"""
    return get_current_ist_time() + timedelta(days=days)

def parse_expiration_date(expires_at_str):
    """Parse expiration date string to IST datetime"""
    if not expires_at_str:
        return None
    
    try:
        # Parse the input string
        if 'Z' in expires_at_str:
            # UTC time with Z suffix - convert to IST
            dt = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
            dt = dt.astimezone(IST)
        else:
            # Try ISO format
            dt = datetime.fromisoformat(expires_at_str)
            if dt.tzinfo is None:
                # Assume it's in local timezone and convert to IST
                dt = IST.localize(dt)
            else:
                # Convert to IST from whatever timezone
                dt = dt.astimezone(IST)
        
        return dt
    except ValueError as e:
        raise ValueError(f"Invalid date format: {expires_at_str}. Expected ISO format: YYYY-MM-DDTHH:MM:SS")