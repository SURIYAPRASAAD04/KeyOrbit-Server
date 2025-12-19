from datetime import datetime, timedelta
from app.models import User, Session
from app.utils.security import hash_password, verify_password, generate_jwt, verify_jwt, generate_verification_code
from app.services.email_service import EmailService
from app.config import Config

class AuthService:
    @staticmethod
    def register_user(user_data):
        # Check if user already exists
        existing_user = User.find_by_email(user_data["email"])
        if existing_user:
            return None, "User with this email already exists"
        
        # Hash password
        hashed_password = hash_password(user_data["password"])
        user_data["password"] = hashed_password
        
        # Create user
        print("Creating user with data:", user_data)
        result = User.create_user(user_data)

        print("User creation result:", result)

        user_id = str(result.inserted_id)
        
        # Generate verification code
        verification_code = generate_verification_code()

        User.set_verification_code(user_id, verification_code)
        print(f"Set verification code for user {user_id}: {verification_code}")
        
        # Send verification email
        name = f"{user_data['firstName']} {user_data['lastName']}"
      
        EmailService.send_verification_email(user_data["email"], verification_code, name)
       
        # Send welcome email (don't wait for verification)
        
        # Send admin notification (optional)
        # You can configure admin email in config or database
        admin_email = Config.SUPPORT_EMAIL  # Add this to your config
        if admin_email:
            EmailService.send_admin_notification_email(
                admin_email, 
                user_data["email"], 
                name
            )
        
        return user_id, None
        
    @staticmethod
    def verify_email(user_id, code):
        user = User.find_by_id(user_id)
        if not user:
            return False, "User not found"
        
        if user.get("isVerified"):
            return True, "User already verified"
        
        if user.get("verificationCode") != code:
            return False, "Invalid verification code"
        
        if datetime.utcnow() > user.get("verificationCodeExpires"):
            return False, "Verification code has expired"
        
        # Verify user
        User.verify_user(user_id)
        EmailService.send_welcome_email(user["email"], f"{user['firstName']} {user['lastName']}")
        return True, None
    
    @staticmethod
    def login(email, password):
        user = User.find_by_email(email)
        print(user)
        if not user:
            return None, "Invalid email or password"
        
        if not user.get("isVerified"):
            return None, "Please verify your email first"
        
        if not verify_password(password, user["password"]):
            return None, "Invalid email or password"
        
        # Update last login
        User.update_user(str(user["_id"]), {"lastLogin": datetime.utcnow()})
        
        # Generate JWT token
        token = generate_jwt({
            "userId": str(user["_id"]),
            "email": user["email"],
            "role": user["role"]
        })
        
        # Store session
        expires = datetime.utcnow() + timedelta(minutes=Config.JWT_EXPIRE_MINUTES)
        Session.create_session(str(user["_id"]), token, expires)
        
        user_data = {
            "id": str(user["_id"]),
            "firstName": user["firstName"],
            "lastName": user["lastName"],
            "email": user["email"],
            "role": user["role"],
            "organization": user.get("organization", {})
        }
        
        return {"user": user_data, "token": token}, None
    
    @staticmethod
    def logout(token):
        Session.delete_session(token)
        return True
    
    @staticmethod
    def resend_verification(email):
        user = User.find_by_email(email)
        if not user:
            return False, "User not found"
        
        if user.get("isVerified"):
            return False, "User already verified"
        
        # Generate new verification code
        verification_code = generate_verification_code()
        User.set_verification_code(str(user["_id"]), verification_code)
        
        # Send verification email
        name = f"{user['firstName']} {user['lastName']}"
        EmailService.send_verification_email(user["email"], verification_code, name)
        
        return True, None
    
    @staticmethod
    def validate_token(token):
        payload = verify_jwt(token)
        if not payload:
            return None
        
        # Check if session exists
        session = Session.find_by_token(token)
        if not session:
            return None
        
        # Check if token is expired
        if datetime.utcnow() > session["expires"]:
            Session.delete_session(token)
            return None
        
        return payload