from datetime import datetime, timedelta
from app.models import User, Session, PendingRegistration, Organization, AuditLog
from app.utils.security import hash_password, verify_password, generate_jwt, verify_jwt, generate_verification_code
from app.services.email_service import EmailService
from app.config import Config
from bson import ObjectId

class AuthService:
    @staticmethod
    def register_user(user_data, ip_address=None, user_agent=None):
        """Register user with all data (user + organization)"""
        # Check if user already exists
        existing_user = User.find_by_email(user_data["email"])
        if existing_user:
            return None, "User with this email already exists"
        
        # Check if pending registration exists
        pending_user = PendingRegistration.find_by_email(user_data["email"])
        if pending_user:
            # If exists, update with new organization data
            PendingRegistration.collection.update_one(
                {"email": user_data["email"].lower()},
                {"$set": {
                    "organizationData": user_data.get("organizationData", {}),
                    "updatedAt": datetime.utcnow()
                }}
            )
            pending_id = str(pending_user["_id"])
        else:
            # Create new pending registration
            hashed_password = hash_password(user_data["password"])
            verification_code = generate_verification_code()
            expires = datetime.utcnow() + timedelta(minutes=Config.VERIFICATION_CODE_EXPIRE_MINUTES)
            
            pending_data = {
                "firstName": user_data["firstName"],
                "lastName": user_data["lastName"],
                "email": user_data["email"].lower(),
                "phone": user_data["phone"],
                "password": hashed_password,
                "organizationData": user_data.get("organizationData", {}),
                "verificationCode": verification_code,
                "verificationCodeExpires": expires,
                "createdAt": datetime.utcnow(),
                "updatedAt": datetime.utcnow()
            }
            
            result = PendingRegistration.create(pending_data)
            pending_id = str(result.inserted_id)
            
            # Send verification email
            name = f"{user_data['firstName']} {user_data['lastName']}"
            EmailService.send_verification_email(user_data["email"], verification_code, name)
        
        # Log registration attempt
        AuditLog.log_auth_attempt(
            user_id=None,
            action_type="REGISTER_ATTEMPT",
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"email": user_data["email"], "pendingId": pending_id}
        )
        
        return pending_id, None
    
    @staticmethod
    def verify_email_and_create_user(code, ip_address=None, user_agent=None):
        """Step 2: Verify email and create user/organization"""
        from bson import ObjectId
        
        # Find pending registration
        pending = PendingRegistration.find_by_code(code)
        if not pending:
            return None, "Invalid verification code"
        
        if datetime.utcnow() > pending["verificationCodeExpires"]:
            # Clean up expired registration
            PendingRegistration.delete_by_email(pending["email"])
            return None, "Verification code has expired"
        
        # Check if user already exists (race condition)
        existing_user = User.find_by_email(pending["email"])
        if existing_user:
            PendingRegistration.delete_by_email(pending["email"])
            return None, "User already exists"
        
        try:
            # Create user first with temporary organization data
            user_data = {
                "firstName": pending["firstName"],
                "lastName": pending["lastName"],
                "email": pending["email"],
                "phone": pending["phone"],
                "password": pending["password"],
                "isVerified": True,
                "verificationCode": None,
                "verificationCodeExpires": None,
                "role": "admin",  # FORCE ADMIN ROLE FOR UI REGISTRATIONS
                "provider": "local",
                "mfaEnabled": False,
                "lastLogin": datetime.utcnow(),
                "createdAt": datetime.utcnow(),
                "updatedAt": datetime.utcnow()
            }
            
            # Create user
            user_result = User.create_user(user_data)
            user_id = str(user_result.inserted_id)
            
            # Create organization with the created user ID
            org_data = pending.get("organizationData", {})
            org_result = Organization.create_organization({
                "name": org_data.get("organizationName", "Personal"),
                "domain": org_data.get("domain", ""),
                "industry": org_data.get("industry", ""),
                "size": org_data.get("companySize", ""),
                "createdBy": ObjectId(user_id),  # Use actual user ObjectId
                "verified": True
            })
            organization_id = str(org_result.inserted_id)
            
            # Update user with organization ID
            User.update_user(user_id, {
                "organizationId": ObjectId(organization_id),
                "organization": {
                    "id": organization_id,
                    "name": org_data.get("organizationName", "Personal"),
                    "domain": org_data.get("domain", "")
                }
            })
            
            # Generate JWT token
            token = generate_jwt({
                "userId": user_id,
                "email": pending["email"],
                "role": "admin"  # Enforce admin role in token
            })
            
            # Store session
            expires = datetime.utcnow() + timedelta(minutes=Config.JWT_EXPIRE_MINUTES)
            Session.create_session(user_id, token, expires)
            
            # Clean up pending registration
            PendingRegistration.delete_by_email(pending["email"])
            
            # Log successful verification
            AuditLog.log_auth_attempt(
                user_id=user_id,
                action_type="EMAIL_VERIFIED",
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={"email": pending["email"], "organizationId": organization_id}
            )
            
            # Send welcome email
            name = f"{pending['firstName']} {pending['lastName']}"
            EmailService.send_welcome_email(pending["email"], name)
            
            user_response = {
                "id": user_id,
                "firstName": pending["firstName"],
                "lastName": pending["lastName"],
                "email": pending["email"],
                "role": "admin",
                "organization": {
                    "id": organization_id,
                    "name": org_data.get("organizationName", "Personal"),
                    "domain": org_data.get("domain", "")
                },
                "isVerified": True
            }
            
            return {"user": user_response, "token": token}, None
            
        except Exception as e:
            print(f"Registration error: {str(e)}")
            # Rollback: delete user if created
            if 'user_id' in locals():
                User.collection.delete_one({"_id": ObjectId(user_id)})
            return None, f"Registration failed: {str(e)}"
    
    @staticmethod
    def login(email, password, ip_address=None, user_agent=None):
        user = User.find_by_email(email)
        
        if not user:
            # Log failed login attempt
            AuditLog.log_auth_attempt(
                user_id=None,
                action_type="LOGIN_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={"email": email, "reason": "User not found"}
            )
            return None, "Invalid email or password"
        
        if not user.get("isVerified"):
            AuditLog.log_auth_attempt(
                user_id=str(user["_id"]),
                action_type="LOGIN_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={"email": email, "reason": "Email not verified"}
            )
            return None, "Please verify your email first"
        
        if not verify_password(password, user["password"]):
            AuditLog.log_auth_attempt(
                user_id=str(user["_id"]),
                action_type="LOGIN_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={"email": email, "reason": "Invalid password"}
            )
            return None, "Invalid email or password"
        
        # Update last login
        User.update_user(str(user["_id"]), {"lastLogin": datetime.utcnow()})
        
        # Generate JWT token
        token = generate_jwt({
            "userId": str(user["_id"]),
            "email": user["email"],
            "role": user["role"]  # Will be "admin" for UI registrations
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
            "organization": user.get("organization", {}),
            "isVerified": user.get("isVerified", False)
        }
        
        # Log successful login
        AuditLog.log_auth_attempt(
            user_id=str(user["_id"]),
            action_type="LOGIN_SUCCESS",
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"email": email}
        )
        
        return {"user": user_data, "token": token}, None
    
    @staticmethod
    def google_login_only(code, ip_address=None, user_agent=None):
        """Google OAuth for LOGIN ONLY (no registration)"""
        from app.services.google_oauth import GoogleOAuthService
        
        # Exchange code for token
        token_data, error = GoogleOAuthService.exchange_code_for_token(code)
        if error:
            AuditLog.log_auth_attempt(
                user_id=None,
                action_type="GOOGLE_LOGIN_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={"reason": "Token exchange failed"}
            )
            return None, error
        
        # Get user info
        user_info, error = GoogleOAuthService.get_user_info(token_data["access_token"])
        if error:
            AuditLog.log_auth_attempt(
                user_id=None,
                action_type="GOOGLE_LOGIN_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={"reason": "Failed to get user info"}
            )
            return None, error
        
        # Check if email is verified by Google
        if not user_info.get("email") or not user_info.get("email_verified", False):
            AuditLog.log_auth_attempt(
                user_id=None,
                action_type="GOOGLE_LOGIN_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={"email": user_info.get("email"), "reason": "Google email not verified"}
            )
            return None, "Google email not verified"
        
        # Check if user exists in our system
        user = User.find_by_email(user_info["email"])
        
        if not user:
            # User doesn't exist - REJECT login
            AuditLog.log_auth_attempt(
                user_id=None,
                action_type="GOOGLE_LOGIN_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={"email": user_info["email"], "reason": "No account found"}
            )
            return None, "No account found with this Google email. Please register first."
        
        if not user.get("isVerified"):
            AuditLog.log_auth_attempt(
                user_id=str(user["_id"]),
                action_type="GOOGLE_LOGIN_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={"email": user_info["email"], "reason": "Email not verified"}
            )
            return None, "Please verify your email first"
        
        # Update user info if needed
        updates = {
            "firstName": user_info.get("given_name", user.get("firstName", "")),
            "lastName": user_info.get("family_name", user.get("lastName", "")),
            "lastLogin": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
        User.update_user(str(user["_id"]), updates)
        
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
            "organization": user.get("organization", {}),
            "isVerified": user.get("isVerified", False)
        }
        
        # Log successful Google login
        AuditLog.log_auth_attempt(
            user_id=str(user["_id"]),
            action_type="GOOGLE_LOGIN_SUCCESS",
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"email": user_info["email"]}
        )
        
        return {"user": user_data, "token": token}, None