import requests
from app.models import User, Organization
from app.utils.security import hash_password, generate_jwt, generate_verification_code
from app.models import Session
from app.services.email_service import EmailService
from datetime import datetime, timedelta
from app.config import Config

class GoogleOAuthService:
    @staticmethod
    def get_oauth_url():
        from urllib.parse import urlencode
        
        params = {
            "client_id": Config.GOOGLE_CLIENT_ID,
            "redirect_uri": Config.GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "consent"
        }
        
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
    
    @staticmethod
    def exchange_code_for_token(code):
        data = {
            "client_id": Config.GOOGLE_CLIENT_ID,
            "client_secret": Config.GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": Config.GOOGLE_REDIRECT_URI
        }
        
        response = requests.post("https://oauth2.googleapis.com/token", data=data)
        if response.status_code != 200:
            return None, "Failed to exchange code for token"
        
        return response.json(), None
    
    @staticmethod
    def get_user_info(access_token):
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get("https://www.googleapis.com/oauth2/v3/userinfo", headers=headers)
        
        if response.status_code != 200:
            return None, "Failed to get user info"
        
        return response.json(), None
    
    @staticmethod
    def verify_email_domain(email, organization_data=None):
        """
        Verify if the email domain matches any organization and auto-verify if it does
        """
        domain = email.split('@')[1] if '@' in email else None
        
        if not domain:
            return False, None
        
        # Check if domain exists in organizations
        organization = Organization.collection.find_one({
            "domain": domain,
            "verified": True
        })
        
        if organization:
            return True, str(organization["_id"])
        
        # If organization data is provided during registration, create new organization
        if organization_data and organization_data.get("domain") == domain:
            org_data = {
                "name": organization_data["organizationName"],
                "domain": domain,
                "industry": organization_data.get("industry", ""),
                "size": organization_data.get("companySize", ""),
                "verified": True,  # Auto-verify for Google OAuth users
                "ssoEnabled": organization_data.get("enableSSO", False),
                "createdAt": datetime.utcnow(),
                "updatedAt": datetime.utcnow()
            }
            result = Organization.collection.insert_one(org_data)
            return True, str(result.inserted_id)
        
        return False, None
    
    @staticmethod
    def handle_google_auth(code, organization_data=None):
        # Exchange code for token
        token_data, error = GoogleOAuthService.exchange_code_for_token(code)
        if error:
            return None, error
        
        # Get user info
        user_info, error = GoogleOAuthService.get_user_info(token_data["access_token"])
        if error:
            return None, error
        
        # Verify email is provided and verified by Google
        if not user_info.get("email") or not user_info.get("email_verified", False):
            return None, "Google email not verified"
        
        # Check if user exists
        user = User.find_by_email(user_info["email"])
        
        if user:
            # Update user info if needed
            updates = {
                "firstName": user_info.get("given_name", user.get("firstName", "")),
                "lastName": user_info.get("family_name", user.get("lastName", "")),
                "isVerified": True,  # Auto-verify Google OAuth users
                "lastLogin": datetime.utcnow(),
                "updatedAt": datetime.utcnow()
            }
            User.update_user(str(user["_id"]), updates)
        else:
            # Verify domain and get organization ID
            is_domain_verified, organization_id = GoogleOAuthService.verify_email_domain(
                user_info["email"], organization_data
            )
            
            # Create new user
            user_data = {
                "firstName": user_info.get("given_name", ""),
                "lastName": user_info.get("family_name", ""),
                "email": user_info["email"],
                "phone": "",
                "password": hash_password(f"google_oauth_{user_info['sub']}"),  # Unique password
                "isVerified": True,  # Auto-verify Google OAuth users
                "verificationCode": None,
                "verificationCodeExpires": None,
                "organization": {
                    "id": organization_id,
                    "name": organization_data["organizationName"] if organization_data else "Personal",
                    "domain": user_info["email"].split('@')[1] if '@' in user_info["email"] else ""
                } if organization_id else {},
                "role": "user",
                "provider": "google",
                "providerId": user_info["sub"],
                "mfaEnabled": False,
                "mfaSecret": None,
                "lastLogin": datetime.utcnow(),
                "createdAt": datetime.utcnow(),
                "updatedAt": datetime.utcnow()
            }
            
            result = User.create_user(user_data)
            user = User.find_by_id(str(result.inserted_id))
            
            # Send welcome email
            name = f"{user_data['firstName']} {user_data['lastName']}".strip()
            EmailService.send_welcome_email(user_info["email"], name)
        
        # Generate JWT token
        token = generate_jwt({
            "userId": str(user["_id"]),
            "email": user["email"],
            "role": user.get("role", "user")
        })
        
        # Store session
        expires = datetime.utcnow() + timedelta(minutes=Config.JWT_EXPIRE_MINUTES)
        Session.create_session(str(user["_id"]), token, expires)
        
        user_data = {
            "id": str(user["_id"]),
            "firstName": user["firstName"],
            "lastName": user["lastName"],
            "email": user["email"],
            "role": user.get("role", "user"),
            "organization": user.get("organization", {}),
            "isVerified": user.get("isVerified", False)
        }
        
        return {"user": user_data, "token": token}, None
    
    @staticmethod
    def handle_google_registration(code, organization_data):
        """
        Handle Google OAuth during registration with organization data
        """
        # Exchange code for token
        token_data, error = GoogleOAuthService.exchange_code_for_token(code)
        if error:
            return None, error
        
        # Get user info
        user_info, error = GoogleOAuthService.get_user_info(token_data["access_token"])
        if error:
            return None, error
        
        # Verify email is provided and verified by Google
        if not user_info.get("email") or not user_info.get("email_verified", False):
            return None, "Google email not verified"
        
        # Check if user already exists
        existing_user = User.find_by_email(user_info["email"])
        if existing_user:
            return None, "User with this email already exists"
        
        # Create organization
        org_data = {
            "name": organization_data["organizationName"],
            "domain": organization_data["domain"],
            "industry": organization_data.get("industry", ""),
            "size": organization_data.get("companySize", ""),
            "verified": True,  # Auto-verify for Google OAuth
            "ssoEnabled": organization_data.get("enableSSO", False),
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
        org_result = Organization.collection.insert_one(org_data)
        organization_id = str(org_result.inserted_id)
        
        # Create user
        user_data = {
            "firstName": user_info.get("given_name", ""),
            "lastName": user_info.get("family_name", ""),
            "email": user_info["email"],
            "phone": organization_data.get("phone", ""),
            "password": hash_password(f"google_oauth_{user_info['sub']}"),
            "isVerified": True,
            "verificationCode": None,
            "verificationCodeExpires": None,
            "organization": {
                "id": organization_id,
                "name": organization_data["organizationName"],
                "domain": organization_data["domain"]
            },
            "role": organization_data.get("role", "user"),
            "provider": "google",
            "providerId": user_info["sub"],
            "mfaEnabled": False,
            "mfaSecret": None,
            "lastLogin": datetime.utcnow(),
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
        
        result = User.create_user(user_data)
        user = User.find_by_id(str(result.inserted_id))
        
        # Send welcome email
        name = f"{user_data['firstName']} {user_data['lastName']}".strip()
        EmailService.send_welcome_email(user_info["email"], name)
        
        # Generate JWT token
        token = generate_jwt({
            "userId": str(user["_id"]),
            "email": user["email"],
            "role": user.get("role", "user")
        })
        
        # Store session
        expires = datetime.utcnow() + timedelta(minutes=Config.JWT_EXPIRE_MINUTES)
        Session.create_session(str(user["_id"]), token, expires)
        
        user_response = {
            "id": str(user["_id"]),
            "firstName": user["firstName"],
            "lastName": user["lastName"],
            "email": user["email"],
            "role": user.get("role", "user"),
            "organization": user.get("organization", {}),
            "isVerified": user.get("isVerified", False)
        }
        
        return {"user": user_response, "token": token}, None