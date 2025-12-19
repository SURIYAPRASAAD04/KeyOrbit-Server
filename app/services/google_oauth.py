import requests
from app.models import User
from app.utils.security import generate_jwt
from app.models import Session
from datetime import datetime, timedelta
from app.config import Config
from urllib.parse import urlencode

class GoogleOAuthService:
    @staticmethod
    def get_oauth_url():
        """Get Google OAuth URL"""
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
        """Exchange authorization code for access token"""
        if not code:
            return None, "Authorization code is required"
        
        data = {
            "client_id": Config.GOOGLE_CLIENT_ID,
            "client_secret": Config.GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": Config.GOOGLE_REDIRECT_URI
        }
        
        try:
            response = requests.post("https://oauth2.googleapis.com/token", data=data, timeout=10)
            if response.status_code != 200:
                print(f"Token exchange failed: {response.status_code} - {response.text}")
                return None, "Failed to exchange code for token"
            
            return response.json(), None
            
        except requests.exceptions.Timeout:
            return None, "Request timeout. Please try again."
        except Exception as e:
            print(f"Token exchange error: {str(e)}")
            return None, f"Token exchange failed: {str(e)}"
    
    @staticmethod
    def get_user_info(access_token):
        """Get user info from Google"""
        if not access_token:
            return None, "Access token is required"
        
        headers = {"Authorization": f"Bearer {access_token}"}
        
        try:
            response = requests.get("https://www.googleapis.com/oauth2/v3/userinfo", headers=headers, timeout=10)
            
            if response.status_code != 200:
                print(f"User info fetch failed: {response.status_code} - {response.text}")
                return None, "Failed to get user info"
            
            return response.json(), None
            
        except requests.exceptions.Timeout:
            return None, "Request timeout. Please try again."
        except Exception as e:
            print(f"User info error: {str(e)}")
            return None, f"Failed to get user info: {str(e)}"
    
    @staticmethod
    def handle_google_auth(code):
        """Handle Google OAuth authentication - LOGIN ONLY"""
        print(f"Google OAuth started with code: {code[:20]}...")
        
        # Exchange code for token
        token_data, error = GoogleOAuthService.exchange_code_for_token(code)
        if error:
            print(f"Token exchange error: {error}")
            return None, error
        
        # Get user info
        user_info, error = GoogleOAuthService.get_user_info(token_data["access_token"])
        if error:
            print(f"Get user info error: {error}")
            return None, error
        
        # Verify email is provided and verified by Google
        if not user_info.get("email") or not user_info.get("email_verified", False):
            print(f"Email not verified: {user_info.get('email')}")
            return None, "Google email not verified"
        
        email = user_info["email"]
        print(f"Google OAuth successful for email: {email}")
        
        # CHECK IF USER EXISTS - GOOGLE IS LOGIN ONLY
        user = User.find_by_email(email)
        
        if not user:
            print(f"No user found with email: {email}")
            # User doesn't exist - Google OAuth is for LOGIN ONLY
            return None, "No account found with this Google email. Please register first."
        
        # Check if user is verified
        if not user.get("isVerified", False):
            print(f"User not verified: {email}")
            return None, "Please verify your email first. Check your inbox for verification email."
        
        print(f"User found and verified: {email}")
        
        # Update user info if needed
        updates = {
            "firstName": user_info.get("given_name", user.get("firstName", "")),
            "lastName": user_info.get("family_name", user.get("lastName", "")),
            "lastLogin": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
        
        # Update provider info if this is first Google login
        if user.get("provider") != "google":
            updates["provider"] = "google"
            updates["providerId"] = user_info.get("sub", "")
        
        User.update_user(str(user["_id"]), updates)
        
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
            "isVerified": user.get("isVerified", False),
            "provider": user.get("provider", "local")
        }
        
        print(f"Google login successful for user: {user_data['email']}")
        
        return {"user": user_data, "token": token}, None