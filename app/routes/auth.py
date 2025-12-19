from flask import Blueprint, request, jsonify, redirect, session
from app.services.auth_service import AuthService
from app.services.google_oauth import GoogleOAuthService
from app.config import Config
from app.models import PendingRegistration, AuditLog
from app.services.email_service import EmailService
from app.utils.security import generate_verification_code
from datetime import datetime, timedelta
from bson import ObjectId

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['firstName', 'lastName', 'email', 'phone', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"error": f"{field} is required"}), 400
        
        # Get IP and User-Agent for audit logging
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        # Register user (temporary pending verification)
        pending_id, error = AuthService.register_user(
            data, 
            ip_address=ip_address, 
            user_agent=user_agent
        )
        
        if error:
            return jsonify({"error": error}), 400
        
        return jsonify({
            "message": "Registration initiated. Please check your email for verification.",
            "pendingId": pending_id
        }), 201
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@auth_bp.route('/verify-email', methods=['POST'])
def verify_email():
    try:
        data = request.get_json()
        
        if 'code' not in data:
            return jsonify({"error": "Verification code is required"}), 400
        
        # Get IP and User-Agent for audit logging
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        # Verify email and create user/organization
        result, error = AuthService.verify_email_and_create_user(
            data['code'], 
            ip_address=ip_address, 
            user_agent=user_agent
        )
        
        if error:
            return jsonify({"error": error}), 400
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if 'email' not in data or 'password' not in data:
            return jsonify({"error": "Email and password are required"}), 400
        
        # Get IP and User-Agent for audit logging
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        result, error = AuthService.login(
            data['email'], 
            data['password'],
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        if error:
            return jsonify({"error": error}), 401
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@auth_bp.route('/google')
def google_login():
    """Redirect to Google OAuth"""
    try:
        from app.services.google_oauth import GoogleOAuthService
        
        # Store redirect URL in session
        redirect_url = request.args.get('redirect', f'{Config.FRONTEND_URL}/dashboard')
        session['oauth_redirect'] = redirect_url
        
        # Get Google OAuth URL
        auth_url = GoogleOAuthService.get_oauth_url()
        print(f"Redirecting to Google OAuth: {auth_url}")
        return redirect(auth_url)
        
    except Exception as e:
        print(f"Google OAuth error: {str(e)}")
        return jsonify({"error": "Google OAuth configuration error"}), 500

@auth_bp.route('/google/callback')
def google_callback():
    try:
        code = request.args.get('code')
        print(f"Google callback received, code: {code[:20] if code else 'None'}...")
        
        if not code:
            print("No code received from Google")
            # Redirect to login with error
            return redirect(f"{Config.FRONTEND_URL}/login?error=Authorization+code+not+provided")
        
        result, error = GoogleOAuthService.handle_google_auth(code)
        
        if error:
            print(f"Google OAuth error: {error}")
            # Redirect to login with specific error message
            error_message = error.replace(" ", "+")
            return redirect(f"{Config.FRONTEND_URL}/login?error={error_message}")
        
        # Get redirect URL from session
        redirect_url = session.get('oauth_redirect', f'{Config.FRONTEND_URL}/dashboard')
        print(f"Google OAuth successful, redirecting to: {redirect_url}")
        
        # Redirect to frontend with token
        return redirect(f"{Config.FRONTEND_URL}/auth/success?token={result['token']}")
        
    except Exception as e:
        print(f"Google callback error: {str(e)}")
        import traceback
        traceback.print_exc()
        return redirect(f"{Config.FRONTEND_URL}/login?error=Internal+server+error")
    
@auth_bp.route('/google/login', methods=['POST'])
def google_login_api():
    """API endpoint for Google OAuth login (for direct code exchange)"""
    try:
        data = request.get_json()
        
        if 'code' not in data:
            return jsonify({"error": "Authorization code is required"}), 400
        
        # Get IP and User-Agent for audit logging
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        from app.services.auth_service import AuthService
        result, error = AuthService.google_login_only(
            data['code'],
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        if error:
            return jsonify({"error": error}), 401
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"Google login API error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500
    
@auth_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    try:
        data = request.get_json()
        
        if 'pendingId' not in data and 'email' not in data:
            return jsonify({"error": "Either pendingId or email is required"}), 400
        
        # Get IP and User-Agent for audit logging
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        # Find pending registration
        if 'pendingId' in data:
            pending = PendingRegistration.collection.find_one({"_id": ObjectId(data['pendingId'])})
        else:
            pending = PendingRegistration.find_by_email(data['email'])
        
        if not pending:
            return jsonify({"error": "Registration not found"}), 404
        
        # Generate new verification code
        verification_code = generate_verification_code()
        expires = datetime.utcnow() + timedelta(minutes=Config.VERIFICATION_CODE_EXPIRE_MINUTES)
        
        # Update pending registration
        PendingRegistration.collection.update_one(
            {"_id": pending["_id"]},
            {"$set": {
                "verificationCode": verification_code,
                "verificationCodeExpires": expires,
                "updatedAt": datetime.utcnow()
            }}
        )
        
        # Send verification email
        name = f"{pending['firstName']} {pending['lastName']}"
        EmailService.send_verification_email(pending["email"], verification_code, name)
        
        # Log resend attempt
        AuditLog.log_auth_attempt(
            user_id=None,
            action_type="VERIFICATION_RESENT",
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"email": pending["email"], "pendingId": str(pending["_id"])}
        )
        
        return jsonify({
            "message": "Verification email sent successfully",
            "pendingId": str(pending["_id"])
        }), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500