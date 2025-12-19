from flask import Blueprint, request, jsonify, redirect, session
from app.services.auth_service import AuthService
from app.services.google_oauth import GoogleOAuthService
from app.config import Config

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        print("Received registration data:", data)
        # Validate required fields
        required_fields = ['firstName', 'lastName', 'email', 'phone', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"error": f"{field} is required"}), 400
        
        # Register user
        user_id, error = AuthService.register_user(data)
        print(f"User registration result: user_id={user_id}, error={error}")
        if error:
            return jsonify({"error": error}), 400
        
        return jsonify({
            "message": "User registered successfully. Please check your email for verification.",
            "userId": user_id
        }), 201
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@auth_bp.route('/verify-email', methods=['POST'])
def verify_email():
    try:
        data = request.get_json()
        
        if 'userId' not in data or 'code' not in data:
            return jsonify({"error": "User ID and verification code are required"}), 400
        
        success, error = AuthService.verify_email(data['userId'], data['code'])
        if error:
            return jsonify({"error": error}), 400
        
        return jsonify({"message": "Email verified successfully"}), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if 'email' not in data or 'password' not in data:
            return jsonify({"error": "Email and password are required"}), 400
        
        result, error = AuthService.login(data['email'], data['password'])
        if error:
            return jsonify({"error": error}), 401
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@auth_bp.route('/logout', methods=['POST'])
def logout():
    try:
        token = request.headers.get('Authorization')
        if token and token.startswith('Bearer '):
            token = token[7:]
            AuthService.logout(token)
        
        return jsonify({"message": "Logged out successfully"}), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@auth_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    try:
        data = request.get_json()
        
        if 'email' not in data:
            return jsonify({"error": "Email is required"}), 400
        
        success, error = AuthService.resend_verification(data['email'])
        if error:
            return jsonify({"error": error}), 400
        
        return jsonify({"message": "Verification email sent successfully"}), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@auth_bp.route('/google')
def google_login():
    # Store redirect URL in session for after authentication
    redirect_url = request.args.get('redirect', '/dashboard')
    session['oauth_redirect'] = redirect_url
    
    auth_url = GoogleOAuthService.get_oauth_url()
    return redirect(auth_url)

@auth_bp.route('/google/callback')
def google_callback():
    try:
        code = request.args.get('code')
        if not code:
            return jsonify({"error": "Authorization code not provided"}), 400
        
        result, error = GoogleOAuthService.handle_google_auth(code)
        if error:
            return jsonify({"error": error}), 400
        
        # Redirect to frontend with token
        redirect_url = session.get('oauth_redirect', f'{Config.FRONTEND_URL}/dashboard')
        return redirect(f"{Config.FRONTEND_URL}/auth/success?token={result['token']}")
        
    except Exception as e:
        print(f"Google callback error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@auth_bp.route('/google/register', methods=['POST'])
def google_register():
    try:
        data = request.get_json()
        
        if 'code' not in data:
            return jsonify({"error": "Authorization code is required"}), 400
        
        if 'organizationData' not in data:
            return jsonify({"error": "Organization data is required"}), 400
        
        result, error = GoogleOAuthService.handle_google_registration(
            data['code'], data['organizationData']
        )
        
        if error:
            return jsonify({"error": error}), 400
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@auth_bp.route('/check-email', methods=['POST'])
def check_email():
    """
    Check if email exists and is verified
    """
    try:
        data = request.get_json()
        
        if 'email' not in data:
            return jsonify({"error": "Email is required"}), 400
        
        from app.models import User
        user = User.find_by_email(data['email'])
        
        if not user:
            return jsonify({
                "exists": False,
                "verified": False,
                "provider": None
            }), 200
        
        return jsonify({
            "exists": True,
            "verified": user.get('isVerified', False),
            "provider": user.get('provider', 'local')
        }), 200
        
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500